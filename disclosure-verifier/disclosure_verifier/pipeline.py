"""Per-disclosure verification orchestration (stages A -> B -> C + edits).

The pipeline is runner-agnostic: it takes a ``ModelRunner`` (anything with
``run(model_key, messages, **gen_params) -> str``) and a lifecycle manager, so
unit tests can drive the whole flow with canned responses and no GPU.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import mechanical as mech
from .cvss31 import CvssError, base_score, candidates_from_texts
from .edits import Edit, apply_edits, edits_from_adjudication, revert, sha256_of
from .jsonx import MAX_TOKENS_CAP, call_with_retry
from .parse_disclosure import Bundle
from .prompts import (
    CLASSIFICATIONS,
    build_adjudication_prompt,
    build_eval_prompt,
)

EVAL_REQUIRED_KEYS = [
    "is_security_problem_per_trust_model",
    "trust_model_analysis",
    "cvss_assessment",
    "impact_assessment",
    "inaccuracies",
]
ADJUDICATION_REQUIRED_KEYS = [
    "classification",
    "legit_security_finding",
    "final_cvss_vector",
    "final_base_score",
    "impact_summary",
    "edits",
]


def _enforce_classification(verdict: dict) -> None:
    """Make the classification bucket authoritative and self-consistent.

    Every disclosure must land in exactly one bucket (security_issue /
    hardening / bug / invalid); an inconclusive resting state is not allowed.
    ``legit_security_finding`` is derived from the bucket so the two can never
    disagree, and a non-security bucket with a nonzero score is normalized to
    the all-N vector unless the adjudicator explicitly kept a residual score.
    """
    cls = verdict.get("classification")
    if not isinstance(cls, str) or cls.strip().lower() not in CLASSIFICATIONS:
        # Last-resort mapping so a malformed bucket still yields a row: any
        # explicit security ruling wins, otherwise treat as a demonstrated bug.
        cls = "security_issue" if verdict.get("legit_security_finding") is True else "bug"
        verdict["classification_note"] = f"unparseable classification coerced to {cls!r}"
    else:
        cls = cls.strip().lower()
    verdict["classification"] = cls
    legit = cls == "security_issue"
    if verdict.get("legit_security_finding") is not legit:
        verdict.setdefault("classification_note", "")
        note = f"legit_security_finding coerced {verdict.get('legit_security_finding')!r} -> {legit!r} to match classification={cls!r}"
        verdict["classification_note"] = (verdict["classification_note"] + " | " + note).strip(" |")
    verdict["legit_security_finding"] = legit


@dataclass(frozen=True)
class EvaluatorSpec:
    """One independent evaluation stage (model + its load/input budgets)."""

    name: str  # short label for reports, e.g. "27b", "7b", "cyber"
    model_key: str  # LM Studio model key
    ctx_tokens: int = 65536  # explicit context length at load time
    input_budget_chars: int = 140_000  # prompt char budget for this stage


@dataclass
class PipelineConfig:
    # Model keys, context lengths and input budgets come from config.toml
    # (see disclosure_verifier/config.py) — no machine-local defaults here.
    evaluators: tuple[EvaluatorSpec, ...]
    adjudicator_model: str
    adjudicator_ctx: int
    adjudicator_input_budget_chars: int
    seed: int = 1337
    temperature: float = 0.0
    top_p: float = 1.0
    # Evaluator-stage budget. Doubles per retry (cap MAX_TOKENS_CAP), so the
    # ladder is 8192 -> 16384 -> 32768: long disclosures need >16k tokens of
    # internal reasoning before any JSON is emitted, and a base of 4096 left
    # attempt 3 stuck at 16384 with the verdict still unwritten.
    max_tokens_eval: int = 8192
    # Final-stage budget. Doubles per retry (cap MAX_TOKENS_CAP), so attempt 3
    # gets a full window for long reasoning PLUS the verdict JSON — thinking
    # models that burn their whole budget on internal CVSS math otherwise come
    # back with empty content and finish_reason=stop.
    max_tokens_final: int = 16384
    run_tests: bool = True
    postpatch: bool = True
    max_attempts: int = 3
    jar_dir: str | None = None


@dataclass
class StageResult:
    model_key: str
    verdict: dict | None
    attempts: list[dict]
    raw_final: str
    truncation_log: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.verdict is not None


def _gen_params(cfg: PipelineConfig, max_tokens: int) -> dict:
    return {
        "temperature": cfg.temperature,
        "top_p": cfg.top_p,
        "seed": cfg.seed,
        "max_tokens": max_tokens,
    }


def _test_sources(bundle: Bundle) -> list[tuple[str, str]]:
    out = []
    for tf in bundle.test_files:
        try:
            src = tf.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            src = f"(could not read test file: {e})"
        out.append((tf.name, src))
    return out


def _jar_dir(cfg: PipelineConfig) -> Path | None:
    if not cfg.jar_dir:
        return None
    candidate = Path(cfg.jar_dir)
    return candidate if candidate.is_dir() else None


def _mechanical_facts(bundle: Bundle, repo_root: Path, cfg: PipelineConfig) -> dict:
    facts: dict = {
        "disclosure_commit_claimed": bundle.commit,
        "cvss_check": mech.check_cvss(bundle.cvss_vector, bundle.claimed_score),
        "patch_applies_at_head": mech.check_patch_applies(repo_root, bundle.diff_text),
        "embedded_vs_saved_patch": mech.compare_embedded_vs_file(
            bundle.diff_text, bundle.patch_file_path
        ),
        "fileline_refs": mech.check_fileline_refs(bundle.text, repo_root),
    }
    if cfg.run_tests and bundle.test_files:
        facts["junit_prepatch"] = mech.compile_and_run_tests(
            bundle.test_files, repo_root, jar_dir=_jar_dir(cfg)
        )
    if (
        cfg.postpatch
        and cfg.run_tests
        and bundle.test_files
        and (facts.get("patch_applies_at_head") or {}).get("ok")
    ):
        facts["postpatch"] = mech.run_postpatch_loop(
            repo_root, bundle.diff_text, bundle.test_files, jar_dir=_jar_dir(cfg)
        )
    return facts


def verify_disclosure(
    bundle: Bundle,
    cfg: PipelineConfig,
    runner,
    lifecycle,
    out_dir: Path,
    security_model_text: str,
    repo_root: Path,
) -> dict:
    """Run the full verification for one disclosure; write all artifacts.

    Returns a summary row (also written to ``out_dir/summary.json``).
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # -- inputs ------------------------------------------------------------
    inputs = {
        "slug": bundle.slug,
        "disclosure_path": str(bundle.path),
        "disclosure_sha256": bundle.sha256,
        "test_files": [str(t) for t in bundle.test_files],
        "unresolved_test_names": bundle.unresolved_test_names,
        "patch_file": str(bundle.patch_file_path) if bundle.patch_file_path else None,
        "patch_file_sha256": bundle.patch_file_sha256,
        "truncation_log": [],
    }

    # -- mechanical checks on the originals ---------------------------------
    mech_facts = _mechanical_facts(bundle, repo_root, cfg)
    (out_dir / "mechanical.json").write_text(json.dumps(mech_facts, indent=2), encoding="utf-8")

    # -- evaluator stages: one model at a time (A, B, C, ...) -----------------
    eval_stages: list[tuple[str, EvaluatorSpec, StageResult]] = []
    truncation_entries: list[dict] = []
    for i, spec in enumerate(cfg.evaluators):
        letter = chr(ord("A") + i)
        messages, log = build_eval_prompt(
            bundle.text,
            bundle.diff_text,
            _test_sources(bundle),
            mech_facts,
            security_model_text,
            spec.input_budget_chars,
        )
        stage = _run_stage(
            spec.model_key, messages, cfg.max_tokens_eval, EVAL_REQUIRED_KEYS, log.entries, cfg, runner, lifecycle
        )
        _write_stage(out_dir, letter.lower(), stage)
        eval_stages.append((letter, spec, stage))
        truncation_entries.extend(log.entries)

    # -- adjudication stage ----------------------------------------------------
    adj_letter = chr(ord("A") + len(cfg.evaluators))
    verdicts: list[tuple[str, str, dict]] = [
        (
            letter,
            spec.model_key,
            stage.verdict or {"error": f"stage {letter} ({spec.name} evaluator) produced no valid verdict"},
        )
        for letter, spec, stage in eval_stages
    ]

    # Precompute scores for every CVSS vector mentioned anywhere (disclosure +
    # all evaluator verdicts) so the adjudicator never has to do CVSS math.
    mech_facts_c = dict(mech_facts)
    candidates = candidates_from_texts([bundle.text] + [json.dumps(v[2]) for v in verdicts])
    if candidates:
        cc = dict(mech_facts_c.get("cvss_check") or {})
        cc["candidates"] = candidates
        mech_facts_c["cvss_check"] = cc

    messages_c, log_c = build_adjudication_prompt(
        bundle.text,
        bundle.diff_text,
        _test_sources(bundle),
        mech_facts_c,
        verdicts,
        security_model_text,
        cfg.adjudicator_input_budget_chars,
    )
    stage_c = _run_stage(
        cfg.adjudicator_model, messages_c, cfg.max_tokens_final, ADJUDICATION_REQUIRED_KEYS, log_c.entries, cfg, runner, lifecycle
    )
    _write_stage(out_dir, adj_letter.lower(), stage_c)

    # -- edits -----------------------------------------------------------------
    edit_report: dict = {"proposed": 0, "applied": [], "failed": [], "notes": []}
    final_verdict = stage_c.verdict or {}
    if final_verdict:
        _enforce_classification(final_verdict)
        if final_verdict.get("classification_note"):
            edit_report["notes"].append(final_verdict["classification_note"])
        # Mechanical check of the adjudicator's own CVSS arithmetic.
        fv = final_verdict.get("final_cvss_vector")
        fs = final_verdict.get("final_base_score")
        if isinstance(fv, str) and fv.strip():
            try:
                computed_final = base_score(fv)
            except CvssError as e:
                edit_report["notes"].append(
                    f"adjudicator's final_cvss_vector is invalid: {e}"
                )
            else:
                if (
                    isinstance(fs, (int, float))
                    and abs(float(fs) - computed_final) >= 0.05
                ):
                    edit_report["notes"].append(
                        f"adjudicator's final_base_score {fs} does not match the "
                        f"mechanically computed {computed_final} for its own vector; "
                        f"the computed value is authoritative"
                    )
    if final_verdict.get("edits"):
        edits, notes = edits_from_adjudication(final_verdict, bundle)
        edit_report["proposed"] = len(edits)
        edit_report["notes"].extend(notes)
        if edits:
            result = apply_edits(edits)
            edit_report["applied"] = result.applied
            edit_report["failed"] = result.failed

            # Mechanical auto-fix: CVSS number mismatch where the adjudicator's
            # final score matches the mechanically computed one.
            cvss_check = mech_facts.get("cvss_check") or {}
            if (
                cvss_check.get("score_match") is False
                and isinstance(final_verdict.get("final_base_score"), (int, float))
                and abs(float(final_verdict["final_base_score"]) - float(cvss_check["computed_score"])) < 0.05
            ):
                edit_report["notes"].append(
                    "mechanical CVSS score mismatch present; adjudicator final score matches computed value"
                )

            # Re-verify edited artifacts before accepting them. The baseline is
            # the original pre-patch JUnit run so we can detect outcome drift.
            recheck = _reverify_edited(
                bundle, repo_root, cfg, mech_facts.get("junit_prepatch")
            )
            edit_report["reverification"] = recheck
            if not recheck.get("passed", False):
                touched = {Path(a["path"]) for a in result.applied}
                revert_result = revert(list(touched))
                edit_report["reverted"] = True
                edit_report["revert_detail"] = revert_result
                edit_report["status"] = "rejected-reverted"
            else:
                edit_report["status"] = "applied-verified"
    else:
        edit_report["status"] = "no-edits"

    # -- report ------------------------------------------------------------------
    inputs["truncation_log"] = truncation_entries + log_c.entries
    (out_dir / "inputs.json").write_text(json.dumps(inputs, indent=2), encoding="utf-8")
    (out_dir / "edits.json").write_text(
        json.dumps(edit_report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    inconclusive_reasons: list[str] = []
    for letter, spec, stage in eval_stages:
        if not stage.ok:
            inconclusive_reasons.append(
                f"stage {letter} ({spec.name} evaluator) produced no valid verdict"
            )
    if not stage_c.ok:
        inconclusive_reasons.append(f"stage {adj_letter} (adjudicator) produced no valid verdict")

    summary = {
        "slug": bundle.slug,
        "title": bundle.title,
        "timestamp_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "models_used": [
            {"stage": f"{letter}-evaluator", "model": spec.model_key, "context_length": spec.ctx_tokens}
            for letter, spec, _st in eval_stages
        ]
        + [
            {
                "stage": f"{adj_letter}-adjudicator",
                "model": cfg.adjudicator_model,
                "context_length": cfg.adjudicator_ctx,
            }
        ],
        "generation_params": {
            "temperature": cfg.temperature,
            "top_p": cfg.top_p,
            "seed": cfg.seed,
            "no_think": True,
            "max_tokens_eval": cfg.max_tokens_eval,
            "max_tokens_final": cfg.max_tokens_final,
            "retry_escalation": f"max_tokens doubles per retry attempt (cap {MAX_TOKENS_CAP})",
        },
        **{f"stage_{letter.lower()}_ok": stage.ok for letter, _spec, stage in eval_stages},
        f"stage_{adj_letter.lower()}_ok": stage_c.ok,
        "classification": final_verdict.get("classification"),
        "legit_security_finding": final_verdict.get("legit_security_finding"),
        "final_cvss_vector": final_verdict.get("final_cvss_vector"),
        "final_base_score": final_verdict.get("final_base_score"),
        "cvss_mechanical_check": mech_facts.get("cvss_check"),
        "patch_applies_at_head": (mech_facts.get("patch_applies_at_head") or {}).get("ok"),
        "junit_prepatch_ok": _summarize_junit(mech_facts.get("junit_prepatch")),
        "postpatch": (
            {
                "applied_ok": pp.get("applied_ok"),
                "restored_ok": pp.get("restored_ok"),
                "recompile_failures": pp.get("recompile_failures", []),
                "junit": _summarize_junit((pp or {}).get("junit")),
            }
            if (pp := mech_facts.get("postpatch")) is not None
            else None
        ),
        "edits_status": edit_report["status"],
        "truncation_log": inputs["truncation_log"],
        "inconclusive": bool(inconclusive_reasons),
        "inconclusive_reasons": inconclusive_reasons,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    report_md = render_report(bundle, summary, mech_facts, eval_stages, stage_c, edit_report)
    (out_dir / "report.md").write_text(report_md, encoding="utf-8")
    return summary


def _stage_config(cfg: PipelineConfig, model_key: str) -> dict:
    """Explicit load config per stage model (deterministic context length)."""
    for spec in cfg.evaluators:
        if spec.model_key == model_key:
            return {"context_length": spec.ctx_tokens}
    if model_key == cfg.adjudicator_model:
        return {"context_length": cfg.adjudicator_ctx}
    return {}


def _run_stage(model_key, messages, max_tokens, required_keys, truncation_entries, cfg, runner, lifecycle) -> StageResult:
    with lifecycle.stage(model_key, **_stage_config(cfg, model_key)):
        verdict, attempts = call_with_retry(
            runner, model_key, messages, _gen_params(cfg, max_tokens), required_keys, max_attempts=cfg.max_attempts
        )
    raw_final = attempts[-1]["raw_text"] if attempts else ""
    return StageResult(
        model_key=model_key,
        verdict=verdict,
        attempts=attempts,
        raw_final=raw_final,
        truncation_log=list(truncation_entries),
    )


def _clip_meta(meta: dict | None) -> dict | None:
    """Per-attempt generation diagnostics for the stage JSON (already clipped upstream)."""
    if not meta:
        return None
    out = {
        "finish_reason": meta.get("finish_reason"),
        "usage": meta.get("usage"),
        "reasoning_chars": meta.get("reasoning_chars"),
        "reasoning_head": meta.get("reasoning_head"),
        "reasoning_tail": meta.get("reasoning_tail"),
    }
    # Record when the verdict had to be salvaged from the thinking stream, or
    # when thinking suppression fell back — both are material to reproducibility.
    for key in ("recovered_from_reasoning", "thinking_suppression_fallback"):
        if key in meta:
            out[key] = meta[key]
    return out


def _write_stage(out_dir: Path, letter: str, stage: StageResult) -> None:
    (out_dir / f"stage-{letter}.raw.txt").write_text(stage.raw_final or "", encoding="utf-8")
    payload = {
        "model": stage.model_key,
        "verdict": stage.verdict,
        "attempts": [
            {
                "attempt": a["attempt"],
                "problems": a["problems"],
                "max_tokens": a.get("max_tokens"),
                "meta": _clip_meta(a.get("meta")),
            }
            for a in stage.attempts
        ],
    }
    (out_dir / f"stage-{letter}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _reverify_edited(
    bundle: Bundle, repo_root: Path, cfg: PipelineConfig, baseline_junit: dict | None = None
) -> dict:
    """Re-run mechanical checks against the (possibly edited) artifacts."""
    from .parse_disclosure import parse_disclosure

    # Same test roots as the original parse in __main__.py: the campaign root
    # (disclosures_dir.parent == bundle.path.parent.parent) plus the repo.
    try:
        fresh = parse_disclosure(bundle.path, [bundle.path.parent.parent, repo_root])
    except Exception as e:  # noqa: BLE001 - report and fail closed
        return {"passed": False, "error": f"re-parse failed after edits: {e}"}

    result: dict = {
        "patch_applies_at_head": mech.check_patch_applies(repo_root, fresh.diff_text),
        "cvss_check": mech.check_cvss(fresh.cvss_vector, fresh.claimed_score),
    }
    passed = bool(result["patch_applies_at_head"].get("ok"))
    if result["cvss_check"].get("score_match") is False:
        # A CVSS mismatch alone does not reject edits (the vector may have been
        # corrected intentionally); only an invalid vector fails the recheck.
        if "error" in result["cvss_check"]:
            passed = False

    if cfg.run_tests and fresh.test_files:
        junit = mech.compile_and_run_tests(fresh.test_files, repo_root, jar_dir=_jar_dir(cfg))
        result["junit_prepatch"] = _summarize_junit(junit)
        # Edits must not change any test's pre-patch outcome. The bar that the
        # disclosure's verification tests FAIL on unmodified source was already
        # established by the original mechanical facts; here we only require
        # that editing preserved it. Pre-existing defect-marker suites may
        # legitimately PASS pre-patch (they assert buggy behavior), so a
        # blanket "all classes must fail" check would wrongly reject edits to
        # them.
        if baseline_junit:

            def _outcomes(j: dict) -> dict[str, object]:
                return {
                    Path(c["file"]).name: c.get("ok")
                    for c in j.get("classes", [])
                    if c.get("ran") and c.get("file")
                }

            before = _outcomes(baseline_junit)
            after = _outcomes(junit)
            drift = [
                f"{name}: {before.get(name)} -> {after.get(name)}"
                for name in sorted(set(before) | set(after))
                if before.get(name) != after.get(name)
            ]
            result["junit_outcome_drift"] = drift
            if drift:
                passed = False
    return {"passed": passed, **result}


def _summarize_junit(junit: dict | None) -> dict | None:
    if not junit:
        return None
    classes = []
    for c in junit.get("classes", []):
        classes.append(
            {
                "file": c.get("file"),
                "ran": c.get("ran"),
                "ok": c.get("ok"),
                "failures": c.get("failures"),
            }
        )
    return {"compiled": junit.get("compiled"), "classes": classes}


def _fmt_verdict(verdict: dict | None, indent: str = "  ") -> str:
    import json as _json

    if verdict is None:
        return f"{indent}(no valid verdict produced)\n"
    return _json.dumps(verdict, indent=2, ensure_ascii=False)


def render_report(
    bundle: Bundle,
    summary: dict,
    mech_facts: dict,
    eval_stages: list[tuple[str, EvaluatorSpec, StageResult]],
    stage_c: StageResult,
    edit_report: dict,
) -> str:
    lines: list[str] = []
    add = lines.append
    add(f"# Verification report — {bundle.slug}")
    add("")
    add(f"- Title: {bundle.title or '(no title)'}")
    add(f"- Disclosure: `{bundle.path}` (sha256 `{bundle.sha256[:16]}…`)")
    if bundle.commit:
        add(f"- Commit claimed by disclosure: `{bundle.commit}`")
    add(f"- Generated: {summary['timestamp_utc']}")
    cls = summary.get("classification")
    if cls:
        add(f"- **Classification: {cls}** (legit_security_finding={summary.get('legit_security_finding')})")
    if summary.get("inconclusive"):
        n_eval = sum(1 for m in summary.get("models_used", []) if m["stage"].endswith("-evaluator"))
        add("")
        add("> **WARNING — INCONCLUSIVE:** " + "; ".join(summary["inconclusive_reasons"]) + ".")
        add(f"> The adjudication below rests on fewer than {n_eval} independent model evaluations.")
    add("")

    add("## Models used to evaluate")
    add("")
    add("| Stage | Model | Context length | Generation params |")
    add("|---|---|---|---|")
    gp = summary["generation_params"]
    gparams = f"temp={gp['temperature']}, top_p={gp['top_p']}, seed={gp['seed']}"
    for m in summary["models_used"]:
        mt = gp["max_tokens_eval"] if not m["stage"].endswith("-adjudicator") else gp["max_tokens_final"]
        add(f"| {m['stage']} | `{m['model']}` | {m['context_length']} | {gparams}, max_tokens={mt} |")
    add("")

    add("## Mechanical checks (deterministic, no model)")
    add("")
    cv = mech_facts.get("cvss_check") or {}
    if cv.get("ok"):
        match_txt = "MATCH" if cv.get("score_match") else ("MISMATCH" if cv.get("score_match") is False else "(no claimed score to compare)")
        add(f"- CVSS: vector `{cv['vector']}` → computed **{cv['computed_score']}**, claimed {cv.get('claimed_score')} — **{match_txt}**")
    else:
        add(f"- CVSS: {cv.get('error', 'check failed')}")
    pa = mech_facts.get("patch_applies_at_head") or {}
    if pa.get("ok"):
        add("- Patch `git apply --check` at repo HEAD: **PASS**")
    else:
        add(f"- Patch `git apply --check` at repo HEAD: **FAIL** — {pa.get('stderr', '')[:300]}")
    ev = mech_facts.get("embedded_vs_saved_patch") or {}
    if ev.get("present"):
        state = "identical" if ev.get("identical") else "**DIFFERENT** (embedded diff vs saved .patch)"
        add(f"- Embedded diff vs saved `.patch` file: {state}")
    fl = mech_facts.get("fileline_refs") or {}
    if fl.get("checked"):
        add(f"- file:line references checked: {fl['checked']}, bad: {fl['bad']}")
        for r in fl.get("refs", []):
            if not (r["file_exists"] and r["line_in_range"]):
                add(f"  - BAD: `{r['ref']}` (exists={r['file_exists']}, in_range={r['line_in_range']})")
    jp = mech_facts.get("junit_prepatch")
    if jp is not None:
        js = _summarize_junit(jp) or {}
        add(f"- JUnit pre-patch (unmodified source): compiled={js.get('compiled')}")
        for c in js.get("classes", []):
            state = "PASS" if c.get("ok") else ("FAIL" if c.get("ok") is False else "UNCLASSIFIED")
            add(f"  - `{c.get('file')}`: {state} (failures={c.get('failures')})")
        add("  - The disclosure's verification tests are expected to FAIL here; pre-existing suites may legitimately PASS (they can assert buggy behavior).")
    pp = mech_facts.get("postpatch")
    if pp is not None:
        if not pp.get("applied_ok"):
            add(f"- Post-patch run: patch did NOT apply in-repo — {pp.get('apply_stderr', '')[:300]}")
        else:
            js = _summarize_junit(pp.get("junit")) or {}
            add(f"- JUnit post-patch (patched source): compiled={js.get('compiled')}, restored_ok={pp.get('restored_ok')}")
            for c in js.get("classes", []):
                state = "PASS" if c.get("ok") else ("FAIL" if c.get("ok") is False else "UNCLASSIFIED")
                add(f"  - `{c.get('file')}`: {state} (failures={c.get('failures')})")
            add("  - The disclosure's verification tests are expected to PASS here; defect-marker assertions in pre-existing suites may legitimately flip.")
            if pp.get("recompile_failures"):
                for rf in pp["recompile_failures"]:
                    add(f"  - recompile failure: {rf[:300]}")
    add("")

    for letter, spec, stage in eval_stages:
        add(f"## Stage {letter} — Evaluator ({spec.name}: `{spec.model_key}`)")
        add("")
        if not stage.ok:
            add("No valid verdict produced. Raw output:")
            add("")
            add("```")
            add(stage.raw_final[:4000])
            add("```")
        else:
            v = stage.verdict or {}
            add(f"- is_security_problem_per_trust_model: **{v.get('is_security_problem_per_trust_model')}** (confidence: {v.get('confidence', 'n/a')})")
            ca = v.get("cvss_assessment") or {}
            if isinstance(ca, dict):
                add(f"- CVSS assessment: agrees_with_claimed={ca.get('agrees_with_claimed_vector')}, proposed `{ca.get('proposed_vector')}` (score {ca.get('base_score')})")
            inc = v.get("inaccuracies") or []
            if inc:
                add("- Inaccuracies found:")
                for item in inc:
                    add(f"  - {item}")
            else:
                add("- Inaccuracies found: none reported")
            add("")
            add("<details><summary>Full verdict JSON</summary>")
            add("")
            add("```json")
            add(_fmt_verdict(stage.verdict).strip())
            add("```")
            add("</details>")
        add("")

    adj_letter = chr(ord("A") + len(eval_stages))
    adj_model = next(
        (m["model"] for m in summary.get("models_used", []) if m["stage"].endswith("-adjudicator")),
        "(unknown)",
    )
    add(f"## Stage {adj_letter} — Final adjudication (`{adj_model}`)")
    add("")
    if not stage_c.ok:
        add("No valid verdict produced. Raw output:")
        add("")
        add("```")
        add(stage_c.raw_final[:4000])
        add("```")
    else:
        v = stage_c.verdict or {}
        cls = v.get("classification")
        add(f"- **Classification: {cls}** — legit_security_finding: {v.get('legit_security_finding')} (confidence: {v.get('confidence', 'n/a')})")
        if v.get("classification_note"):
            add(f"  - note: {v['classification_note']}")
        add(f"- Final CVSS: `{v.get('final_cvss_vector')}` — base score **{v.get('final_base_score')}**")
        if v.get("trust_model_ruling"):
            add(f"- Trust-model ruling: {v['trust_model_ruling']}")
        if v.get("impact_summary"):
            add(f"- Impact: {v['impact_summary']}")
        ma = v.get("model_agreement") or {}
        if isinstance(ma, dict):
            for letter, spec, _st in eval_stages:
                key = f"evaluator_{letter}_verdict"
                if key in ma:
                    add(f"- Evaluator {letter} ({spec.name}) verdict per adjudicator: **{ma[key]}**")
        if isinstance(ma, dict) and ma.get("disagreements"):
            add("- Disagreements resolved:")
            for d in ma["disagreements"]:
                add(f"  - {d}")
        add("")
        add("<details><summary>Full adjudication JSON</summary>")
        add("")
        add("```json")
        add(_fmt_verdict(stage_c.verdict).strip())
        add("```")
        add("</details>")
    add("")

    add("## Edits to original artifacts")
    add("")
    status = edit_report.get("status", "unknown")
    if status == "no-edits":
        add("No edits proposed by the adjudicator; originals untouched.")
    else:
        add(f"Status: **{status}** (proposed: {edit_report.get('proposed', 0)})")
        for a in edit_report.get("applied", []):
            add("")
            add(f"- Applied to `{a['path']}` (backup: `{a.get('backup_path')}`)")
            add(f"  - reason: {a.get('reason', '')}")
            cur = a.get("current_text", "")
            prop = a.get("proposed_text", "")
            add("  - before:")
            add("    ```")
            for ln in cur.splitlines()[:40]:
                add(f"    {ln}")
            if len(cur.splitlines()) > 40:
                add("    … (truncated)")
            add("    ```")
            add("  - after:")
            add("    ```")
            for ln in prop.splitlines()[:40]:
                add(f"    {ln}")
            if len(prop.splitlines()) > 40:
                add("    … (truncated)")
            add("    ```")
        for f_ in edit_report.get("failed", []):
            add("")
            add(f"- FAILED to apply on `{f_.get('path')}`: {f_.get('error')}")
        rv = edit_report.get("reverification") or {}
        if rv:
            add("")
            add(f"Re-verification of edited artifacts: **{'PASS' if rv.get('passed') else 'FAIL'}** (full detail in `edits.json`)")
            pa2 = rv.get("patch_applies_at_head") or {}
            add(f"- Patch `git apply --check` at repo HEAD after edits: {'PASS' if pa2.get('ok') else 'FAIL'}")
            cv2 = rv.get("cvss_check") or {}
            if cv2.get("ok"):
                add(f"- CVSS after edits: vector `{cv2['vector']}` → computed **{cv2['computed_score']}** (claimed {cv2.get('claimed_score')})")
            else:
                add(f"- CVSS after edits: {cv2.get('error', 'check failed')}")
            js2 = rv.get("junit_prepatch") or {}
            if js2:
                add(f"- JUnit pre-patch after edits (unmodified source): compiled={js2.get('compiled')}")
                for c in js2.get("classes", []):
                    state = "PASS" if c.get("ok") else ("FAIL" if c.get("ok") is False else "UNCLASSIFIED")
                    add(f"  - `{c.get('file')}`: {state} (failures={c.get('failures')})")
            for d in rv.get("junit_outcome_drift", []):
                add(f"  - OUTCOME DRIFT vs pre-edit baseline: {d}")
        if edit_report.get("reverted"):
            add("")
            add("- Re-verification of edited artifacts FAILED — all applied edits were reverted from their `.orig` backups. See `edits.json` for detail.")
        for n in edit_report.get("notes", []):
            add(f"- note: {n}")
    add("")

    truncations = summary.get("truncation_log") or []
    if truncations:
        add("## Prompt truncations (deterministic, recorded)")
        add("")
        for t in truncations:
            add(
                f"- `{t['section']}`: {t['original_chars']} → {t['kept_chars']} chars "
                f"({t['omitted_chars']} omitted, method={t['method']})"
            )
        add("")

    return "\n".join(lines) + "\n"
