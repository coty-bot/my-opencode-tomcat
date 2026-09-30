"""CLI: verify one or all Tomcat security disclosures (independent evaluator models + adjudicator).

All machine-local values (paths, LM Studio URL, model keys, context lengths,
input budgets, generation params) come from config.toml at the tool root; CLI
flags override them for a single run. See disclosure_verifier/config.py for the
schema and validation rules.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from .config import (
    DEFAULT_CONFIG_PATH,
    ConfigError,
    apply_evaluator_overrides,
    load_config,
    select_evaluators,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="disclosure-verifier", description=__doc__)
    p.add_argument(
        "slugs",
        nargs="*",
        help="disclosure slugs to verify (default: all *.md in the configured disclosures dir)",
    )
    p.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="path to config.toml")

    # --- overrides for individual config values ------------------------------
    p.add_argument("--repo-root", help="override repo_root (Tomcat checkout)")
    p.add_argument("--disclosures-dir", help="override disclosures_dir")
    p.add_argument(
        "--out-dir",
        default=None,
        help="output root (default: <campaign>/verification, i.e. the parent of the disclosures dir)",
    )
    p.add_argument("--security-model", help="override security_model path")
    p.add_argument("--jar-dir", help="override jar_dir (empty string disables test execution)")
    p.add_argument("--lmstudio-url", help="override [lmstudio] url")

    # Per-evaluator overrides, keyed by the evaluator `name` in config.toml.
    for name in ("27b", "7b", "cyber"):
        p.add_argument(f"--model-{name}", help=f"override the {name} evaluator's model key")
        p.add_argument(f"--ctx-{name}", type=int, help=f"override the {name} evaluator's ctx_tokens")
        p.add_argument(
            f"--input-budget-{name}-chars",
            type=int,
            help=f"override the {name} evaluator's input_budget_chars",
        )
    p.add_argument(
        "--evaluators",
        default=None,
        help="comma-separated evaluator names to run (default: all configured; stage order follows config.toml)",
    )

    # Generation / pipeline overrides.
    p.add_argument("--seed", type=int)
    p.add_argument("--temperature", type=float)
    p.add_argument("--top-p", type=float, dest="top_p")
    p.add_argument("--max-tokens-eval", type=int)
    p.add_argument("--max-tokens-final", type=int)
    p.add_argument("--no-tests", action="store_true", help="skip JUnit compile/run stages")
    p.add_argument(
        "--no-postpatch", action="store_true", help="skip the apply-patch-and-rerun-tests stage"
    )
    return p


def _apply_overrides(cfg, args):
    """Fold CLI overrides into the loaded config; raise ConfigError on bad names."""
    if args.repo_root is not None:
        cfg = replace(cfg, repo_root=Path(args.repo_root))
    if args.disclosures_dir is not None:
        cfg = replace(cfg, disclosures_dir=Path(args.disclosures_dir))
    if args.security_model is not None:
        cfg = replace(cfg, security_model=Path(args.security_model))
    if args.jar_dir is not None:
        cfg = replace(cfg, jar_dir=Path(args.jar_dir) if args.jar_dir else None)
    if args.lmstudio_url is not None:
        cfg = replace(cfg, lmstudio_url=args.lmstudio_url)

    for flag in ("seed", "temperature", "top_p", "max_tokens_eval", "max_tokens_final"):
        val = getattr(args, flag)
        if val is not None:
            cfg = replace(cfg, **{flag: val})

    return apply_evaluator_overrides(
        cfg,
        models={n: v for n, v in (
            ("27b", args.model_27b),
            ("7b", args.model_7b),
            ("cyber", args.model_cyber),
        ) if v is not None},
        ctx_tokens={n: v for n, v in (
            ("27b", args.ctx_27b),
            ("7b", args.ctx_7b),
            ("cyber", args.ctx_cyber),
        ) if v is not None},
        input_budget_chars={n: v for n, v in (
            ("27b", args.input_budget_27b_chars),
            ("7b", args.input_budget_7b_chars),
            ("cyber", args.input_budget_cyber_chars),
        ) if v is not None},
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    from .lmstudio import LmStudioClient, LmStudioRunner, ModelLifecycle
    from .parse_disclosure import parse_disclosure
    from .pipeline import PipelineConfig, verify_disclosure

    try:
        cfg = load_config(args.config)
        cfg = _apply_overrides(cfg, args)
        requested = (
            [n.strip() for n in args.evaluators.split(",") if n.strip()]
            if args.evaluators is not None
            else None
        )
        evaluators = select_evaluators(cfg, requested)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    disclosures_dir = cfg.disclosures_dir
    if not disclosures_dir.is_dir():
        print(f"error: disclosures dir not found: {disclosures_dir}", file=sys.stderr)
        return 2
    security_model_path = cfg.security_model
    if not security_model_path.is_file():
        print(f"error: security model file not found: {security_model_path}", file=sys.stderr)
        return 2

    md_files = sorted(disclosures_dir.glob("*.md"))
    if args.slugs:
        wanted = set(args.slugs)
        md_files = [m for m in md_files if m.stem in wanted]
        missing = wanted - {m.stem for m in md_files}
        if missing:
            print(f"error: no disclosure file(s) for slug(s): {sorted(missing)}", file=sys.stderr)
            return 2
    if not md_files:
        print("error: no disclosures selected", file=sys.stderr)
        return 2

    out_root = Path(args.out_dir) if args.out_dir else disclosures_dir.parent / "verification"
    security_model_text = security_model_path.read_text(encoding="utf-8")
    repo_root = cfg.repo_root

    pipeline_cfg = PipelineConfig(
        evaluators=evaluators,
        adjudicator_model=cfg.adjudicator_model,
        adjudicator_ctx=cfg.adjudicator_ctx,
        adjudicator_input_budget_chars=cfg.adjudicator_input_budget_chars,
        seed=cfg.seed,
        temperature=cfg.temperature,
        top_p=cfg.top_p,
        max_tokens_eval=cfg.max_tokens_eval,
        max_tokens_final=cfg.max_tokens_final,
        run_tests=(not args.no_tests) and cfg.run_tests,
        postpatch=(not args.no_postpatch) and cfg.postpatch,
        jar_dir=str(cfg.jar_dir) if cfg.jar_dir else None,
    )

    client = LmStudioClient(base_url=cfg.lmstudio_url)
    lifecycle = ModelLifecycle(client)
    # The runner evicts intruding models before every call so each generation
    # starts with exactly one model resident.
    runner = LmStudioRunner(client, lifecycle=lifecycle)
    try:
        available = {row["key"] for row in client.list_models()}
    except Exception as e:  # noqa: BLE001
        print(f"error: cannot reach LM Studio at {cfg.lmstudio_url}: {e}", file=sys.stderr)
        return 2

    wanted_models = [s.model_key for s in pipeline_cfg.evaluators] + [pipeline_cfg.adjudicator_model]
    missing_models = [k for k in dict.fromkeys(wanted_models) if k not in available]
    if missing_models:
        print(f"error: model(s) not loaded/known to LM Studio: {missing_models}", file=sys.stderr)
        print(f"available models: {sorted(available)}", file=sys.stderr)
        return 2

    out_root.mkdir(parents=True, exist_ok=True)

    # Snapshot whatever is currently loaded for the audit trail (lifecycle.json).
    lifecycle.snapshot()

    rows = []
    try:
        # Test files live under the campaign root (which mirrors the repo
        # layout: test/, tests/, test-services/), not inside disclosures/.
        # Test roots: the campaign dir (new tests live beside disclosures/)
        # first, then the repo itself (disclosures may cite pre-existing
        # Tomcat tests by path).
        for md in md_files:
            bundle = parse_disclosure(md, [disclosures_dir.parent, repo_root])
            out_dir = out_root / bundle.slug
            print(f"== verifying {bundle.slug} -> {out_dir}", file=sys.stderr)
            try:
                summary = verify_disclosure(
                    bundle, pipeline_cfg, runner, lifecycle, out_dir, security_model_text, repo_root
                )
            except Exception as e:  # noqa: BLE001 - keep the campaign alive
                print(f"!! {bundle.slug} failed: {e!r}", file=sys.stderr)
                summary = {
                    "slug": bundle.slug,
                    "classification": None,
                    "legit_security_finding": None,
                    "error": f"{type(e).__name__}: {e}",
                }
            rows.append(summary)
    finally:
        # Always end with a clean slate: unload every model so nothing lingers
        # in VRAM to contend with whatever runs next (agent turns, other jobs).
        try:
            final_unloaded = lifecycle.unload_all()
        except Exception as e:  # noqa: BLE001 - cleanup must not mask results
            print(f"warning: could not unload all models at end: {e!r}", file=sys.stderr)
            final_unloaded = None
        (out_root / "lifecycle.json").write_text(
            json.dumps({"events": lifecycle.events, "final_unloaded": final_unloaded}, indent=2),
            encoding="utf-8",
        )

    # Merge with any existing all-summary.json (keyed by slug) so partial
    # re-runs update their rows instead of clobbering the full campaign.
    summary_path = out_root / "all-summary.json"
    merged: dict[str, dict] = {}
    if summary_path.exists():
        try:
            for r in json.loads(summary_path.read_text(encoding="utf-8")):
                if isinstance(r, dict) and r.get("slug"):
                    merged[r["slug"]] = r
        except (json.JSONDecodeError, OSError):
            pass
    for r in rows:
        if isinstance(r, dict) and r.get("slug"):
            merged[r["slug"]] = r
    summary_path.write_text(json.dumps(list(merged.values()), indent=2), encoding="utf-8")
    print(f"\nDone. {len(rows)} disclosure(s) verified -> {out_root}", file=sys.stderr)
    for r in rows:
        cls = r.get("classification") or "INCONCLUSIVE"
        print(
            f"  {r['slug']}: {cls} (cvss={r.get('final_base_score')} edits={r.get('edits_status')})",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
