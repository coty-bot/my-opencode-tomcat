"""CLI: verify one or all Tomcat security disclosures (independent evaluator models + adjudicator)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_REPO = "/home/opencode/src/tomcat"
DEFAULT_SECURITY_MODEL = (
    "/home/opencode/workspace/security-scans/tomcat/SECURITY-MODEL.md"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="disclosure-verifier", description=__doc__)
    p.add_argument(
        "slugs",
        nargs="*",
        help="disclosure slugs to verify (default: all *.md in --disclosures-dir)",
    )
    p.add_argument("--repo-root", default=DEFAULT_REPO)
    p.add_argument(
        "--disclosures-dir",
        default="/home/opencode/workspace/security-scans/tomcat/disclosures",
    )
    p.add_argument("--out-dir", default=None, help="default: <campaign>/verification")
    p.add_argument("--security-model", default=DEFAULT_SECURITY_MODEL)
    p.add_argument("--model-27b", default="qwen/qwen3.8-27b")
    p.add_argument("--model-7b", default="vulnllm-r-7b")
    p.add_argument(
        "--model-cyber",
        default=(
            "ravenx-cyberagent-qwen3.6-35b-a3b-opus-4.7-openmythos-pentester-bughunter-rath"
        ),
    )
    p.add_argument(
        "--evaluators",
        default="27b,7b,cyber",
        help=(
            "comma-separated evaluator stages to run (subset of: 27b,7b,cyber); "
            "always runs in canonical order; the adjudicator is separate"
        ),
    )
    p.add_argument("--ctx-27b", type=int, default=65536)
    p.add_argument("--ctx-7b", type=int, default=32768)
    p.add_argument("--ctx-cyber", type=int, default=98304)
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--top-p", type=float, default=1.0)
    p.add_argument("--max-tokens-eval", type=int, default=8192)
    p.add_argument("--max-tokens-final", type=int, default=16384)
    p.add_argument("--input-budget-27b-chars", type=int, default=140_000)
    p.add_argument("--input-budget-7b-chars", type=int, default=80_000)
    p.add_argument("--input-budget-cyber-chars", type=int, default=140_000)
    p.add_argument("--jar-dir", default="/home/opencode/tomcat-build-libs")
    p.add_argument("--no-tests", action="store_true", help="skip JUnit compile/run stages")
    p.add_argument(
        "--no-postpatch", action="store_true", help="skip the apply-patch-and-rerun-tests stage"
    )
    p.add_argument(
        "--lmstudio-url", default="http://127.0.0.1:1234"
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    from .lmstudio import LmStudioClient, LmStudioRunner, ModelLifecycle
    from .pipeline import EvaluatorSpec, PipelineConfig, verify_disclosure
    from .parse_disclosure import parse_disclosure

    disclosures_dir = Path(args.disclosures_dir)
    if not disclosures_dir.is_dir():
        print(f"error: disclosures dir not found: {disclosures_dir}", file=sys.stderr)
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
    security_model_text = Path(args.security_model).read_text(encoding="utf-8")
    repo_root = Path(args.repo_root)

    spec_by_name = {
        "27b": EvaluatorSpec("27b", args.model_27b, args.ctx_27b, args.input_budget_27b_chars),
        "7b": EvaluatorSpec("7b", args.model_7b, args.ctx_7b, args.input_budget_7b_chars),
        "cyber": EvaluatorSpec(
            "cyber", args.model_cyber, args.ctx_cyber, args.input_budget_cyber_chars
        ),
    }
    requested = [n.strip() for n in args.evaluators.split(",") if n.strip()]
    unknown = [n for n in requested if n not in spec_by_name]
    if unknown:
        print(
            f"error: unknown evaluator(s) {unknown}; choose from {sorted(spec_by_name)}",
            file=sys.stderr,
        )
        return 2
    if not requested:
        print("error: --evaluators must name at least one evaluator", file=sys.stderr)
        return 2
    # Canonical order regardless of input order -> deterministic stage letters.
    evaluators = tuple(spec_by_name[n] for n in ("27b", "7b", "cyber") if n in requested)

    cfg = PipelineConfig(
        evaluators=evaluators,
        seed=args.seed,
        temperature=args.temperature,
        top_p=args.top_p,
        max_tokens_eval=args.max_tokens_eval,
        max_tokens_final=args.max_tokens_final,
        run_tests=not args.no_tests,
        postpatch=not args.no_postpatch,
        jar_dir=args.jar_dir or None,
    )

    client = LmStudioClient(base_url=args.lmstudio_url)
    lifecycle = ModelLifecycle(client)
    # The runner evicts intruding models before every call so each generation
    # starts with exactly one model resident.
    runner = LmStudioRunner(client, lifecycle=lifecycle)
    try:
        available = {row["key"] for row in client.list_models()}
    except Exception as e:  # noqa: BLE001
        print(f"error: cannot reach LM Studio at {args.lmstudio_url}: {e}", file=sys.stderr)
        return 2

    wanted_models = [s.model_key for s in cfg.evaluators] + [cfg.adjudicator_model]
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
                    bundle, cfg, runner, lifecycle, out_dir, security_model_text, repo_root
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
