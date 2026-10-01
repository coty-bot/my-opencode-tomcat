---
name: disclosure-pipeline-run
description: Use when kicking off, resuming, or checking the Tomcat disclosure-verifier campaign — multi-model LM Studio verification of security disclosures/tests/patches at /home/opencode/src/my-opencode-tomcat/disclosure-verifier (three independent evaluators + adjudicator, deterministic mechanical checks, edit tracking). Covers launch via run_pipeline.sh or the custom tools (disclosure-pipeline_launch/_status/_results), out-dir conventions, polling protocol, measured timing, model roles, and known failure modes.
---

# Disclosure Pipeline Run

Verifies each Tomcat security disclosure against the project trust model using
LM Studio models plus deterministic mechanical checks, then adjudicates a final
ruling (security_issue / hardening / bug), CVSS score, and accuracy edits to
the disclosure/tests/patches.

## Custom tools (preferred interface)

The repo ships `tools/disclosure-pipeline.ts` (symlinked into the opencode
config by `install.sh`), exposing three tools that wrap this protocol:

- `disclosure-pipeline_launch(slugs?, out_dir?)` — runs `run_pipeline.sh`
  detached and returns pid/log/status-file. Unloads all LM Studio models first,
  including the agent's own (auto-reloads on demand in later turns).
- `disclosure-pipeline_status(tail_lines?)` — pid liveness, elapsed time,
  detected out-dir, per-slug stage progress, log tail. Read-only; safe to poll.
- `disclosure-pipeline_results(slug?, out_dir?)` — all-summary.json rows for a
  run (classification / legit_security_finding / CVSS / edits_status), plus the
  full report.md when slug is given. Defaults to the latest launch's out-dir.

Use these instead of hand-running bash; fall back to the raw commands below if
the tools are missing (e.g. config not reinstalled) or for flags they don't
expose (`--wait`, per-evaluator overrides, `--no-tests`, …).

## What one disclosure run does

1. **Mechanical checks** (no model): parse the disclosure bundle; compute CVSS
   3.1 vectors/scores from claimed text; `git apply --check` the patch at repo
   HEAD; compile + run cited JUnit tests pre-patch and post-patch in a scratch
   copy of `/home/opencode/src/tomcat`.
2. **Stage A** — evaluator: `qwen/qwen3.8-27b` (ctx 65536).
3. **Stage B** — evaluator: `vulnllm-r-7b` (ctx 32768).
4. **Stage C** — evaluator: `ravenx-cyberagent-qwen3.6-35b-a3b-opus-4.7-openmythos-pentester-bughunter-rath` (ctx 98304) — the adversarial "vulnerability hunting" model; it argues hardest that findings ARE security issues.
5. **Stage D** — adjudicator: `qwen/qwen3.8-27b` (ctx 65536, max_tokens 16384). Sees all three verdicts + mechanical facts, rules per the trust model (`SECURITY-MODEL.md`), picks the final CVSS vector/score (mechanical computed scores are authoritative over disclosure claims), and proposes edits.
6. **Edit application**: proposed edits to disclosure/tests/patches are applied, re-verified (patch still applies; tests compile + expected pass/fail), then either kept (`applied-verified`) or fully reverted byte-for-byte (`rejected-reverted`). Every edited file gets a `.orig` backup.

Every stage starts from a clean slate: the runner unloads ALL loaded models
(including the agent's own) before loading exactly one stage model, and the
pipeline ends by unloading everything again. Generation params are fixed for
determinism: temp=0.0, top_p=1.0, seed=1337 (override via CLI flags).

## Launch protocol

```bash
# full campaign (all disclosures/*.md), fresh out-dir recommended:
bash /home/opencode/src/my-opencode-tomcat/disclosure-verifier/run_pipeline.sh \
  --out-dir /home/opencode/workspace/security-scans/tomcat/verification-run<N>-$(date +%Y%m%d-%H%M%S)

# subset of slugs (positional args, with or without .md):
bash /home/opencode/src/my-opencode-tomcat/disclosure-verifier/run_pipeline.sh <slug> [slug ...]
```

- The wrapper unloads every loaded model first (clean t=0), starts the verifier
  detached in its own session, and writes `output/pipeline-status.json`
  (`pid`, `log`) plus a timestamped log under `/home/opencode/src/my-opencode-tomcat/disclosure-verifier/output/`.
- **Use a fresh `--out-dir` per campaign** to preserve prior results. Within an
  out-dir, re-runs overwrite per-slug dirs and merge into `all-summary.json`
  keyed by slug (partial re-runs update only their rows). Default out-dir is
  `<campaign>/verification`.
- `--wait` blocks until done — for use outside an agent session.

Campaign layout: `/home/opencode/workspace/security-scans/tomcat/` holds
`disclosures/*.md`, saved `.patch` files (top level, compared against embedded
patches), cited tests under `test/...` mirroring the repo layout, and
`SECURITY-MODEL.md` (the trust model; override with `--security-model`).

## Polling protocol (measured safe)

- Completion = pid from `pipeline-status.json` is gone AND `all-summary.json`
  exists in the out-dir. Per-slug progress: each slug dir appears with
  `mechanical.json` first, then `stage-a…d.{json,raw.txt}`, then `report.md`.
- **Polling does not break the run.** The agent model auto-reloads on demand;
  stage loads retry up to 3x with backoff (`stage-entry-retry` events in
  `lifecycle.json`). A full campaign was polled every ~25 min from an active
  agent session and finished with zero lifecycle retries. Keep polling turns
  sparse (one short read-only check per turn) so the agent model is resident
  only briefly between stage boundaries.
- Do not treat a quiet run as hung before ~10 min for one slug.

## Timing (measured, this machine: RTX 5090 32 GB)

~8–9 min per disclosure with all four model stages + JUnit compile/runs; a full
15-disclosure campaign took **~2 h 10 m**. The 35B-A3B MoE stage-C model is fast
per token (3B active); the 27b Q5_K_P MTP build is also quick.

## Reading results

- `all-summary.json` — one row per slug: `classification`,
  `legit_security_finding`, final CVSS score, `edits_status`.
- Per-slug `report.md` — human-readable: models table (exact model keys +
  generation params), mechanical check results, each evaluator's verdict, the
  adjudicator's ruling with per-evaluator rebuttals (`model_agreement` /
  `disagreements` in `stage-d.json`), and the edit log.
- `lifecycle.json` — load/unload audit; look for `stage-entry-retry`,
  `context-mismatch`; `final_unloaded` should list the last stage model.

## Determinism caveats (observed)

- Params are fixed, but runs are **not bit-identical**: at temp=0 a verdict can
  still flip between runs (observed: evaluator A flipped on one slug; two
  adjudications changed class when the third evaluator was added). Treat single
  runs as high-confidence, not absolute.
- The adjudicator is final authority and routinely overrules evaluators using
  trust-model exception clauses (AJP standard request attributes,
  RemoteIpValve/Filter-processed headers are trusted; WebDAV modification
  security is the web application's responsibility — `WebdavServlet` is a core
  servlet class, NOT a "shipped web application").
- Mechanical facts override disclosure claims: computed CVSS scores beat claimed
  ones (e.g. an all-N vector computes to 3.9, not the often-claimed 0.0), and
  post-patch JUnit results can refute "patch verified" statements.

## Known failure modes

- **Stage C empty completions**: the pentester model is a heavy reasoner and
  frequently exhausts `max_tokens_eval` (8192) on internal reasoning, returning
  no text. The runner retries 3x; if all fail, C is excluded from agreement
  (not counted as "no") — adjudication proceeds with A+B. Raise
  `--max-tokens-eval` (e.g. 16384) for a run where you want reliable C verdicts.
- **Stage load failure**: transient VRAM/server hiccups retry 3x; persistent
  failure marks that disclosure as an error row and the campaign continues.
- **Edits rejected-reverted**: proposed edits that fail re-verification (e.g. a
  test edit that doesn't pass) are reverted byte-for-byte; originals are safe.

## Changing models / params

All machine-local values live in `config.toml` at the tool root (`/home/opencode/src/my-opencode-tomcat/disclosure-verifier/config.toml`): paths, LM Studio URL, per-evaluator model keys/context lengths/input budgets (stage order follows the `[[evaluators]]` list), adjudicator, and generation params. Edit it for permanent changes; CLI flags override individual values for a single run:

- `--config <path>` — alternate config file
- Per evaluator (name = `name` field in config.toml): `--model-<name>`, `--ctx-<name>`, `--input-budget-<name>-chars`; `--evaluators 27b,cyber` runs a subset (stage letters follow config order)
- Paths/URL: `--repo-root`, `--disclosures-dir`, `--out-dir`, `--security-model`, `--jar-dir` (empty string disables test execution), `--lmstudio-url`
- Generation/pipeline: `--seed`, `--temperature`, `--top-p`, `--max-tokens-eval`, `--max-tokens-final`, `--no-tests`, `--no-postpatch`

Model keys must be known to LM Studio at the configured URL (checked up front; missing models abort with the available list).
