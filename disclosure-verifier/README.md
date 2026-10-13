# disclosure-verifier

Multi-model verification of Tomcat security disclosures. Each disclosure
bundle (prose + patch + JUnit tests) is checked by deterministic mechanical
checks plus three independent LM Studio evaluator models, then adjudicated
into a final ruling — `security_issue` / `hardening` / `bug`, CVSS 3.1
score/vector, and accuracy edits to the disclosure/tests/patch.

Full run protocol (launch/poll conventions, timing, failure modes):
[../skills/disclosure-pipeline-run/SKILL.md](../skills/disclosure-pipeline-run/SKILL.md).

## How a run works

Per disclosure slug:

1. **Mechanical checks** (no model) — parse the bundle; compute CVSS 3.1 from
   claimed text; `git apply --check` the patch at repo HEAD; compile + run the
   cited JUnit tests pre- and post-patch in a scratch copy of the Tomcat checkout.
2. **Stages A–C** — three independent evaluators (config order: 27b primary,
   7b second opinion, cyber adversarial "this IS a vulnerability" model). Each
   stage starts from a clean slate: all models unloaded, exactly one stage model loaded.
3. **Stage D** — adjudicator sees all verdicts + mechanical facts and rules per
   the trust model (`SECURITY-MODEL.md`); picks the final CVSS (mechanical
   scores are authoritative over claims) and proposes edits.
4. **Edit application** — proposed edits are applied, re-verified (patch still
   applies; tests compile + expected pass/fail), then kept (`applied-verified`)
   or reverted byte-for-byte (`rejected-reverted`). Edited files get `.orig` backups.

Generation params are fixed for determinism (temp=0, top_p=1, seed=1337) but
runs are not bit-identical — treat single runs as high-confidence, not absolute.

## Expected input

Campaign dir (configured in local `config.toml`; start by copying
[`config.example.toml`](config.example.toml)):

- `disclosures/<slug>.md` — one markdown file per disclosure: title, commit
  hash, CVSS vector/score claim, CWE, a ```diff block or reference to a saved
  `.patch` file (top level of the campaign dir), and references to JUnit tests
  (`test/...Test*.java` paths mirroring the repo layout, or bare `TestX.java` names).
- `SECURITY-MODEL.md` — the project trust model the adjudicator rules by.
- Tomcat source checkout at `repo_root` (default `/home/opencode/src/tomcat`)
  and JARs in `jar_dir` for the scratch-copy test runs (empty disables tests).

## Configuration & launch

All machine-local values live in `config.toml` — paths, LM Studio URL,
per-evaluator model keys/context lengths/input budgets, adjudicator, generation
params. `config.toml` is intentionally gitignored; create it from the example:

```bash
cp config.example.toml config.toml
```

CLI flags override individual values for a single run (`python3 -m disclosure_verifier --help` for the full list).

```bash
# preferred from an agent session: the disclosure-pipeline_launch/_status/_results custom tools

# raw launch (detached; writes output/pipeline-status.json + timestamped log):
bash run_pipeline.sh --out-dir <campaign>/verification-run<N>-$(date +%Y%m%d-%H%M%S) [slug ...]

# direct, blocking invocation:
python3 -m disclosure_verifier [--config config.toml] [flags...] [slugs ...]
```

Use a fresh `--out-dir` per campaign to preserve prior results; re-runs within
an out-dir merge into `all-summary.json` keyed by slug. `run_pipeline.sh --wait`
blocks until done (for use outside an agent session).

## Output

Per run, in the out-dir:

- `all-summary.json` — one row per slug: classification, legit_security_finding,
  final CVSS score/vector, edits_status
- `<slug>/report.md` — human-readable full report (models + params table,
  mechanical results, each evaluator's verdict, adjudication with rebuttals, edit log)
- `<slug>/{mechanical.json, stage-a…d.{json,raw.txt}}`, `lifecycle.json`
  (model load/unload audit), `.orig` backups of edited files

Run logs and `pipeline-status.json` land in `output/` (gitignored).

## Timing

~8–9 min per disclosure on this machine (RTX 5090); a full 15-disclosure
campaign takes ~2 h 10 m.
