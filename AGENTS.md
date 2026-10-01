# my-opencode-tomcat

Apache Tomcat security-scan bucket for this machine's opencode setup: the
campaign-lead agent, its batch worker, the skills they run from, and the
disclosure-verifier pipeline.

## Layout

- `agents/tomcat-security-scan.md` — campaign lead (dispatches serial scan-worker batches)
- `agents/scan-worker.md` — batch worker that writes defects reports + JUnit verification tests
- `skills/tomcat-security-scan/` — single source of truth: fleet pattern, ledger format, report structure, test conventions, CodeQL/astnav recipes, security-model.md
- `skills/java-ast-nav/` — tree-sitter-based Java call-graph navigation (astnav.py)
- `skills/disclosure-pipeline-run/` — multi-model disclosure verification campaign launcher
- `tools/disclosure-pipeline.ts` — opencode custom tools (`disclosure-pipeline_launch/_status/_results`) wrapping the pipeline for agent use
- `disclosure-verifier/` — the pipeline itself: LM Studio multi-model evaluators + adjudicator, mechanical checks, edit tracking (`run_pipeline.sh`)

## Install

Run `./install.sh` to symlink agents/skills/tools into `~/.config/opencode/` and
merge this repo's `AGENTS.fragment.md` into the global AGENTS.md. Idempotent;
re-run after adding/removing items. `./install.sh --uninstall` reverses it
(removes only symlinks pointing here).

## Machine-local values (keep this repo private)

This repo is intentionally PRIVATE and carries real local values:

- `agents/scan-worker.md`, `agents/tomcat-security-scan.md` — frontmatter `model:` lines (LM Studio model IDs)
- Paths to the local checkout at `/home/opencode/src/tomcat` and scan outputs under `/home/opencode/workspace/security-scans/tomcat`

Do not make this repo public or push it to a shared remote without stripping
those values first.
