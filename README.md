# my-opencode-tomcat

opencode bucket for the Apache Tomcat security-scan workstream on this machine:
the campaign-lead agent, its batch worker, the skills they run from, custom
tools, and the disclosure-verifier pipeline.

## Layout

| Path | What it is |
|---|---|
| `agents/tomcat-security-scan.md` | Campaign lead — dispatches serial scan-worker batches over Tomcat classes/packages |
| `agents/scan-worker.md` | Batch worker — reviews code line-by-line, writes defects reports + JUnit verification tests |
| `skills/tomcat-security-scan/` | Single source of truth for the scan: fleet pattern, ledger format, report structure, test conventions, CodeQL/astnav recipes, security model |
| `skills/java-ast-nav/` | Tree-sitter-based Java call-graph navigation (`astnav.py`) |
| `skills/disclosure-pipeline-run/` | How to launch/poll/read the disclosure-verifier campaign (protocol, timing, failure modes) |
| `tools/disclosure-pipeline.ts` | opencode custom tools wrapping the pipeline: `disclosure-pipeline_launch/_status/_results` |
| `disclosure-verifier/` | The verification pipeline itself — see its [README](disclosure-verifier/README.md) |

## Install

```bash
./install.sh              # symlink agents/skills/tools into ~/.config/opencode/, merge AGENTS.fragment.md + opencode.fragment.jsonc
./install.sh --uninstall  # remove only symlinks pointing here
```

Idempotent; re-run after adding/removing items. Restart opencode to pick up
new tools/agents (config is loaded once at startup).

## Notes

- This repo is intentionally **private** and carries machine-local values
  (LM Studio model IDs, local paths). See [AGENTS.md](AGENTS.md) for the full
  list before sharing or making it public.
- Campaign state lives outside this repo: Tomcat source checkout at
  `~/src/tomcat`, scan outputs under `/home/opencode/workspace/security-scans/tomcat`.
