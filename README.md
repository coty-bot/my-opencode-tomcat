# my-opencode-tomcat

opencode bucket for the Apache Tomcat security-scan workstream on this machine:
the campaign-lead agent, its batch worker, the skills they run from, custom
tools, and the disclosure-verifier pipeline.

## Layout

| Path | What it is |
|---|---|
| `agents/tomcat-security-scan.md` | Campaign lead — dispatches serial tomcat-scan-worker batches over Tomcat classes/packages |
| `agents/tomcat-scan-worker.md` | Batch worker — reviews code line-by-line, writes defects reports + JUnit verification tests |
| `skills/tomcat-security-scan/` | Single source of truth for the scan: fleet pattern, ledger format, report structure, test conventions, CodeQL/astnav recipes, security model |
| `skills/java-ast-nav/` | Tree-sitter-based Java call-graph navigation (`astnav.py`) |
| `skills/disclosure-pipeline-run/` | How to launch/poll/read the disclosure-verifier campaign (protocol, timing, failure modes) |
| `tools/disclosure-pipeline.ts` | opencode custom tools wrapping the pipeline: `disclosure-pipeline_launch/_status/_results` |
| `commands/campaign-review.md` | opencode slash command `/campaign-review` for reviewing verification outcomes and preparing concise Tomcat security disclosures |
| `disclosure-verifier/` | The verification pipeline itself — see its [README](disclosure-verifier/README.md) |
| `LOCAL_SETUP_NOTES.md` | Portable notes distilled from the original local setup |

## Install

```bash
cp disclosure-verifier/config.example.toml disclosure-verifier/config.toml  # edit local paths/models if using the verifier
./install.sh              # symlink agents/skills/tools into ~/.config/opencode/, merge AGENTS.fragment.md + opencode.fragment.jsonc
./install.sh --uninstall  # remove only symlinks pointing here
```

Idempotent; re-run after adding/removing items. Restart opencode to pick up
new tools/agents/commands (config is loaded once at startup). If upgrading from
an older checkout that installed `agents/scan-worker.md`, run
`./install.sh --uninstall && ./install.sh` once so the old symlink is removed
and the renamed `tomcat-scan-worker` subagent is installed.

## Commands

### `/campaign-review`

Reviews a completed Tomcat scanner verification campaign, identifies the findings
that are legitimate Tomcat security issues, verifies their red/green tests and
patches against a Tomcat checkout, and cleans disclosure reports for security-team
submission.

After `./install.sh` and restarting opencode, run:

```text
/campaign-review /path/to/campaign [/path/to/tomcat]
```

Example:

```text
/campaign-review /home/opencode/source/local-scanner-findings/1-oct-tomcat /home/opencode/source/tomcat
```

If the Tomcat checkout argument is omitted, the command instructs the agent to use
`/home/opencode/source/tomcat`.

The command tells the agent to:

- start from `all-summary.json` or per-finding `summary.json`;
- apply the campaign's Tomcat security model;
- assign low/moderate/high/critical impact to legitimate security findings;
- run reproducer tests on unpatched and patched Tomcat when needed;
- create timestamped backups before editing disclosures;
- make report paths relative and remove local-machine-specific paths;
- rewrite disclosures to be concise and security-team-ready;
- verify final patch files with `git apply --check`;
- restore the Tomcat checkout before finishing.

## Notes

- This repo is intentionally **private** and still carries machine-local values
  in agent prompts/skills (LM Studio model IDs, local paths). The disclosure
  verifier config is now local-only: copy `disclosure-verifier/config.example.toml`
  to `disclosure-verifier/config.toml` and edit it for your machine.
- Campaign state lives outside this repo: Tomcat source checkout at
  `~/src/tomcat`, scan outputs under `/home/opencode/workspace/security-scans/tomcat`.
