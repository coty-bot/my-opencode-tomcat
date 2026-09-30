## Tomcat security scan (this box)

- Campaign state: reports/tests live in `/home/opencode/workspace/security-scans/tomcat`; source checkout at `/home/opencode/src/tomcat`. Resume protocol, ledger format, and worker dispatch rules are in `skills/tomcat-security-scan` — read it before resuming or extending the scan.
- Disclosure verifier pipeline: lives in this repo at `disclosure-verifier/` (multi-model LM Studio verification of disclosures/tests/patches; launch/poll protocol in `skills/disclosure-pipeline-run`).
- Permissions: this repo's `opencode.fragment.jsonc` (merged by `install.sh`) grants `external_directory` allow for `~/src/**` only — enough to clone/edit repos under `~/src`, nothing else on the FS.
