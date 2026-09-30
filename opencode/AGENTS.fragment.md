## Tomcat security scan (this box)

- Campaign state: reports/tests live in `/home/opencode/workspace/security-scans/tomcat`; source checkout at `/home/opencode/src/tomcat`. Resume protocol, ledger format, and worker dispatch rules are in `skills/tomcat-security-scan` — read it before resuming or extending the scan.
- Permissions: this repo's `opencode.fragment.jsonc` (merged by `install.sh`) grants `external_directory` allow for `~/src/**` only — enough to clone/edit repos under `~/src`, nothing else on the FS.
