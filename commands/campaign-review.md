---
description: Review Tomcat scanner campaign verification results and prepare security-team-ready disclosures
---

You are reviewing a Tomcat scanner verification campaign.

Arguments supplied by the user:

$ARGUMENTS

Interpret the arguments as:

1. Campaign directory: first argument.
2. Tomcat checkout: second argument, or `/home/csutherl/source/tomcat` if omitted.

If either path is ambiguous, ask before proceeding.

Scope and safety rules:

- Only inspect files under the campaign directory and the Tomcat checkout.
- Do not inspect unrelated directories.
- Do not run local model checks or remote/network checks.
- Start with the campaign summary JSON, preferably `all-summary.json` or per-finding `summary.json`.
- Do not edit files until after summarizing what appears to need changing.
- Before editing any report, patch, or disclosure file, create timestamped backups next to the originals.
- Restore the Tomcat checkout after testing.
- Keep final responses concise and list paths clearly.

Primary goals:

1. Review the verification outcomes.
2. Decide which findings are legitimate Tomcat security issues under the supplied Tomcat security model.
3. For legitimate security issues, assign an impact bucket:
   - low
   - moderate
   - high
   - critical
4. Confirm whether those issues are still present in current Tomcat `main` / `12.0.x-dev`.
5. Verify whether proposed patches fix the issue and whether failures are caused by the patch.
6. Update disclosure reports and patch files so they are concise and suitable for submission to the Tomcat Security Team.

Workflow:

1. Read the campaign summary:
   - Start with `all-summary.json` if present.
   - Otherwise inspect each finding's `summary.json`.
   - Note classification, legit-security verdict, CVSS, inconclusive flags, test outcomes, patch outcomes, and edit status.

2. Read the Tomcat security model if present in the campaign:
   - Usually `SECURITY-MODEL.md`.
   - Apply that model when deciding whether each finding is a Tomcat security issue.

3. Summarize all verification outcomes:
   - Which findings are legit security issues.
   - Which are hardening, bugs, or non-findings.
   - Which are inconclusive.
   - Any mechanical caveats, especially bad CVSS math, failed postpatch tests, no-edits status, or patch/test mismatch.

4. For each legit security issue:
   - Identify the disclosure under `disclosures/`.
   - Identify related tests under `test/` or `tests/`.
   - Identify patch content, either embedded in the report or stored as a `.patch` file.
   - Copy required tests into the Tomcat checkout only if needed.
   - Run the reproducer against unpatched Tomcat `main`.
   - Confirm the issue is still present.
   - Apply or check the patch.
   - Re-run the reproducer.
   - Determine whether failures are:
     - fixed by the patch,
     - caused by the patch,
     - pre-existing,
     - unrelated red tests,
     - or test harness/environment problems.
   - Restore Tomcat source files and remove temporary copied tests when done.

5. For each disclosure that needs cleanup:
   - Create a timestamped backup first.
   - Update files under the campaign's `disclosures/` directory.
   - Make paths relative where possible.
   - Remove local-machine-specific paths such as `/home/...`, `/tmp/...`, or workspace-specific locations.
   - Correct version wording:
     - current Tomcat `main` should be described as `main` / `12.0.x-dev`, not `11.0.x`.
     - mention other maintained branches only if evidence supports it.
   - Make the report concise:
     - summary,
     - affected versions,
     - severity,
     - root cause,
     - impact,
     - reproducer,
     - suggested fix,
     - patch file,
     - relevant references.
   - Remove long raw JUnit logs unless necessary.
   - Remove internal progress notes, status comments, and scanner-only narrative.
   - Preserve enough test evidence for the Security Team to understand red/green behavior.

6. Patch handling:
   - If a report contains an embedded diff but no separate patch file, write a corresponding `.patch` under `disclosures/`.
   - Ensure patch paths are repository-relative.
   - Verify each final patch using:
     - `git apply --check <patch-file>`
   - Do not leave patches applied to the Tomcat checkout unless the user explicitly asks.

7. Final response must include:
   - security issues confirmed,
   - impact bucket for each,
   - tests run and whether they were red/green,
   - patch files verified,
   - disclosure/report files changed,
   - backups created,
   - Tomcat checkout restoration status,
   - any caveats or unresolved failures.
