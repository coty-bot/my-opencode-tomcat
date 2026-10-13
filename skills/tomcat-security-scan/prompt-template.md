# Batch worker prompt template

Fill every `{{PLACEHOLDER}}`, delete the guidance comments, and pass the result as the Task tool
prompt (subagent_type: tomcat-scan-worker). One class or a small group per batch. The standing worker
discipline — working style, review method, finding format, test conventions, deliverable structure,
and final-message contract — lives in the `tomcat-scan-worker` agent definition; do NOT restate it here.
Pass only the batch-specific scope below.

---

You are performing a security/defect code review of Apache Tomcat source at /home/opencode/src/tomcat (a git repo, 12.0.x-dev). This is batch {{BATCH_ID}} covering {{PACKAGE_OR_AREA}}. Prior batches {{PRIOR_BATCH_LIST, e.g. "F1, F1a, F2"}} are complete; their reports exist at /home/opencode/workspace/security-scans/tomcat/defects-{{AREA_PREFIX}}*.md — dedupe against them (overlap → note it, skip or add only new detail).

YOUR SCOPE: {{CLASS_PATHS_WITH_LINE_COUNTS, e.g. "java/org/apache/coyote/http2/Foo.java (~1200 lines)"}} — {{ONE_SENTENCE_ROLE_OF_THE_CLASS: what it parses/handles and why it is security-relevant}}. Target line budget for this worker: {{TARGET_LINE_BUDGET, e.g. "~1500 lines"}}; if the scope exceeds it, cover what fits and mark the rest in `## Progress` as not-covered rather than dying. Before starting, confirm the actual files exist with `ls`/line-counts; if the supplied list is stale or names classes that are not in this tree (source moves across pulls), review whatever is actually on disk in scope and note the discrepancy in Scope and method.

MANDATORY FIRST STEPS:
1. Read /home/opencode/src/tomcat/SECURITY.md, then read /home/opencode/.config/opencode/skills/tomcat-security-scan/security-model.md (distilled canonical security model with provenance + hashes). Do NOT webfetch the page per-batch; only webfetch https://tomcat.apache.org/security-model.html if you need a nuance not in that file.
2. Read {{REFERENCE_REPORT, e.g. defects-coyote-http2-F4.md}} fully (structure/style reference), then skim the other reports in /home/opencode/workspace/security-scans/tomcat/ so you do NOT duplicate already-reported findings.

BATCH CONTEXT:
- Line map (if available): {{LINE_MAP — verified per-region map noting which regions are data vs logic, what to spot-check, and which methods are security-critical}}.
- Related classes already reviewed (do not re-review their internals; DO review how this class uses/validates them): {{RELATED_CLASSES_ALREADY_REVIEWED}}.

DELIVERABLES (paths only — format and method per your worker discipline + SKILL.md):
- Report: /home/opencode/workspace/security-scans/tomcat/defects-{{AREA_PREFIX}}-{{BATCH_ID}}.md
- Tests: NEW file(s) under /home/opencode/workspace/security-scans/tomcat/test/org/apache/coyote/{{PKG_PATH}}/TestDefects{{AREA}}{{BATCH_ID}}.java (package declaration must match the directory). Fully-qualified test class for JUnitCore: org.apache.coyote.{{PKG_DOTS}}.TestDefects{{AREA}}{{BATCH_ID}}.
