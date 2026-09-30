---
name: tomcat-security-scan
description: Use when performing a Tomcat security/defect code review of the Apache Tomcat source at /home/opencode/src/tomcat — dispatching fleet-style batch reviewers over classes or packages (coyote http11/http2 series), writing defects-*.md reports with JUnit verification tests, deduping against prior batches, resuming/extending the ongoing scan campaign, or curating submission-ready disclosure bundles (end-to-end PoC + currently-failing test + suggested patch).
---

# Tomcat Security Scan

Fleet-based security/defect review of Apache Tomcat source at `/home/opencode/src/tomcat` (git repo, 12.0.x-dev). One subagent worker per batch; each batch covers one class or a small group of classes line by line and produces a report plus JUnit verification tests.

The campaign runs as two agents (defined in `~/.config/opencode/agent/`): a primary `tomcat-security-scan` orchestrator that dispatches serial `scan-worker` subagents using `prompt-template.md`. The standing worker discipline (working style, review method, test conventions) lives in the `scan-worker` agent definition so workers start with it loaded; this file remains the canonical reference for depth.

## Environment facts (verified)

- Repo: `/home/opencode/src/tomcat`. No Maven. Java 25 (`javac`/`java` on PATH). If it doesn't exist, clone it first: `git clone https://github.com/apache/tomcat /home/opencode/src/tomcat` (default branch is the current dev line; the campaign tracks `origin/main`).
- Compiled classes live in `output/classes`, test classes in `output/testclasses` (ant build outputs, untracked/gitignored).
- Dependency jars: `/home/opencode/tomcat-build-libs/` (junit-4.13.2, hamcrest, easymock, bouncycastle, ...).
- Classpath recipe:

  ```bash
  CP="output/classes:output/testclasses:$(find /home/opencode/tomcat-build-libs -name '*.jar' | tr '\n' ':')"
  javac -cp "$CP" -d <out-dir> <TestFile.java>
  java -cp "<out-dir>:$CP" org.junit.runner.JUnitCore <fully.qualified.TestClass>
  ```

- Before compiling, check `output/classes` is fresh: compare timestamps of a few `.class` vs `.java` files; if stale, recompile the needed sources into `output/classes` with the same CP.
- Tests compile and run fine from OUTSIDE the repo tree (precedent: F1b ran from `/tmp/opencode/coyote-F1b`).

## Git state & hygiene (pull before, clean after)

The repo tracks `origin/main` (github.com/apache/tomcat). Keep it in a known, clean state so line refs are reproducible and no scan leaves source modified.

- **Before scanning:** ensure the tree is clean (`git status --porcelain` empty), then `git pull --ff-only`. Record the scanned commit with `git rev-parse HEAD` and put that hash in each report's "Scope and method" so findings' `file:line` refs are reproducible. Re-pull at session start and before resuming after a long gap; if a pull moves code, re-check any just-completed batch whose target files changed (line refs may shift).
- **After every batch:** verify the tree is clean again — `git status --porcelain` must show no modified tracked source. Workers can leave stray edits or stale recompiles; revert anything under tracked paths with `git checkout -- <paths>` (or `git restore`). Build output in `output/` is gitignored, so recompiling `.class` files there never dirties the tree — only changes to tracked files (`java/`, `test/`, docs) matter.
- **Fix-validation edits are temporary:** when a worker applies a proposed fix to validate it (see Test conventions), it MUST `git checkout -- <files>` those sources back before finishing so the repo is left clean.

## Code navigation (`astnav`) — prefer over grep for cross-file tracing

For following code paths (callers, field writers, references, symbol definitions, structural searches), use the `java-ast-nav` skill's helper instead of many greps. It is syntax-aware (ignores comments/strings, distinguishes decl vs call vs ref) and returns pipeable `file:line` results that keep large search output out of a worker's context (pipe through `head`).

```bash
A=/home/opencode/.config/opencode/skills/java-ast-nav/astnav.py   # run from /home/opencode/src/tomcat
python3 $A calls <method>  --root java          # all call sites, with receiver context
python3 $A writes <field>  --root java          # every assignment to a field (dead-flag checks)
python3 $A refs   <ident>  --root java/<pkg>    # references (excludes the declaration site)
python3 $A defs   <name>   --root java/<pkg>    # declarations named NAME
python3 $A symbols <File.java>                  # class/method/field outline w/ line numbers
python3 $A query '(synchronized_statement) @sync' --root java/<pkg>   # raw tree-sitter structural query
```

It is **syntactic, not semantic** (no overload/type resolution; name-based commands can match a same-named local in another class — confirm by reading the reported file:line). See the `java-ast-nav` skill for full docs and recipes. Use it to verify reachability and prove dead guards cheaply.

## Reflection-aware taint / dataflow (CodeQL)

Standard CodeQL taint tracking stops at reflective boundaries (`Method.invoke`, `Constructor.newInstance`) because there is no static call edge. To trace attacker input *through* reflection into a named target, add the missing edges yourself via an additional flow step. Reusable layer + working examples live in `qll/` next to this file:

- `qll/ReflectionCallGraph.qll` — `ReflectiveMethodInvoke` (a `java.lang.reflect.Method.invoke(...)` call) with `getATargetMethod()` (resolves the target via `semmle.code.java.Reflection::inferAccessedMethod`) and `argFlowsToParam(target, argExpr, param)` mapping invoke args → target params; also `ReflectiveNewInstance` for constructor reflection.
- `qll/ReflTaint.ql` — end-to-end example (verified result in REFERENCE.md).
- `qll/Sweep.ql` — whole-codebase sweep across 3 reflective channels (result + conclusion in REFERENCE.md).

Run (2026-09-15: the codeql repo at `/home/opencode/tools/ql` moved to a new layout — java stdlib now at `java/ql/lib`, pack renamed `codeql/java-all`; the old `--search-path="$SP:<dir>"` recipe no longer resolves `import java` for loose queries, and a standalone mini-workspace also fails: data-extension globbing does not follow symlinks and extensible predicates are invisible across packs — "extensible predicate ... does not exist in pack"). Working approach: place the query + its `.qll` deps inside the codeql repo's own workspace (the provided `codeql/java-queries` pack), run with NO search path, then delete the dir to keep the tools checkout clean):

```bash
export PATH="/home/opencode/tools/codeql:$PATH"
SRC=/home/opencode/.config/opencode/skills/tomcat-security-scan/qll
DST=/home/opencode/tools/ql/java/ql/src/tomcatscan
mkdir -p $DST && cp $SRC/<query.ql> $SRC/ReflectionCallGraph.qll $DST/   # + any other .qll deps
codeql query run $DST/<query.ql> --database=/home/opencode/tools/codeql-dbs/tomcat-db -o out.bqrs
codeql bqrs decode out.bqrs --format=csv
rm -rf $DST
```

Keep only ONE taint query per directory (each defines top-level `module Config`/`module Flow`; duplicates break pack resolution).

**This CodeQL build uses a NEWER signature-based taint API, not the classic one** — the standard "class extends TaintTracking::Configuration" idiom does NOT compile here. Before writing or editing any `.ql`, read REFERENCE.md for the full gotcha list (ConfigSig modules, `Parameter` is a `Variable`, no chained comparisons, reserved `from`, ...) and the resolution limits / extension strategy.

### Per-batch recon: `qll/InputTaint.ql` (client-HTTP-input → dangerous-sink)

General recall tool for the fleet pattern. Seeds sources at client HTTP input accessors and reports every dangerous sink whose receiver or an argument is client-tainted, scoped to one package via its `inScope` path prefix (edit that string per batch; `"%"` = whole codebase). Sink categories: **deserialization** (`ObjectInputStream.readObject`, `XMLDecoder.readObject`), **reflection** (`Method.invoke`, `Class.forName`, `Proxy.newProxyInstance`), **sql-exec** (`java.sql.*.execute*/addBatch`), **process/exec** (`Runtime.exec`, `ProcessBuilder.start`).

**Workflow (main agent, pre-dispatch):** before dispatching a batch worker, run `InputTaint.ql` scoped to the batch's package and hand the worker a compact digest of any hits ("client input reaches these N sites — verify them by hand"). This is a RECALL cross-check for input-handling classes (servlets, webresources, ssi, websocket, ajp); it adds little for pure logic/concurrency packages (e.g. `catalina.session` returns empty — those bugs are state-machine/concurrency, which only manual review catches). Always pair with a cheap grep method-map so the worker can navigate without re-reading everything.

**Run-dir isolation gotcha (cost a run):** each taint query defines its own top-level `module Config` and `module Flow`. If two such `.ql` files share one directory, CodeQL sees duplicate module names and pack resolution fails. Keep exactly one taint query in the run dir.

```bash
export PATH="/home/opencode/tools/codeql:$PATH"
DST=/home/opencode/tools/ql/java/ql/src/tomcatscan; mkdir -p $DST
cp /home/opencode/.config/opencode/skills/tomcat-security-scan/qll/{ReflectionCallGraph.qll,InputTaint.ql} $DST/
# edit $DST/InputTaint.ql inScope prefix to the batch package first
codeql query run $DST/InputTaint.ql --database=/home/opencode/tools/codeql-dbs/tomcat-db \
  -o /tmp/opencode/inputtaint.bqrs
codeql bqrs decode /tmp/opencode/inputtaint.bqrs --format=csv   # category,file,line,sink
rm -rf $DST
```

**DB freshness:** the DB at `/home/opencode/tools/codeql-dbs/tomcat-db` lags HEAD; before trusting an EMPTY result for a package, confirm via `git diff --stat <db-commit>..HEAD -- java/org/apache/<pkg>` that the package's sources are unchanged since the DB was built (a non-empty hit list is still useful as recall even if lines shifted).

## Where artifacts go

Reports and tests land in **`/home/opencode/workspace/security-scans/tomcat/`**, NOT the repo — findings were moved out of the repo so git operations can't delete them. Keep this layout:

- Reports: `security-scans/tomcat/defects-<area>-<batch>.md` (e.g. `defects-coyote-http2-F7.md`)
- Tests: `security-scans/tomcat/test/org/apache/coyote/http2/TestDefectsHttp2F7.java` (package declaration matches the directory; compile with `-d` into a scratch dir)
- Disclosures (submission-ready security reports, one per curated finding): `security-scans/tomcat/disclosures/NN-slug.md` (e.g. `01-xff-access-control-bypass.md`). See "Disclosure bundle".

Existing reports to dedupe against are already there. The repo's `TODO.md` is a separate generated TODO list, not part of this campaign — don't conflate them.

## Security model (filter every finding through it)

Workers read `SECURITY.md`, then **read `security-model.md`** (next to this skill) — a distilled copy of the canonical page with provenance + hashes. Do NOT webfetch the security model per-batch: it costs context and is part of why workers die; only webfetch if you need a nuance not in that file. The main agent re-verifies `security-model.md`'s freshness once per campaign/resume (see its "Freshness check" section), not per worker. Quick triage summary:

- **Untrusted input** = HTTP/AJP connector data from clients (malformed requests, crafted frames). That is the only attack surface that can yield a security finding. Trusted exceptions: AJP request attributes permitted by `allowedRequestAttributesPattern`, and headers processed by RemoteIp/SSL valves/filters.
- **Trusted / not bugs**: config files, admin users (incl. Manager/Host Manager), JMX, Java Attach/debugging, temp/work dirs, persisted session store, Tomcat binaries/scripts/logs, deployed web apps (app bugs are the app's problem).
- **Known non-findings** (full list in `security-model.md`): clustering deserialisation without EncryptInterceptor; attacker-controlled cluster node; persisted-session modification not reachable by a non-admin; write access to an app's docBase; attacker-controlled SSI directives. Also not findings: generic DoS without non-linear resource consumption, large-but-valid data within configurable limits, TLS internals (JSSE), deliberate RFC deviations kept for compatibility/robustness.
- A finding needs REACHABILITY: a real client or container usage must actually trigger it — check state-machine preconditions, locking, and configuration gates. Unreachable candidates go under "Verified non-issues" with the reason.

## Finding categories and format

Three live categories plus two bookkeeping sections. Every confirmed finding needs: unique ID (`<BATCH>-<n>`), title, exact `file:line` references, explanation (with code excerpt), reachability evidence + concrete impact, proposed fix. Do not report unverified speculation — verify or drop it.

- **Security findings** — client-exploitable: auth/authz bypass, injection, DoS, info leak, protocol desync. Every security finding MUST include an "Estimated security impact" paragraph (what the attacker gains, which mitigations bound it) and a CVSS 3.1 vector string + base score with brief rationale for non-obvious axis choices.
- **Bugs** — functional correctness, incl. RFC violations that misbehave against conforming clients or break Tomcat invariants.
- **Documentation issues (no functional impact)** — stale/misleading javadoc is reportable here.

Report structure (EXACTLY this; match the depth/style of `defects-coyote-http2-F4.md`):

```markdown
# org.apache.coyote.http2 review — batch <ID> (<classes>)
## Scope and method
## Security findings
## Bugs
## Documentation issues (no functional impact)
## Verified non-issues
## Verification artifacts
```

"Verified non-issues" records what was checked and cleared (with evidence, e.g. "Huffman table compared programmatically against RFC 7541 Appendix B — exact match"). "Verification artifacts" records test paths, compile/run commands, and the actual JUnit output verbatim. Empty categories say "None found." Record the scanned commit (`git rev-parse HEAD`) in Scope and method so `file:line` refs are reproducible against a specific source state.

## Test conventions

- JUnit 4 only; one new file per batch (`TestDefects<Area><Batch>.java`). Do not modify existing tests. You MAY temporarily edit `java/` sources ONLY to apply + validate a proposed fix, and MUST `git checkout -- <files>` them back before finishing so the repo is left clean (see Git state & hygiene).
- For client/embedded-container-level defects, model the harness on `test/org/apache/coyote/http2/Http2TestBase.java`, `TestFlowControl.java`, `TestHttp2Section_3_5.java`: embedded Tomcat via `org.apache.catalina.startup.Tomcat` with an Http11NioProtocol configured for h2c (`upgradeProtocol=org.apache.coyote.http2.Http2Protocol`) or direct H2.
- **Native-boundary classes (JNI / Panama FFI wrappers, e.g. `openssl/`, `openssl/panama/`):** the Java side wraps native calls you cannot unit-test directly. Two proven strategies — pick per finding and say which in the report: (a) **pure-Java stubs** of the native layer (fake the JNI/FFI return values / memory segments) so the test runs without loading the native lib — good for buffer-offset, bounds, and state-machine logic; or (b) **live integration** if the native lib loads in this environment (e.g. a real TLS 1.2 handshake against an embedded server) — stronger but heavier. Focus assertions on the Java-side logic around the calls (bounds, null handling, `arrayOffset`, state invariants), not the native code itself.
- **Default: a failing test that passes after the fix.** For each functional/security defect with a concrete proposed fix, write a test asserting the CORRECT/expected behavior so it FAILS on unmodified source. Then validate the loop end-to-end: (1) run on current code → must FAIL (proves the bug is real/reproducible); (2) apply your proposed fix to `java/` sources + recompile; (3) rerun → must PASS (proves the fix works); (4) `git checkout -- <files>` to revert the source so the repo stays clean. Record BOTH runs verbatim in Verification artifacts — the failing run on unmodified code and the passing run with the fix applied.
- Where a full fail→fix→pass loop is impractical (the correct behavior can't be asserted in isolation, or the fix spans many files), fall back to a test that documents actual current behavior + a note explaining why; say so in the report.
- **Red flag — a "failing" test that PASSES on unmodified source:** if your test asserts correct/expected behavior but does NOT actually fail before the fix, the harness does not reach the buggy path (wrong preconditions, missing state, or the bug is narrower than assumed). Do not accept it as proof. Either fix the harness so it genuinely fails first, or downgrade the finding to "code-trace only — not reproduced by a test" and say exactly why in the report (e.g. "harness cannot force BUFFER_UNDERFLOW without a real TLS peer"). Findings retained on code-trace alone are lower-confidence; label them as such so they are never mistaken for demonstrated defects. (Observed 2026-09: a SecureNioChannel batch kept 4 findings whose tests all passed on current source — the harness never forced the triggering state.)
- Disclosure bundles (`disclosures/NN-slug.md`) additionally REQUIRE an end-to-end failing test + a `git apply --check`-clean patch; see "Disclosure bundle" below.
- If a test won't compile/run after 2 attempts, note it in the report and move on — don't loop.

## Worker working style (learned from failed runs)

Workers die by exceeding the local model's context window. Subagents run on a **local LM Studio Qwen 27B** with a TIGHT effective context — well under the ~125k of frontier models, and concurrent dispatch overloads it further (see Fleet pattern). Two triggers: **(a)** one batch reads too much source, or **(b)** the fixed upfront cost (SECURITY.md + security-model.md + reference report) plus a large target file leaves no room for analysis/tests. Standing worker discipline now lives in the `scan-worker` agent definition (loaded up front), which lowers this fixed cost versus the old AGENTS.md + webfetch approach. Observed deaths: http2 F7 (~2225-line class → no report), catalina-connector-F1 (died after 1 chunk of a 2-class scope, left "(under construction)" placeholders), catalina-servlets-B (3344-line class → skeleton only; recovered by a finisher with hard caps). The prompt must enforce:

- **Cap batch size by LINES, not "one class":** ≤ ~1500 lines of target source per worker. Split any larger class into multiple sequential batches (e.g. a 3300-line servlet → B1/B2/B3 by line range). A single 2000+ line class WILL die.
- Every response contains at least one tool call except the final message; assistant text < 30 words per message.
- Create the report skeleton FIRST with all six section headers AND a `## Progress` log, then append analysis IMMEDIATELY after each read chunk (never accumulate in chat). The `## Progress` log records lines-read-so-far + candidate findings so a finisher can resume cheaply after a death.
- Read in chunks of ~120 lines max (`offset`/`limit`); pipe greps through `head -15`; never re-read a file you already read.
- For large data tables (e.g. HPackHuffman's 257-entry table): spot-check a few entries, don't read line by line; verify programmatically instead.
- **STATUS marker:** the report ends with `<!-- STATUS: IN-PROGRESS -->` until done, then flip to `<!-- STATUS: COMPLETE -->`. A missing COMPLETE marker (or an empty final message) = the worker died — that is how you detect it.
- **Structured-incomplete final message:** if context runs out before tests are written, STOP and return "STATUS: INCOMPLETE — read L1–L2 of N lines; findings so far: ...; next: ..." rather than dying silently with an empty result.

## Fleet pattern

1. Pick batch scope: **≤ ~1500 lines of target source** per worker — one class, a line-range slice of a large class (split 2000+ line classes into sequential batches), or 2–3 small classes. Give approximate line counts. Batch IDs are sequential within an area (`A`, `B`, ... or `F1`, `F2`, ...).
2. Dispatch ONE worker at a time — serially. Wait for each worker's final message before dispatching the next; do NOT issue multiple Task calls concurrently. Concurrent workers overload the local model and cause "Context size has been exceeded" failures (observed 2026-09-10). Use `prompt-template.md` filled in. List ALL prior completed batches and require deduping against their reports (overlap → note it, skip or add only new detail).
3. Findings that live primarily in another class go to a "cross-batch observation" for the owning batch, not fully developed here. For **parallel implementations of the same feature** (e.g. the JNI `openssl/` vs the Panama-FFI `openssl/panama/`), note "identical in <other impl>" rather than re-reporting — but DO report genuine divergences/regressions between them as live findings (observed: a buffer-offset term present in the JNI engine was dropped in the Panama rewrite → wrong bytes encrypted).
4. Worker final message contract: findings list (ID + one line each) or "NO FINDINGS", report path, test file path(s) + JUnit pass/fail counts, cross-batch observations. Never paste the report into chat.
5. After a batch completes, spot-check the report against its claims before treating it as done: do the cited `file:line`s exist? does the recorded JUnit output look real? **Re-run at least one "failing" test yourself on unmodified source and confirm it actually FAILS** — if a test asserting correct behavior passes, the finding is not demonstrated (see Test conventions red flag) and you must downgrade or re-test it. Also confirm `git status --porcelain` is clean. Do this for every batch; do not trust the worker's pass/fail counts alone. Finalize a batch only after spot-checking EACH reported defect against its cited source lines and running its targeted JUnit test(s) on unmodified source — confirm both the expected failure (for failing-test findings) and that regression guards still pass.

### Batch ledger (todo list) — keep it live

Maintain a todo list for the current fleet: one item per batch, plus items for post-batch spot-checks and any pending follow-ups. Update it IMMEDIATELY as each worker returns — mark a batch completed only after you have spot-checked its report against its claims (item 5). Never leave a stale `in_progress` item or defer updates to the end of the session; the list is how the user (and a resuming session) sees true progress. Keep granularity per-batch so "dispatch N batches" never hides that only one has landed.

If a worker returns an empty/missing result, do **NOT** assume death — **check disk first**: read the report's final STATUS line + `## Progress` and look for the test file. An empty message frequently means the worker finished (or nearly did) on disk without emitting a final summary (observed repeatedly: full completions with no final text). If COMPLETE + tests present → verify its claims (step 5) and accept it; if IN-PROGRESS → dispatch a finisher; only re-dispatch fresh when there is nothing usable on disk. Re-dispatching a batch that already completed wastes a worker and can clobber good work.

**Pausing mid-campaign:** when stopping between batches or mid-batch, record self-describing resume state in the live ledger — a top-of-file pause banner plus a batch row noting verified commit/tree status, which batches are completed and spot-checked, partial report skeleton details (lines read, candidate findings), missing tests/findings, and the exact next finisher action. A resuming session should be able to continue from the ledger alone.

## Disclosure bundle (submission-ready reports)

Curated findings become standalone security disclosures in `security-scans/tomcat/disclosures/NN-slug.md` (one per finding): component, affected versions, severity/CVSS 3.1 + CWE, summary, root cause with verified file:line refs, preconditions & exploitability, impact, reproduction (PoC), suggested patch, references.

A disclosure is SUBMISSION-READY only when it has all three of these (the user's bar):

1. **End-to-end reproducer** — makes a COMPLETE request to Tomcat (embedded container, raw socket, or real h2c client) that demonstrates the exploit; not just a unit-level call into one method.
2. **A test that CURRENTLY FAILS on unmodified source** — asserts the correct/secure behavior so it is red today, proving "the bad code needs fixing." Name it by path + method and paste its ACTUAL JUnit output verbatim showing the failure. (Internal `defects-*.md` reports may instead use passing tests that document actual buggy behavior — disclosures must not.)
3. **A suggested patch** — a concrete unified diff in a `## Suggested patch` section (```diff block) that applies cleanly with `git apply --check`, focused on the owning lines cited in the report.

Hardening workflow: for each finding, dispatch ONE worker at a time to (a) add the failing E2E test, (b) write the patch, (c) update the md with both + actual JUnit output. Never modify `java/` sources or existing tests — only add one new test file and edit the disclosure md; confirm the repo tree is clean after.

Verification checklist before calling a bundle ready (do it yourself; don't trust worker claims):
- Run every new failing test → each must report FAILURES on current code.
- `grep -c '^## Suggested patch'` per disclosure → 1.
- Extract each embedded ```diff block and run `git apply --check` from the repo root → all pass.

Produce each suggested patch by applying the exact edit in the repo and capturing `git diff`, then restoring the clean tree (rebuilding original artifacts if needed) before validating with `git apply --check` from the repo root — don't hand-write diffs; they drift from what actually applies.

## Resuming / extending the campaign

- Enumerate what's left in an area: list `java/org/apache/<...>/<pkg>/**/*.java` (recurse into subpackages — each large subpackage is its own batch or set of batches) with line counts, cross-reference against existing `defects-*.md` reports in `security-scans/tomcat/`. Have the worker re-confirm the actual files via `ls`, since supplied class lists go stale across pulls.
- **Current campaign state** (already-covered batches per area, notable findings K-2/J-1/H/G/L etc., remaining classes with line counts): read REFERENCE.md — "Campaign state". Re-read current code before citing old line refs; source moves across pulls.

- **Before declaring an area unscanned:** enumerate existing report filenames and inspect their stated package/class scope — parent-package reports may explicitly defer subpackages to later batches, so a missing report name does not mean the scope is uncovered.
- **Tallying completion across campaigns:** reconcile per-file ledgers with the actual report files and their STATUS footers; parse all finding-header variants (e.g. `### F-1:` and `### F-1 —`); confirm a stub/skeleton report is superseded by its completed successor batch before treating that scope as unreviewed.
- **Campaign finalization:** when an area or campaign is done, independently re-run each retained finding's JUnit reproducer on unmodified source at the recorded commit, verify clean git state and artifact presence (reports + tests), dedupe against prior campaigns' reports, and record cross-batch observations in the live findings ledger.

### Stalled-worker recovery pattern (proven on ajp-A)

**Detect** a death by a missing `<!-- STATUS: COMPLETE -->` marker or an empty final message; the report's `## Progress` log tells you exactly which lines were read and what candidates exist. Then do NOT resume its session — dispatch a fresh "finisher" that reads that progress log, gets key candidate findings pre-verified by the main agent (with file:line refs) so it skips re-derivation, and only covers the remaining line range + tests. Also add hard caps to prompts: webfetch ≤1, javac attempts ≤3, a target-source line budget, and a "next tool call after each read chunk must edit the report" rule. **Keep finishers small:** pass candidate summaries inline (so they do NOT re-read a large existing report or big source file) and bound their remaining line range — a large completion scope dies just like a fresh one (observed: an `openssl/` batch died after reading only its 1424-line lead class, leaving the other 10 files + all tests undone). If a batch's original scope was too big to finish in one worker, split it into sub-batches (e.g. F → F + F2) rather than leaving one half-covered report.
