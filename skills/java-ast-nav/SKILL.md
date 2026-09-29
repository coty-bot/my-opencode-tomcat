---
name: java-ast-nav
description: Follow code paths in Java source (Tomcat or any repo) with syntax-aware precision instead of grep — call sites/callers of a method, every write to a field, symbol definitions and references, class/method/field outlines, raw tree-sitter structural queries. Use when tracing data flow, verifying reachability ("can this be triggered?"), confirming a flag/guard is dead code, or enumerating where an API is invoked during security/defect review. Backed by the astnav.py helper (tree-sitter + tree-sitter-java).
---

# Java AST Navigation (`astnav`)

Follow code paths in Java with **syntax-aware** precision. Unlike `grep`, it ignores comments and string literals, distinguishes declarations from invocations from references, matches specific AST node types, and shows receiver context on call sites. Helper: `astnav.py` (this directory).

## When to use vs grep

- Use `astnav` when you need **structure or symbol semantics**: "who calls X?", "where is field Y written?", "outline class Z", "all synchronized blocks in package P". It answers these precisely.
- Plain `grep`/ripgrep is still fine for: searching string literals, log messages, config keys, comments, or free text that isn't a code symbol.

## Setup (already installed on this box)

```bash
pip install tree-sitter tree-sitter-java   # verified working; tree-sitter 0.26.x
A=/home/opencode/.config/opencode/skills/java-ast-nav/astnav.py
python3 $A <subcommand> ...
```

Run from the repo root (e.g. `/home/opencode/src/tomcat`) so `--root` paths are relative and clean. Build dirs (`output`, `build`, `target`, `.git`, ...) are skipped automatically. Whole-tree queries over all of Tomcat's `java/` take ~1–2 s — no index needed.

## Subcommands

Output lines are `<relpath>:<line> <kind-or-capture> <snippet>` (whitespace collapsed, clipped). Counts go to stderr so they don't pollute pipeable stdout.

| Command | Purpose | Example |
|---|---|---|
| `symbols FILE` | Outline classes/methods/fields with line numbers — get a method map without reading the file | `python3 $A symbols java/org/apache/catalina/connector/Response.java` |
| `defs NAME --root DIR` | Find declarations (class/method/field/local) named NAME | `python3 $A defs included --root java/org/apache/catalina/connector` |
| `calls NAME --root DIR` | Find every call site invoking NAME, with receiver context | `python3 $A calls setCharacterEncoding --root java/org/apache/catalina/connector` |
| `writes FIELD --root DIR` | Find assignments to a field (bare `f =`, `this.f =`, `obj.f =`, and compound `+=`) | `python3 $A writes included --root java` |
| `refs NAME --root DIR` | Find references to an identifier (excludes the declaration site itself) | `python3 $A refs included --root java/org/apache/catalina/connector` |
| `query SITTER_QUERY --root DIR` | Raw tree-sitter structural query (escape hatch for patterns the named commands don't cover) | `python3 $A query '(synchronized_statement) @sync' --root java/org/apache/coyote/http11` |

### Reading the output

- `calls` prints `<recv>.<name>(...)`. An empty receiver means an unqualified call (implicit `this.`), e.g. an overload delegating to another overload in the same class.
- `writes`/`refs` are **name-based**: they will also match a *different* local variable or field that happens to share the name in another class. Disambiguate by reading the file:line context (this is expected and usually obvious — e.g. a same-named local in `DefaultServlet`).

## Semantic index (`SemIndex.java`)

`astnav.py` is syntactic; when you need **type-resolved** disambiguation (which overload an invocation actually resolves to, which field an assignment writes to), use `SemIndex.java` in this directory. It compiles the whole source set with full attribution via javac's compiler API and emits resolved edges as TSV (`kind \t file \t line \t name \t decl_fqn \t signature \t receiver_type \t enclosing_method`). Heavier than astnav (full compile) — use it to confirm findings that name-based matching leaves ambiguous:

```bash
javac SemIndex.java
java -Xmx4g SemIndex <srcRoot> <classpath-or-empty> <outTsvPath>
```

## Security-scan recipes

- **Prove a flag/guard is dead code** (e.g. "is `included` ever set true?"): `python3 $A writes included --root java` → if the only write to the real field is `= false`, every `if (included)` guard is unreachable. Confirm with `refs included --root <pkg>` to enumerate guards.
- **Verify reachability of a sink**: start at the sink method, run `calls <sink> --root java` to find its callers, then repeat up the chain until you hit an entry point (connector/protocol class).
- **Enumerate API abuse surface**: `python3 $A calls getParameter --root java/org/apache/catalina` or outline a class first with `symbols`, then target specific methods.
- **Concurrency review**: `python3 $A query '(synchronized_statement) @sync' --root <pkg>`; also try `(object_creation_expression type: (type_identifier) @t)` for allocations, etc.

## Raw tree-sitter queries (`query`)

Query syntax is standard tree-sitter S-expression with capture names in `@name`. Useful Java node types: `method_invocation`, `field_access`, `assignment_expression`, `augmented_assignment_expression`, `object_creation_expression`, `synchronized_statement`, `try_statement`, `if_statement`, `local_variable_declaration`, `class_declaration`, `method_declaration`, `identifier`, `string_literal`.

Examples:
```bash
# all method invocations whose name is captured (filter by eye or pipe to grep)
python3 $A query '(method_invocation name: (identifier) @m)' --root java/org/apache/coyote/http11 | head
# every string literal in a package (find hardcoded secrets / magic values)
python3 $A query '(string_literal) @s' --root java/org/apache/catalina/connector | head
```

## Limitations (be honest about these in reports)

- **Syntactic, not semantic.** Matching is by name and AST shape. It does NOT resolve overloads, generics, or prove two same-named symbols are the same type/scope. For true call-hierarchy / type-based resolution use `SemIndex.java` above (or a Java LSP such as `jdtls`, which is not installed here).
- Name-based commands can include same-named locals/fields from other classes — always confirm by reading the reported file:line before asserting a finding.
- It parses source only; it does not see bytecode-level or reflection-driven call edges.

## Integration with tomcat-security-scan

In batch-reviewer prompts, point workers at this tool for cross-file tracing instead of many greps — it returns precise, pipeable `file:line` results and keeps large search output out of the worker's context (pipe through `head`). Suggested prompt line: "To trace callers/writers/references across files use `python3 /home/opencode/.config/opencode/skills/java-ast-nav/astnav.py <calls|writes|refs|defs> <name> --root java` rather than grep."
