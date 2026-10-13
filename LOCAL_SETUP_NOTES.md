# Local setup notes that may help others

These notes capture the assumptions that made this Tomcat security-scan setup work reliably on the original machine. They are not required values; treat them as a reference when adapting the project to another host.

## Directory layout

The original setup kept three kinds of files separate:

- **Tooling repo**: this repository, containing opencode agents/skills/tools and the disclosure verifier.
- **Tomcat checkout**: a clean upstream `apache/tomcat` checkout used only for reading, temporary patch validation, and test runs.
- **Campaign workspace**: scan reports, disclosure markdown, generated reproducer tests, verifier outputs, and patches.

Keeping campaign artifacts outside the Tomcat checkout is important: git cleanup in the Tomcat repo should never delete findings or generated tests.

A portable equivalent layout is:

```text
~/src/opencode-tomcat-security/       # this repo
~/src/tomcat/                         # upstream apache/tomcat checkout
~/workspace/security-scans/tomcat/    # campaign artifacts
~/tomcat-build-libs/                  # JUnit and other test/build jars, if not using Tomcat's own lib dir
```

## Tomcat checkout/build expectations

The scan prompts assume a Tomcat source tree that can be built without Maven, with compiled classes under:

```text
output/classes
output/testclasses
```

The worker test recipe uses a classpath shaped like:

```bash
CP="output/classes:output/testclasses:$(find /path/to/tomcat-build-libs -name '*.jar' | tr '\n' ':')"
javac -cp "$CP" -d /tmp/scratch /path/to/TestFile.java
java -cp "/tmp/scratch:$CP" org.junit.runner.JUnitCore fully.qualified.TestClass
```

On another machine, replace `/path/to/tomcat-build-libs` with wherever JUnit 4, Hamcrest, EasyMock, BouncyCastle, and other Tomcat test dependencies are available. If you already have Tomcat's build dependencies in a different location, use that instead.

## opencode installation model

`install.sh` does not copy files. It symlinks this repo's agents, skills, commands, and tools into the opencode config directory, then merges small config/AGENTS fragments. Re-run it after adding/removing agents or skills.

Useful convention:

```bash
OPENCODE_CONFIG_DIR="$HOME/.config/opencode" ./install.sh
```

If multiple projects install opencode agents/skills, watch for name collisions in:

```text
~/.config/opencode/agent
~/.config/opencode/skills
~/.config/opencode/tools
~/.config/opencode/command
```

## Local model / LM Studio assumptions

The disclosure verifier was designed for a local LM Studio server and assumes verifier stages should have exclusive access to GPU memory. `run_pipeline.sh` unloads all loaded LM Studio models before launching the pipeline, and the pipeline unloads models again at the end.

That behavior is useful on single-GPU machines, but surprising if you share LM Studio with other jobs. If adapting this setup, document this clearly for users.

The original setup used multiple evaluator models plus an adjudicator. You can use different models; update `disclosure-verifier/config.toml` after copying it from `config.example.toml`.

## Campaign workflow conventions

The scanner is intentionally serial: one batch worker at a time. This avoids local-model context/VRAM contention and reduces half-written reports.

Worker batches are intentionally small, typically capped around 1500 source lines. Large Java classes should be split into line-range batches.

Reports should include a status marker at the end:

```html
<!-- STATUS: IN-PROGRESS -->
<!-- STATUS: COMPLETE -->
```

This makes stalled-worker recovery possible by checking files on disk instead of relying on the agent's final chat message.

## Optional CodeQL/AST navigation

The Java AST navigation helper only needs Python plus `tree-sitter` and `tree-sitter-java`. It is useful even outside Tomcat for quick call/reference/writer searches.

CodeQL integration is optional. If you use it, keep the CodeQL database path and CodeQL checkout path configurable; those are usually machine-specific and expensive to recreate.
