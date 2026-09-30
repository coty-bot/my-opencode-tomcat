"""Parse a disclosure markdown file into a structured bundle."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .cvss31 import extract_cvss_claim

_COMMIT_RE = re.compile(r"\b([0-9a-f]{40})\b")
_CWE_RE = re.compile(r"\bCWE-(\d+)\b")
_DIFF_BLOCK_RE = re.compile(r"^```diff\n(.*?)^```\s*$", re.MULTILINE | re.DOTALL)
# Any path (absolute or relative, with any directory prefix) whose final
# component is Test*.java and which contains a test/tests/test-services dir.
# Segments are matched as leading-slash + name so adjacent segments share no
# characters (a trailing-slash segment pattern can never repeat).
_TEST_PATH_RE = re.compile(
    r"(?<![\w.-])(?:/?(?:[\w.-]+/)*)test(?:s|-services)?/[\w/.-]*Test\w+\.java"
)
_BARE_TEST_RE = re.compile(r"\b(Test\w+)\.java\b")


@dataclass
class Bundle:
    slug: str
    path: Path
    text: str
    sha256: str

    title: str | None = None
    commit: str | None = None
    cvss_vector: str | None = None
    claimed_score: float | None = None
    cwe: str | None = None
    diff_text: str | None = None
    patch_file_path: Path | None = None
    patch_file_sha256: str | None = None

    test_files: list[Path] = field(default_factory=list)
    unresolved_test_names: list[str] = field(default_factory=list)
    sections: dict[str, str] = field(default_factory=dict)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def split_sections(text: str) -> dict[str, str]:
    """Split markdown into {header: body} for level-2 (##) headers."""
    sections: dict[str, str] = {}
    current = None
    buf: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.startswith("## "):
            if current is not None:
                sections[current] = "".join(buf)
            current = line[3:].strip()
            buf = []
        elif current is not None:
            buf.append(line)
    if current is not None:
        sections[current] = "".join(buf)
    return sections


def _resolve_test_refs(text: str, test_roots: list[Path]) -> tuple[list[Path], list[str]]:
    """Resolve every Test*.java mention to a file on disk.

    Path-shaped mentions are tried verbatim (absolute or relative to each
    test root); bare basenames are searched under the roots. Order of first
    appearance is preserved; duplicates collapse.
    """
    resolved: list[Path] = []
    seen: set[str] = set()
    unresolved: list[str] = []

    def add(p: Path) -> None:
        key = str(p)
        if key not in seen:
            seen.add(key)
            resolved.append(p)

    path_spans: list[tuple[int, int]] = []
    fence_spans: list[tuple[int, int]] = []
    in_fence, fence_start = False, 0
    for m in re.finditer(r"^```.*$", text, re.MULTILINE):
        if not in_fence:
            in_fence, fence_start = True, m.start()
        else:
            in_fence = False
            fence_spans.append((fence_start, m.end()))

    mentions: list[tuple[int, str]] = []
    for m in _TEST_PATH_RE.finditer(text):
        path_spans.append((m.start(), m.end()))
        mentions.append((m.start(), m.group(0)))

    def inside_path_span(pos: int) -> bool:
        return any(s <= pos < e for s, e in path_spans)

    def only_in_fences(name: str) -> bool:
        """True when every bare mention of ``name`` sits inside a code fence.

        Unresolvable names that appear ONLY in fenced blocks (pasted JUnit
        output / stack traces, e.g. org.junit.rules.TestWatcher.java) are
        treated as noise; the same name in prose is a real reference problem.
        """
        hits = [m.start() for m in _BARE_TEST_RE.finditer(text) if f"{m.group(1)}.java" == name]
        return bool(hits) and all(any(s <= p < e for s, e in fence_spans) for p in hits)

    for m in _BARE_TEST_RE.finditer(text):
        if not inside_path_span(m.start()):
            mentions.append((m.start(), f"{m.group(1)}.java"))
    mentions.sort(key=lambda t: t[0])

    def suffix_match(root: Path, mention: str) -> Path | None:
        """Longest tail of ``mention`` that exists as a file under ``root``."""
        parts = [p for p in mention.split("/") if p]
        for i in range(1, len(parts)):
            cand = root.joinpath(*parts[i:])
            if cand.is_file():
                return cand
        return None

    for _, mention in mentions:
        found: Path | None = None
        if "/" not in mention:
            base = Path(mention)
            hits = [r / base.name for r in test_roots]
            # also allow package-style search under roots
            found = next((h for h in hits if h.is_file()), None)
            if found is None:
                found = next((p for r in test_roots for p in r.rglob(base.name)), None)
        else:
            candidates = [Path(mention)]
            if not Path(mention).is_absolute():
                candidates += [r / mention for r in test_roots]
            found = next((c for c in candidates if c.is_file()), None)
            if found is None:
                # e.g. an absolute path captured with a foreign prefix, or a
                # repo-relative path that only exists under another root
                found = next(
                    (s for r in test_roots if (s := suffix_match(r, mention)) is not None),
                    None,
                )
        if found is not None:
            add(found.resolve())
        elif "/" not in mention and only_in_fences(mention):
            continue  # stack-trace noise inside pasted test output
        elif mention not in unresolved:
            unresolved.append(mention)

    return resolved, unresolved


def parse_disclosure(path: Path, test_roots: list[Path]) -> Bundle:
    """Parse one disclosure markdown file into a :class:`Bundle`."""
    path = Path(path).resolve()
    text = path.read_text(encoding="utf-8")
    slug = path.stem  # e.g. "07-webdav-lock-token-bypass"

    title_m = re.search(r"^# +(.+)$", text, re.MULTILINE)
    commit_m = _COMMIT_RE.search(text)
    cwe_m = _CWE_RE.search(text)
    vector, claimed = extract_cvss_claim(text)
    diff_m = _DIFF_BLOCK_RE.search(text)

    patch_file = path.with_suffix(".patch")
    test_files, unresolved = _resolve_test_refs(text, [Path(r).resolve() for r in test_roots])

    return Bundle(
        slug=slug,
        path=path,
        text=text,
        sha256=_sha256(text.encode("utf-8")),
        title=title_m.group(1).strip() if title_m else None,
        commit=commit_m.group(1) if commit_m else None,
        cvss_vector=vector,
        claimed_score=claimed,
        cwe=f"CWE-{cwe_m.group(1)}" if cwe_m else None,
        diff_text=diff_m.group(1).rstrip("\n") + "\n" if diff_m else None,
        patch_file_path=patch_file if patch_file.is_file() else None,
        patch_file_sha256=_sha256(patch_file.read_bytes()) if patch_file.is_file() else None,
        test_files=test_files,
        unresolved_test_names=unresolved,
        sections=split_sections(text),
    )
