"""Deterministic (non-LLM) verification of disclosure artifacts.

Covers: CVSS score computation vs claim, ``git apply --check`` on the patch,
embedded-diff vs saved-.patch consistency, JUnit compile+run of the cited
tests (pre-patch must FAIL; post-patch must PASS), and file:line reference
sanity checks. Everything here is reproducible without any model.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .cvss31 import CvssError, base_score


def _run(cmd: list[str], cwd: str | None = None, timeout: float = 600.0) -> subprocess.CompletedProcess:
    """Run a command; a timeout is reported as rc=124, never raised.

    Callers (especially ``run_postpatch_loop``) must always be able to reach
    their cleanup/restore steps even when a child process hangs.
    """
    try:
        return subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as e:
        proc = subprocess.CompletedProcess(cmd, 124, "", f"timed out after {timeout}s")
        if e.stdout:
            proc.stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout)
        return proc


# -- CVSS --------------------------------------------------------------------


def check_cvss(vector: str | None, claimed_score: float | None) -> dict:
    if not vector:
        return {"ok": False, "error": "no CVSS 3.1 vector found in disclosure"}
    try:
        computed = base_score(vector)
    except CvssError as e:
        return {"ok": False, "vector": vector, "error": f"invalid vector: {e}"}
    result: dict = {
        "ok": True,
        "vector": vector,
        "computed_score": computed,
        "claimed_score": claimed_score,
    }
    if claimed_score is None:
        result["score_match"] = None
        result["note"] = "no claimed base score found to compare"
    else:
        match = abs(computed - claimed_score) < 0.05
        result["score_match"] = match
        if not match:
            result["note"] = (
                f"claimed base score {claimed_score} does not match computed "
                f"{computed} for the stated vector"
            )
    return result


# -- patch -------------------------------------------------------------------


def check_patch_applies(repo_root: Path, diff_text: str | None) -> dict:
    if not diff_text or not diff_text.strip():
        return {"ok": False, "error": "no embedded diff block found"}
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as f:
        f.write(diff_text)
        patch_path = f.name
    try:
        proc = _run(["git", "apply", "--check", "-p1", patch_path], cwd=str(repo_root))
    finally:
        Path(patch_path).unlink(missing_ok=True)
    return {
        "ok": proc.returncode == 0,
        "rc": proc.returncode,
        "stderr": proc.stderr.strip()[:2000],
    }


def compare_embedded_vs_file(diff_text: str | None, patch_file_path: Path | None) -> dict:
    if patch_file_path is None or not diff_text:
        return {"present": False}
    file_text = Path(patch_file_path).read_text(encoding="utf-8")
    identical = _normalize_diff(file_text) == _normalize_diff(diff_text)
    return {
        "present": True,
        "identical": identical,
        "sha256_embedded": hashlib.sha256(_normalize_diff(diff_text).encode()).hexdigest(),
        "sha256_file": hashlib.sha256(file_text.encode()).hexdigest(),
    }


def _normalize_diff(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.splitlines()).strip("\n") + "\n"


# -- JUnit -------------------------------------------------------------------

_JUNIT_OK_RE = re.compile(r"^OK \((\d+) tests?\)$", re.MULTILINE)
_JUNIT_FAILS_RE = re.compile(r"(?:Tests run: (\d+),\s*)?Failures?: (\d+)")
_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)


def build_classpath(repo_root: Path, jar_dir: Path | None, extra_dirs: list[str] | None = None) -> str:
    parts = [str(repo_root / "output/classes"), str(repo_root / "output/testclasses")]
    if extra_dirs:
        parts.extend(extra_dirs)
    if jar_dir is not None and Path(jar_dir).is_dir():
        jars = sorted(Path(jar_dir).rglob("*.jar"))
        parts.extend(str(j) for j in jars)
    return ":".join(parts)


def fqcn_of(test_file: Path) -> str | None:
    m = _PACKAGE_RE.search(Path(test_file).read_text(encoding="utf-8", errors="replace"))
    if not m:
        return None
    return f"{m.group(1)}.{Path(test_file).stem}"


def compile_and_run_tests(
    test_files: list[Path],
    repo_root: Path,
    jar_dir: Path | None = None,
    scratch_dir: Path | None = None,
    extra_cp_dirs: list[str] | None = None,
    javac_timeout: float = 300.0,
    java_timeout: float = 600.0,
) -> dict:
    """Compile the cited test files and run each with JUnitCore.

    Returns {compiled, compile_stderr, classes: [{file, fqcn, ran, ok,
    failures, raw}]}. ``ok`` is True only when JUnit reports OK (all pass);
    a failing assertion yields ok=False with the failure count.
    """
    cp = build_classpath(repo_root, jar_dir, extra_cp_dirs)
    scratch = Path(scratch_dir) if scratch_dir else Path(tempfile.mkdtemp(prefix="dv-junit-"))
    scratch.mkdir(parents=True, exist_ok=True)

    compile_result: dict = {"compiled": False, "compile_stderr": ""}
    if test_files:
        proc = _run(
            ["javac", "-cp", cp, "-d", str(scratch), *[str(t) for t in test_files]],
            timeout=javac_timeout,
        )
        compile_result["compiled"] = proc.returncode == 0
        compile_result["compile_stderr"] = (proc.stderr or "")[:4000]

    classes: list[dict] = []
    for tf in test_files:
        fqcn = fqcn_of(tf)
        entry: dict = {"file": str(tf), "fqcn": fqcn, "ran": False, "ok": None, "failures": None, "raw": ""}
        if not compile_result["compiled"] or fqcn is None:
            classes.append(entry)
            continue
        proc = _run(
            ["java", "-cp", f"{scratch}:{cp}", "org.junit.runner.JUnitCore", fqcn],
            timeout=java_timeout,
        )
        raw = (proc.stdout or "") + ("\n[stderr]\n" + proc.stderr if proc.stderr else "")
        entry["ran"] = True
        entry["raw"] = raw[:8000]
        ok_m = _JUNIT_OK_RE.search(proc.stdout or "")
        fail_m = _JUNIT_FAILS_RE.search(proc.stdout or "")
        if ok_m:
            entry["ok"] = True
            entry["failures"] = 0
        elif fail_m:
            entry["ok"] = False
            entry["failures"] = int(fail_m.group(2))
        else:
            entry["ok"] = None  # could not classify (e.g. init error)
            entry["note"] = "JUnit output could not be classified"
        classes.append(entry)

    return {"compiled": compile_result["compiled"], "compile_stderr": compile_result["compile_stderr"], "classes": classes}


def changed_sources_from_diff(diff_text: str) -> list[str]:
    """Return repo-relative paths of files the diff modifies (a/ and b/ sides)."""
    out = []
    for line in diff_text.splitlines():
        m = re.match(r"^\+\+\+ b/(.+)$", line) or re.match(r"^--- a/(.+)$", line)
        if m:
            p = m.group(1).strip()
            if p != "/dev/null" and p not in out:
                out.append(p)
    return out


def run_postpatch_loop(
    repo_root: Path,
    diff_text: str,
    test_files: list[Path],
    jar_dir: Path | None = None,
    extra_cp_dirs: list[str] | None = None,
    javac_timeout: float = 300.0,
    java_timeout: float = 600.0,
) -> dict:
    """Apply the patch in-repo, recompile changed sources, rerun tests, restore.

    Leaves both the git tree and output/classes exactly as found (patched
    classes are recompiled back from restored sources). Returns {applied_ok,
    apply_stderr, junit, restored_ok}.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as f:
        f.write(diff_text)
        patch_path = f.name
    try:
        proc = _run(["git", "apply", "-p1", patch_path], cwd=str(repo_root))
        if proc.returncode != 0:
            return {
                "applied_ok": False,
                "apply_stderr": proc.stderr.strip()[:2000],
                "junit": None,
                "restored_ok": True,
            }

        changed = [p for p in changed_sources_from_diff(diff_text) if p.endswith(".java")]
        cp = build_classpath(repo_root, jar_dir, extra_cp_dirs)
        # Compile all changed sources TOGETHER: a patch may add symbols to one
        # file that another patched file references; per-file javac would see
        # the stale .class for the sibling instead.
        recompile_failures: list[str] = []
        changed_srcs = [str(repo_root / rel) for rel in changed if (repo_root / rel).is_file()]
        if changed_srcs:
            r = _run(
                ["javac", "-cp", cp, "-d", str(repo_root / "output/classes")] + changed_srcs,
                timeout=min(javac_timeout * max(1, len(changed_srcs)), javac_timeout * 8),
            )
            if r.returncode != 0:
                recompile_failures.append(r.stderr.strip()[:2000])

        junit = compile_and_run_tests(
            test_files, repo_root, jar_dir=jar_dir, extra_cp_dirs=extra_cp_dirs,
            javac_timeout=javac_timeout, java_timeout=java_timeout,
        )

        # Restore sources by reverse-applying the patch (handles added/removed
        # files too), then recompile changed sources so output/classes matches.
        git_restore = _run(["git", "apply", "-R", "-p1", patch_path], cwd=str(repo_root))
        restored_ok = git_restore.returncode == 0
        if changed_srcs:
            _run(
                ["javac", "-cp", cp, "-d", str(repo_root / "output/classes")] + changed_srcs,
                timeout=min(javac_timeout * max(1, len(changed_srcs)), javac_timeout * 8),
            )

        return {
            "applied_ok": True,
            "apply_stderr": "",
            "recompile_failures": recompile_failures,
            "junit": junit,
            "restored_ok": restored_ok,
        }
    finally:
        Path(patch_path).unlink(missing_ok=True)


# -- file:line references ------------------------------------------------------

_FILELINE_RE = re.compile(
    r"((?:java|test)/[\w/.-]+?\.java)\s*(?:L(\d+)(?:\s*-\s*L?(\d+))?)?"
)


def check_fileline_refs(text: str, repo_root: Path) -> dict:
    """Sanity-check `path/File.java L###` references against the tree."""
    refs = []
    seen: set[tuple[str, int]] = set()
    for m in _FILELINE_RE.finditer(text):
        rel, start, end = m.group(1), m.group(2), m.group(3)
        if not start:
            continue
        key = (rel, int(start))
        if key in seen:
            continue
        seen.add(key)
        path = repo_root / rel
        exists = path.is_file()
        line_ok = None
        max_line = 0
        if exists:
            try:
                max_line = sum(1 for _ in path.open(encoding="utf-8", errors="replace"))
            except OSError:
                pass
            hi = int(end) if end else int(start)
            line_ok = 1 <= int(start) and hi <= max_line
        refs.append(
            {
                "ref": m.group(0).strip(),
                "file": rel,
                "line_start": int(start),
                "line_end": int(end) if end else None,
                "file_exists": exists,
                "line_in_range": line_ok,
                "max_line": max_line or None,
            }
        )
    bad = [r for r in refs if not (r["file_exists"] and r["line_in_range"])]
    return {"checked": len(refs), "bad": len(bad), "refs": refs}
