"""Apply adjudicator-proposed edits to disclosure artifacts, with backups.

Policy (per user decision): before any edit, the original file is copied to
``<name>.orig`` so it can be compared later; edits are applied in place; if a
post-edit re-verification fails, every applied file for that disclosure is
reverted from its ``.orig`` copy and the batch is flagged as rejected.
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path


def orig_path(path: Path) -> Path:
    return path.with_name(path.name + ".orig")


def backup(path: Path) -> Path | None:
    """Copy ``path`` to its .orig twin if one does not exist yet.

    Returns the backup path, or None when no copy was made (already backed up).
    The first original is always preserved - a second edit round never
    overwrites an existing .orig.
    """
    op = orig_path(path)
    if op.exists():
        return None
    shutil.copy2(path, op)
    return op


def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@dataclass
class Edit:
    target: str  # "disclosure" | "test:<basename>" | "patch"
    path: Path
    current_text: str
    proposed_text: str
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "path": str(self.path),
            "current_text": self.current_text,
            "proposed_text": self.proposed_text,
            "reason": self.reason,
        }


@dataclass
class EditResult:
    applied: list[dict] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)

    @property
    def no_failures(self) -> bool:
        """True when every edit applied (an empty batch trivially qualifies)."""
        return not self.failed


def apply_edits(edits: list[Edit]) -> EditResult:
    """Apply exact-match text replacements; never partially applies a file.

    An edit whose current_text is absent from the artifact is recorded as
    failed and left untouched. Repeated identical edits to one file are all
    applied in order (each against the result of the previous).
    """
    result = EditResult()
    for edit in edits:
        path = Path(edit.path)
        if not path.is_file():
            result.failed.append({**edit.to_dict(), "error": f"file not found: {path}"})
            continue
        content = path.read_text(encoding="utf-8")
        count = content.count(edit.current_text)
        if count == 0:
            result.failed.append(
                {**edit.to_dict(), "error": "current_text not found verbatim in artifact"}
            )
            continue
        backup(path)
        sha_before = hashlib.sha256(content.encode("utf-8")).hexdigest()
        new_content = content.replace(edit.current_text, edit.proposed_text, 1)
        path.write_text(new_content, encoding="utf-8")
        result.applied.append(
            {
                **edit.to_dict(),
                "occurrences_found": count,
                "sha256_before": sha_before,
                "sha256_after": hashlib.sha256(new_content.encode("utf-8")).hexdigest(),
                "backup_path": str(orig_path(path)),
            }
        )
    return result


def revert(paths: list[Path]) -> dict:
    """Restore each path from its .orig backup (kept in place for comparison)."""
    restored = []
    errors = []
    for p in paths:
        p = Path(p)
        op = orig_path(p)
        if not op.exists():
            errors.append(f"no .orig backup for {p}")
            continue
        shutil.copy2(op, p)
        restored.append(str(p))
    return {"restored": restored, "errors": errors}


def edits_from_adjudication(final_verdict: dict, bundle) -> list[Edit]:
    """Translate the adjudicator's edits[] into Edit objects bound to files.

    target mapping: "disclosure" -> bundle.path; "patch" -> adjacent .patch
    file (or the disclosure md if none); "test:<basename>" -> matching test
    file in bundle.test_files (unresolvable targets are dropped with a note).
    """
    edits: list[Edit] = []
    notes: list[str] = []
    for raw in final_verdict.get("edits") or []:
        if not isinstance(raw, dict):
            continue
        target = str(raw.get("target", "")).strip()
        current = raw.get("current_text")
        proposed = raw.get("proposed_text")
        reason = str(raw.get("reason", ""))
        if not isinstance(current, str) or not isinstance(proposed, str) or not current.strip():
            notes.append(f"skipped edit with missing/empty text: {str(raw)[:120]}")
            continue

        path: Path | None = None
        if target == "disclosure":
            path = bundle.path
        elif target == "patch":
            path = bundle.patch_file_path or bundle.path
        elif target.startswith("test:"):
            base = target[len("test:") :].strip()
            for tf in bundle.test_files:
                if tf.name == base or tf.stem == base.removesuffix(".java"):
                    path = tf
                    break
        else:
            notes.append(f"skipped edit with unknown target {target!r}")
            continue

        if path is None or not Path(path).is_file():
            notes.append(f"skipped edit: target file not found for {target!r}")
            continue
        edits.append(Edit(target=target, path=Path(path), current_text=current, proposed_text=proposed, reason=reason))
    return edits, notes
