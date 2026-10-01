#!/usr/bin/env python3
"""Merge this repo's fragments into the global opencode config dir.

Two independent operations (each idempotent):

1. AGENTS.md: replaces the content between the marker comments for --marker,
   inserts it at the end if absent, or removes the block when no --fragment is
   given (or the file is missing/empty).

2. opencode.jsonc (--config + --fragment-jsonc): deep-merges this repo's JSONC
   fragment into the global config, or with --remove deletes exactly the keys
   the fragment defines (pruning dicts left empty). The global file is
   rewritten as plain 2-space-indented JSON — keep it comment-free.

Stdlib only.
"""
import argparse
import json
import re
from pathlib import Path


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments (outside strings) and trailing commas."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_jsonc(path: Path):
    if not path.exists():
        return {}
    return json.loads(strip_jsonc(path.read_text()))


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2) + "\n")


def deep_merge(base, frag) -> None:
    for k, v in frag.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v


def deep_remove(target, frag) -> None:
    for k, v in list(frag.items()):
        if isinstance(v, dict) and isinstance(target.get(k), dict):
            deep_remove(target[k], v)
            if not target[k]:
                del target[k]
        else:
            target.pop(k, None)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agents-md", default=None, help="global AGENTS.md path")
    ap.add_argument("--marker", required=True, help="block id (repo name)")
    ap.add_argument(
        "--fragment",
        default=None,
        help="AGENTS.md fragment file; omit to remove the block",
    )
    ap.add_argument("--config", default=None, help="global opencode.jsonc path")
    ap.add_argument(
        "--fragment-jsonc",
        default=None,
        help="this repo's JSONC config fragment (merged into --config)",
    )
    ap.add_argument(
        "--remove",
        action="store_true",
        help="with --config: delete the fragment's keys instead of merging",
    )
    args = ap.parse_args()

    if not args.agents_md and not args.config:
        ap.error("nothing to do: pass --agents-md and/or --config")

    if args.agents_md:
        begin = f"<!-- BEGIN {args.marker} -->"
        end = f"<!-- END {args.marker} -->"
        block_re = re.compile(
            r"\n*<!-- BEGIN " + re.escape(args.marker) + r" -->.*?<!-- END "
            + re.escape(args.marker) + r" -->\n*",
            re.DOTALL,
        )

        target = Path(args.agents_md)
        text = target.read_text() if target.exists() else "# Global rules\n"

        fragment = None
        if args.fragment:
            frag_path = Path(args.fragment)
            if frag_path.exists():
                raw = frag_path.read_text().strip("\n")
                fragment = raw if raw.strip() else None

        # Leading \n\n keeps one blank line before the block; trailing \n\n keeps
        # one between adjacent blocks (collapsed at EOF by the final normalize).
        # block_re's \n* consumes both on re-runs, so output is stable.
        replacement = (
            f"\n\n{begin}\n{fragment}\n{end}\n\n" if fragment is not None else ""
        )

        new_text, count = block_re.subn(lambda _m: replacement, text)
        if count == 0 and fragment is not None:
            new_text = text.rstrip("\n") + replacement
        new_text = new_text.rstrip("\n") + "\n"
        target.write_text(new_text)
        action = "merged" if fragment is not None else "removed"
        print(f"[merge_config] {args.marker}: {action} AGENTS.md block in {target}")

    if args.config:
        cfg_path = Path(args.config)
        frag_obj = None
        if args.fragment_jsonc:
            fp = Path(args.fragment_jsonc)
            if fp.exists() and fp.read_text().strip():
                frag_obj = load_jsonc(fp)
        if frag_obj is None:
            print(f"[merge_config] {args.marker}: no JSONC fragment; config untouched")
            return
        cfg = load_jsonc(cfg_path)
        if args.remove:
            deep_remove(cfg, frag_obj)
            write_json(cfg_path, cfg)
            print(f"[merge_config] {args.marker}: removed fragment keys from {cfg_path}")
        else:
            deep_merge(cfg, frag_obj)
            write_json(cfg_path, cfg)
            print(f"[merge_config] {args.marker}: merged JSONC fragment into {cfg_path}")


if __name__ == "__main__":
    main()
