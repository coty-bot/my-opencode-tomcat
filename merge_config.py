#!/usr/bin/env python3
"""Merge this repo's AGENTS.md fragment into the global opencode AGENTS.md.

Idempotent: replaces the content between the marker comments for --marker,
inserts it at the end if absent, or removes the block when no --fragment is
given (or the file is missing/empty). Stdlib only.
"""
import argparse
import re
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--agents-md", required=True, help="global AGENTS.md path")
    ap.add_argument("--marker", required=True, help="block id (repo name)")
    ap.add_argument(
        "--fragment",
        default=None,
        help="fragment file; omit to remove the block",
    )
    args = ap.parse_args()

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
    print(f"[merge_config] {args.marker}: {action} block in {target}")


if __name__ == "__main__":
    main()
