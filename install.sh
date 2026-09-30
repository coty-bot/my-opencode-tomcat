#!/usr/bin/env bash
# Install this bucket's agents/skills/plugins into the opencode config dir as
# symlinks, merge AGENTS.fragment.md into the global AGENTS.md, and deep-merge
# opencode.fragment.jsonc (permissions) into opencode.jsonc.
# Idempotent; re-run after adding/removing items. --uninstall reverses it.
set -euo pipefail

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
MARKER="$(basename "$SRC")"

link_items() {
  local made=0 d f
  if [ -d "$SRC/skills" ]; then
    for d in "$SRC"/skills/*/; do
      [ -d "$d" ] || continue
      ln -sfn "${d%/}" "$DEST/skills/$(basename "$d")" && made=$((made+1))
    done
  fi
  if [ -d "$SRC/agents" ]; then
    for f in "$SRC"/agents/*.md; do
      [ -f "$f" ] || continue
      ln -sfn "$f" "$DEST/agent/$(basename "$f")" && made=$((made+1))
    done
  fi
  if [ -d "$SRC/plugins" ]; then
    # Top-level plugin files only. A plugin with local imports (a sibling
    # module dir, e.g.) needs those dirs linked too — or reference it by
    # absolute path in opencode.jsonc "plugin".
    for f in "$SRC"/plugins/*.ts "$SRC"/plugins/*.js; do
      [ -f "$f" ] || continue
      ln -sfn "$f" "$DEST/plugins/$(basename "$f")" && made=$((made+1))
    done
  fi
  echo "[install] $MARKER: linked $made item(s) into $DEST"
}

unlink_items() {
  local removed=0 base p tgt
  for base in skills agent plugins; do
    [ -d "$DEST/$base" ] || continue
    for p in "$DEST/$base"/*; do
      [ -L "$p" ] || continue
      tgt="$(readlink "$p")"
      case "$tgt" in
        "$SRC"/*) rm "$p"; removed=$((removed+1)) ;;
      esac
    done
  done
  echo "[install] $MARKER: removed $removed symlink(s)"
}

case "${1:-}" in
  --uninstall)
    unlink_items
    python3 "$SRC/merge_config.py" --marker "$MARKER" \
      --agents-md "$DEST/AGENTS.md" \
      --config "$DEST/opencode.jsonc" --fragment-jsonc "$SRC/opencode.fragment.jsonc" \
      --remove
    ;;
  "")
    mkdir -p "$DEST/skills" "$DEST/agent" "$DEST/plugins"
    link_items
    python3 "$SRC/merge_config.py" --marker "$MARKER" \
      --agents-md "$DEST/AGENTS.md" --fragment "$SRC/AGENTS.fragment.md" \
      --config "$DEST/opencode.jsonc" --fragment-jsonc "$SRC/opencode.fragment.jsonc"
    ;;
  *) echo "usage: $0 [--uninstall]" >&2; exit 2 ;;
esac
