#!/usr/bin/env bash
# Launch the disclosure-verifier pipeline with a clean LM Studio slate.
#
# Why this exists: the pipeline needs exclusive GPU access, but anything that
# shares the local LM Studio (an agent's own model, other jobs) steals VRAM
# and slows or breaks stage loads. This script unloads EVERY loaded model
# first - including an agent's model - then starts the verifier fully detached
# in its own session so it survives this shell exiting. The pipeline itself
# unloads all models again when it finishes, leaving a clean slate at both ends.
#
# Usage:
#   run_pipeline.sh [SLUG ...]        verify specific disclosure slugs
#   run_pipeline.sh                   verify every disclosure in the campaign
#   run_pipeline.sh --wait [SLUG...]  block until the run finishes, then print results
set -euo pipefail

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$TOOL_DIR/output"
mkdir -p "$OUT_DIR"

WAIT=0
if [[ ${1:-} == "--wait" ]]; then WAIT=1; shift; fi

# 1. Unload every loaded model so the pipeline starts from a clean slate.
#    Non-fatal: if LM Studio is unreachable, let the pipeline report that itself.
python3 - "$TOOL_DIR" <<'EOF' || echo "warning: could not unload models (LM Studio unreachable?)" >&2
import sys

sys.path.insert(0, sys.argv[1])
from disclosure_verifier.lmstudio import LmStudioClient

try:
    c = LmStudioClient()
    for inst in c.loaded_instances():
        try:
            c.unload_instance(inst.instance_id)
            print(f"unloaded {inst.model_key}")
        except Exception as e:  # noqa: BLE001 - keep going, warn per model
            print(f"warning: could not unload {inst.model_key}: {e}", file=sys.stderr)
except Exception as e:  # noqa: BLE001
    print(f"warning: LM Studio query failed: {e}", file=sys.stderr)
EOF

# 2. Launch fully detached in its own session (survives this shell, the agent
#    turn that started it, or a terminal closing).
LOG="$OUT_DIR/pipeline-$(date +%Y%m%d-%H%M%S).log"
cd "$TOOL_DIR"
setsid nohup python3 -m disclosure_verifier "$@" >"$LOG" 2>&1 </dev/null &
PID=$!

# 3. Sanity-check it survived startup, then record status for later inspection.
sleep 2
if ! kill -0 "$PID" 2>/dev/null; then
    echo "error: pipeline exited immediately; last log lines:" >&2
    tail -n 20 "$LOG" >&2
    exit 1
fi

SLUG_JSON=$(python3 -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "$@")
cat >"$OUT_DIR/pipeline-status.json" <<EOF
{"pid": $PID, "log": "$LOG", "launched_at": "$(date -Iseconds)", "slugs": $SLUG_JSON}
EOF

echo "pipeline launched: pid=$PID"
echo "  log:    $LOG"
echo "  status: $OUT_DIR/pipeline-status.json"

if [[ $WAIT == 1 ]]; then
    while kill -0 "$PID" 2>/dev/null; do sleep 15; done
    echo "--- pipeline finished ---"
    tail -n 30 "$LOG"
fi
