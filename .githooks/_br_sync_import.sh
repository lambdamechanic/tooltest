#!/usr/bin/env sh

set -u

hook_name=${1:-}
base_ref=${2:-}
head_ref=${3:-}

if [ -z "$hook_name" ]; then
    echo "Warning: missing hook name for br import helper." >&2
    exit 0
fi

if [ "${BR_BEADS_SYNC_MAINTENANCE:-}" = "1" ]; then
    exit 0
fi

if [ -z "$base_ref" ] || [ -z "$head_ref" ]; then
    exit 0
fi

if ! git diff --name-only "$base_ref" "$head_ref" -- .beads/issues.jsonl | grep -q .; then
    exit 0
fi

if ! command -v br >/dev/null 2>&1; then
    echo "Warning: br command not found; skipping $hook_name import." >&2
    echo "  Run 'br sync --import-only' manually once br is available." >&2
    exit 0
fi

if ! br sync --import-only; then
    echo "Warning: br sync --import-only failed after $hook_name." >&2
    echo "  Run 'br sync --import-only' manually to recover." >&2
    exit 0
fi
