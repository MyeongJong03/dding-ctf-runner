#!/usr/bin/env bash
set -euo pipefail

WORKER_ID="${WORKER_ID:-worker-1}"
CODEX_HOME="${CODEX_HOME:-$HOME/.codex-workers/$WORKER_ID}"

echo "Placeholder worker start for $WORKER_ID"
echo "CODEX_HOME=$CODEX_HOME"
echo "Future loop: ctfctl worker register, queue next, run Codex solve task, verify, guarded submit, release/finalize."
