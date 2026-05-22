#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

COUNT=5
LINK_AUTH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)
      COUNT="${2:?missing count}"
      shift 2
      ;;
    --link-auth)
      LINK_AUTH=1
      shift
      ;;
    -h|--help)
      cat <<'EOF'
usage: scripts/init-codex-workers.sh [--count N] [--link-auth]

Creates worker-local CODEX_HOME directories under ~/.codex-workers.
Auth is not linked unless --link-auth is provided.
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

ARGS=(codex init-workers --count "$COUNT")
if [[ "$LINK_AUTH" -eq 1 ]]; then
  ARGS+=(--link-auth)
else
  echo "Auth will not be linked. Use --link-auth only after accepting the local-only symlink risk."
fi

./scripts/ctfctl "${ARGS[@]}"
