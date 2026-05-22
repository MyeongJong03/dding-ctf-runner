#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEEP_DIR=0
DEST=""

usage() {
  cat <<'EOF'
Usage: scripts/fresh-clone-check.sh [--keep-dir] [--dest DIR]

Creates a temporary file:// clone of the current repository, overlays current
uncommitted tracked and untracked non-ignored changes, then runs the public-safe
release smoke commands without external CTF traffic.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-dir)
      KEEP_DIR=1
      shift
      ;;
    --dest)
      DEST="${2:-}"
      if [[ -z "$DEST" ]]; then
        echo "[fresh-clone-check] --dest requires a directory" >&2
        exit 2
      fi
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "[fresh-clone-check] unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$DEST" ]]; then
  DEST="/tmp/dding-ctf-runner-fresh-$(date -u +%Y%m%d%H%M%S)-$$"
fi

LOG_DIR="$DEST/.fresh-clone-check/logs"
STATUS_FILE="$DEST/.fresh-clone-check/status.tsv"

cleanup() {
  if [[ "$KEEP_DIR" != "1" && -n "${DEST:-}" && -d "$DEST" ]]; then
    rm -rf "$DEST"
  fi
}
trap cleanup EXIT

if [[ "$(pwd -P)" == /mnt/c/* ]]; then
  echo "[fresh-clone-check] refusing to run from /mnt/c" >&2
  exit 1
fi

if [[ -e "$DEST" ]]; then
  echo "[fresh-clone-check] destination already exists: $DEST" >&2
  exit 1
fi

git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null
git clone -q "file://$ROOT" "$DEST"
mkdir -p "$LOG_DIR"
: > "$STATUS_FILE"

if [[ -z "${PYTHON:-}" && -x "$ROOT/.venv/bin/python" ]]; then
  export PYTHON="$ROOT/.venv/bin/python"
fi

patch_file="$(mktemp)"
git -C "$ROOT" diff --binary HEAD > "$patch_file"
if [[ -s "$patch_file" ]]; then
  git -C "$DEST" apply "$patch_file"
fi
rm -f "$patch_file"

while IFS= read -r -d '' rel; do
  mkdir -p "$DEST/$(dirname "$rel")"
  cp -a "$ROOT/$rel" "$DEST/$rel"
done < <(git -C "$ROOT" ls-files -o --exclude-standard -z)

run_step() {
  local name="$1"
  shift
  local log="$LOG_DIR/$name.log"
  printf '[fresh-clone-check] %-24s' "$name"
  if (cd "$DEST" && "$@") >"$log" 2>&1; then
    printf 'ok\n'
    printf '%s\tok\n' "$name" >> "$STATUS_FILE"
    return 0
  fi
  printf 'failed\n'
  printf '%s\tfailed\n' "$name" >> "$STATUS_FILE"
  return 1
}

run_required() {
  if ! run_step "$@"; then
    if [[ "$KEEP_DIR" == "1" ]]; then
      echo "[fresh-clone-check] kept: $DEST"
    fi
    exit 1
  fi
}

summarize_json_log() {
  local name="$1"
  local log="$LOG_DIR/$name.log"
  python3 - "$name" "$log" <<'PY'
import json
import sys
from pathlib import Path

name = sys.argv[1]
path = Path(sys.argv[2])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    print({"step": name, "json": "unavailable"})
    raise SystemExit(0)
summary = {"step": name, "status": data.get("status")}
if name == "preflight":
    risk = data.get("risk") or {}
    summary["High"] = list(risk.get("High") or [])
    summary["Medium"] = list(risk.get("Medium") or [])
for key in (
    "expected_met",
    "raw_leak_detected",
    "workers_requested",
    "accepted_submissions",
    "blocked_submissions",
    "duplicate_claims",
    "duplicate_submissions",
):
    if key in data:
        summary[key] = data.get(key)
print(summary)
PY
}

run_required git_status git status --short
run_required compileall python3 -m compileall -q ctf_runner
run_required pytest python3 -m pytest -q
run_required release_check ./scripts/release-check.sh
run_required preflight ./scripts/ctfctl preflight --deep --json
run_required fake_ctfd_smoke ./scripts/ctfctl fake-ctfd smoke --json
run_required local_e2e ./scripts/ctfctl worker local-e2e --workers 3 --solver mock --fake-ctfd --json

summarize_json_log preflight
summarize_json_log fake_ctfd_smoke
summarize_json_log local_e2e

if [[ "$KEEP_DIR" == "1" ]]; then
  echo "[fresh-clone-check] kept: $DEST"
fi
echo "[fresh-clone-check] ok"
