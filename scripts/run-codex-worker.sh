#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
USER_HOME="${HOME}"

DRY_RUN=1
if [[ "${1:-}" == "--run" ]]; then
  DRY_RUN=0
  shift
elif [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  shift
fi

WORKER_ID="${1:-}"
MODE="${2:-interactive}"
PROMPT="${3:-}"

if [[ -z "$WORKER_ID" || "$MODE" == "-h" || "$MODE" == "--help" ]]; then
  cat <<'EOF'
usage:
  scripts/run-codex-worker.sh [--dry-run|--run] worker-1 interactive
  scripts/run-codex-worker.sh [--dry-run|--run] worker-1 exec '<prompt file or prompt text>'

Default is --dry-run to avoid accidental model calls.
EOF
  exit 0
fi

if [[ "$MODE" != "interactive" && "$MODE" != "exec" ]]; then
  echo "mode must be interactive or exec" >&2
  exit 2
fi
if [[ "$MODE" == "exec" && -z "$PROMPT" ]]; then
  echo "exec mode requires a prompt file or prompt text" >&2
  exit 2
fi

cd "$REPO_ROOT"
if [[ ! -f "$REPO_ROOT/pyproject.toml" || ! -d "$REPO_ROOT/ctf_runner" ]]; then
  echo "refusing to run outside a dding-ctf-runner checkout" >&2
  exit 1
fi
if [[ "$PWD" == /mnt/c/* ]]; then
  echo "refusing to run under /mnt/c" >&2
  exit 1
fi

./scripts/ctfctl codex status --worker-id "$WORKER_ID"
./scripts/ctfctl codex launch-cmd --worker-id "$WORKER_ID" --mode "$MODE"

export CODEX_HOME="$USER_HOME/.codex-workers/$WORKER_ID"
if [[ ! -d "$CODEX_HOME" || ! -f "$CODEX_HOME/AGENTS.md" ]]; then
  echo "worker home is not initialized; run scripts/init-codex-workers.sh first" >&2
  exit 1
fi

resolve_codex_bin() {
  if [[ -n "${CTF_CODEX_BIN:-}" ]]; then
    printf '%s\n' "${CTF_CODEX_BIN}"
    return 0
  fi
  local preferred
  preferred="$(./scripts/ctfctl codex preferred-bin --json | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get("path",""))')"
  if [[ -n "$preferred" ]]; then
    printf '%s\n' "$preferred"
    return 0
  fi
  type -P codex 2>/dev/null || true
}

CODEX_BIN="$(resolve_codex_bin)"
if [[ -z "$CODEX_BIN" || ! -e "$CODEX_BIN" ]]; then
  echo "codex binary not found" >&2
  exit 1
fi

expand_path() {
  local raw="$1"
  if [[ "$raw" == "~" ]]; then
    printf '%s\n' "$USER_HOME"
    return
  fi
  if [[ "$raw" == ~/* ]]; then
    printf '%s\n' "$USER_HOME/${raw#~/}"
    return
  fi
  printf '%s\n' "$raw"
}

declare -a ADD_DIRS=()
add_dir_once() {
  local candidate="$1"
  local existing
  [[ -n "$candidate" ]] || return 0
  for existing in "${ADD_DIRS[@]:-}"; do
    if [[ "$existing" == "$candidate" ]]; then
      return 0
    fi
  done
  ADD_DIRS+=("$candidate")
}

add_dir_once "$REPO_ROOT"
add_dir_once "$USER_HOME/CTF"
add_dir_once "$USER_HOME/.ctf-solver"
add_dir_once "$USER_HOME/.codex-workers"

if [[ -n "${CTF_CODEX_EXTRA_ADD_DIRS:-}" ]]; then
  IFS=':' read -r -a EXTRA_ADD_DIRS <<< "${CTF_CODEX_EXTRA_ADD_DIRS}"
  for extra_dir in "${EXTRA_ADD_DIRS[@]}"; do
    add_dir_once "$(expand_path "$extra_dir")"
  done
fi

APPROVAL_POLICY="${CTF_CODEX_APPROVAL:-never}"
SANDBOX_MODE="${CTF_CODEX_SANDBOX:-}"
normalize_codex_model() {
  local raw="${1:-}"
  local lowered
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  lowered="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  if [[ -z "$raw" || "$lowered" == "auto" ]]; then
    printf ''
    return 0
  fi
  printf '%s' "$raw"
}
CODEX_MODEL="$(normalize_codex_model "${CTF_CODEX_MODEL-}")"
DANGER_MODE=1
if [[ "${CTF_CODEX_DANGER:-1}" == "0" ]]; then
  DANGER_MODE=0
fi

declare -a CODEX_ARGS=()
if [[ -n "$CODEX_MODEL" ]]; then
  CODEX_ARGS+=("--model" "$CODEX_MODEL")
fi
CODEX_ARGS+=("--ask-for-approval" "$APPROVAL_POLICY")
if [[ "$DANGER_MODE" -eq 1 ]]; then
  EFFECTIVE_SANDBOX="danger-full-access"
else
  if [[ -z "$SANDBOX_MODE" ]]; then
    SANDBOX_MODE="workspace-write"
  fi
  EFFECTIVE_SANDBOX="$SANDBOX_MODE"
fi
MODEL_LABEL="${CODEX_MODEL:-auto/unpinned}"
echo "[warn] competition worker uses model=$MODEL_LABEL approval=$APPROVAL_POLICY sandbox=$EFFECTIVE_SANDBOX" >&2
CODEX_ARGS+=("--sandbox" "$EFFECTIVE_SANDBOX")

for add_dir in "${ADD_DIRS[@]}"; do
  CODEX_ARGS+=("--add-dir" "$add_dir")
done

if [[ "${CTF_CODEX_IGNORE_USER_CONFIG:-0}" == "1" ]]; then
  export HOME="$CODEX_HOME"
fi

declare -a FINAL_CMD=("$CODEX_BIN" "${CODEX_ARGS[@]}")
if [[ "$MODE" == "exec" ]]; then
  FINAL_CMD+=("exec" "$PROMPT")
fi

if [[ "$MODE" == "interactive" ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'dry-run command: cd %q && ' "$REPO_ROOT"
    printf '%q=%q ' "CODEX_HOME" "$CODEX_HOME"
    if [[ "${CTF_CODEX_IGNORE_USER_CONFIG:-0}" == "1" ]]; then
      printf '%q=%q ' "HOME" "$HOME"
    fi
    printf '%q ' "${FINAL_CMD[@]}"
    printf '\n'
    echo "dry-run: codex was not executed"
    exit 0
  fi
  exec "${FINAL_CMD[@]}"
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  printf 'dry-run command: cd %q && ' "$REPO_ROOT"
  printf '%q=%q ' "CODEX_HOME" "$CODEX_HOME"
  if [[ "${CTF_CODEX_IGNORE_USER_CONFIG:-0}" == "1" ]]; then
    printf '%q=%q ' "HOME" "$HOME"
  fi
  printf '%q ' "${FINAL_CMD[@]}"
  printf '\n'
  echo "dry-run: codex was not executed"
  exit 0
fi

exec "${FINAL_CMD[@]}"
