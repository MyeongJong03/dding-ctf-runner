#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

APPLY=0
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=1
elif [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
usage: scripts/fix-playwright-deps.sh [--apply]

Checks browser smoke and, with --apply, runs:
  .venv/bin/python -m playwright install-deps chromium

This may prompt for sudo. No secrets or browser storage are read.
EOF
  exit 0
fi

if [[ ! -f "$REPO_ROOT/pyproject.toml" || ! -d "$REPO_ROOT/ctf_runner" ]]; then
  echo "refusing to run outside a dding-ctf-runner checkout" >&2
  exit 1
fi
if [[ "$PWD" == /mnt/c/* ]]; then
  echo "refusing to run under /mnt/c" >&2
  exit 1
fi
if [[ ! -x .venv/bin/python ]]; then
  echo "missing .venv/bin/python; run scripts/setup-browser.sh first" >&2
  exit 1
fi

echo "Running current browser smoke."
SMOKE_JSON="$(./scripts/ctfctl browser smoke --json || true)"
echo "$SMOKE_JSON"
SMOKE_OK="$(printf '%s' "$SMOKE_JSON" | .venv/bin/python -c 'import json,sys; print(str(json.load(sys.stdin).get("ok", False)).lower())' 2>/dev/null || echo false)"
SMOKE_REASON="$(printf '%s' "$SMOKE_JSON" | .venv/bin/python -c 'import json,sys; print(json.load(sys.stdin).get("reason", ""))' 2>/dev/null || true)"

if [[ "$SMOKE_OK" == "true" ]]; then
  echo "browser smoke already passes; no dependency command needed"
  ./scripts/ctfctl preflight --deep --json
  exit 0
fi

if [[ "$SMOKE_REASON" != "browser_launch_failed" && "$SMOKE_REASON" != "browser_smoke_failed" ]]; then
  echo "browser smoke reason is '$SMOKE_REASON'; dependency install is not automatically applied"
  exit 1
fi

echo "Planned dependency command:"
echo ".venv/bin/python -m playwright install-deps chromium"

if [[ "$APPLY" -ne 1 ]]; then
  echo "dry-run: pass --apply to run the dependency command"
  exit 0
fi

echo "Applying Playwright Chromium system dependencies. This command may prompt for sudo."
set +e
.venv/bin/python -m playwright install-deps chromium
INSTALL_RC=$?
set -e

if [[ "$INSTALL_RC" -ne 0 ]]; then
  echo "dependency command failed with exit code $INSTALL_RC"
  echo "manual command to run from repo root:"
  echo ".venv/bin/python -m playwright install-deps chromium"
fi

./scripts/ctfctl browser smoke --json
./scripts/ctfctl preflight --deep --json
exit "$INSTALL_RC"
