#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

echo "Checking tunnel provider availability only. No public tunnel will be started."
./scripts/ctfctl tunnel check --json

missing=()
for candidate in cloudflared bore ngrok lt localtunnel; do
  if ! command -v "$candidate" >/dev/null 2>&1; then
    missing+=("$candidate")
  fi
done

if (( ${#missing[@]} > 0 )); then
  echo "Missing tunnel candidates: ${missing[*]}"
  echo "Manual install helpers:"
  echo "  cloudflared: see docs/setup-windows-wsl.md for the Cloudflare apt repository commands"
  echo "  bore: cargo install bore-cli"
  echo "See docs/setup-windows-wsl.md for public tunnel cautions and token handling notes."
fi
