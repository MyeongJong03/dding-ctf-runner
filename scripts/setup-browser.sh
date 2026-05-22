#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$REPO_ROOT" == /mnt/c/* ]]; then
  echo "Refusing to set up browser tooling under /mnt/c. Move the repo to WSL ext4 first."
  exit 1
fi

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install pytest playwright
.venv/bin/python -m playwright install chromium

echo "If Chromium reports missing system dependencies, review docs/setup-windows-wsl.md and install them manually."
.venv/bin/python -m pytest -q
PATH="$REPO_ROOT/.venv/bin:$PATH" ./scripts/ctfctl browser smoke --json
