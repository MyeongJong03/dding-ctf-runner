#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
APPLY=0

if [[ "${1:-}" == "--apply" ]]; then
  APPLY=1
  shift
fi

if [[ $# -ne 0 ]]; then
  echo "usage: scripts/fix-codex-shell.sh [--apply]" >&2
  exit 2
fi

cd "$REPO_ROOT"
PREFERRED_BIN="$(./scripts/ctfctl codex preferred-bin --json | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get("path",""))')"
if [[ -z "$PREFERRED_BIN" ]]; then
  echo "preferred codex binary not found" >&2
  exit 1
fi

BASHRC="${HOME}/.bashrc"
START_MARKER="# >>> dding-ctf-runner codex aliases >>>"
END_MARKER="# <<< dding-ctf-runner codex aliases <<<"

redact_line() {
  printf '%s\n' "$1" | sed -E \
    -e 's/(Bearer|bearer)[[:space:]]+[A-Za-z0-9._~+\/=-]+/\1 [REDACTED]/g' \
    -e 's/((token|cookie|authorization|password|session|secret)[[:space:]]*[:=][[:space:]]*)[^ "'\'';]+/\1[REDACTED]/Ig'
}

detect_existing() {
  if [[ ! -f "$BASHRC" ]]; then
    return 0
  fi
  python3 - "$BASHRC" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
    lower = line.lower()
    if "alias codex=" in lower or "ctf-worker-" in lower or "ctf_codex_bin" in lower:
        print(f"{idx}:{line}")
PY
}

EXISTING_LINES="$(detect_existing || true)"
EXISTING_ALIAS_COUNT="$(printf '%s\n' "$EXISTING_LINES" | rg -c 'alias codex=' || true)"

echo "bashrc: $BASHRC"
echo "preferred_codex_bin: $PREFERRED_BIN"
if [[ -n "$EXISTING_LINES" ]]; then
  echo "detected existing codex-related lines:"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    redact_line "$line"
  done <<< "$EXISTING_LINES"
else
  echo "detected existing codex-related lines: none"
fi
if [[ "${EXISTING_ALIAS_COUNT:-0}" -gt 1 ]]; then
  echo "warning: multiple existing codex alias lines detected" >&2
fi

TMP_FILE="$(mktemp)"
cleanup() {
  rm -f "$TMP_FILE"
}
trap cleanup EXIT

python3 - "$BASHRC" "$TMP_FILE" "$PREFERRED_BIN" <<'PY'
from pathlib import Path
import sys

bashrc = Path(sys.argv[1])
tmp = Path(sys.argv[2])
preferred = sys.argv[3]
start = "# >>> dding-ctf-runner codex aliases >>>"
end = "# <<< dding-ctf-runner codex aliases <<<"
block = [
    start,
    f'export CTF_CODEX_BIN="{preferred}"',
    "alias ctf-runner='cd ~/dding-ctf-runner'",
    "alias ctf-worker-1='~/dding-ctf-runner/scripts/ctf-worker-1'",
    "alias ctf-worker-2='~/dding-ctf-runner/scripts/ctf-worker-2'",
    "alias ctf-worker-3='~/dding-ctf-runner/scripts/ctf-worker-3'",
    "alias ctf-worker-4='~/dding-ctf-runner/scripts/ctf-worker-4'",
    "alias ctf-worker-5='~/dding-ctf-runner/scripts/ctf-worker-5'",
    '# optional plain codex alias, preserving user\'s preference:',
    'alias codex="$CTF_CODEX_BIN -a never -s danger-full-access"',
    end,
]
text = bashrc.read_text(encoding="utf-8") if bashrc.exists() else ""
lines = text.splitlines()
out = []
inside = False
replaced = False
for line in lines:
    if line == start:
        inside = True
        replaced = True
        if out and out[-1] != "":
            out.append("")
        out.extend(block)
        continue
    if inside and line == end:
        inside = False
        continue
    if inside:
        continue
    out.append(line)
if not replaced:
    if out and out[-1] != "":
        out.append("")
    out.extend(block)
content = "\n".join(out).rstrip() + "\n"
tmp.write_text(content, encoding="utf-8")
PY

echo "planned block:"
sed -n '/^# >>> dding-ctf-runner codex aliases >>>$/,/^# <<< dding-ctf-runner codex aliases <<</p' "$TMP_FILE"

if [[ "$APPLY" -eq 0 ]]; then
  echo "dry-run only; no files changed"
  echo "run 'scripts/fix-codex-shell.sh --apply' to write after creating a backup"
  exit 0
fi

TIMESTAMP="$(date +%Y%m%d%H%M%S)"
BACKUP="${HOME}/.bashrc.bak.${TIMESTAMP}"
if [[ -f "$BASHRC" ]]; then
  cp "$BASHRC" "$BACKUP"
else
  : > "$BACKUP"
fi
cp "$TMP_FILE" "$BASHRC"
echo "backup created: $BACKUP"
echo "updated: $BASHRC"
echo "run 'source ~/.bashrc' manually in your shell"
