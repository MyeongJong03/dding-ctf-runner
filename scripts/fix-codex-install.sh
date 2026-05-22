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
  echo "usage: scripts/fix-codex-install.sh [--apply]" >&2
  exit 2
fi

cd "$REPO_ROOT"

PREFERRED_BIN="${CTF_CODEX_BIN:-}"
if [[ -z "$PREFERRED_BIN" ]]; then
  PREFERRED_BIN="$(./scripts/ctfctl codex preferred-bin --json | python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get("path",""))')"
fi
if [[ -z "$PREFERRED_BIN" ]]; then
  echo "preferred codex binary not found" >&2
  exit 1
fi

export FIX_CODEX_APPLY="$APPLY"
export FIX_CODEX_PREFERRED_BIN="$PREFERRED_BIN"

python3 <<'PY'
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path


VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
START_MARKER = "# >>> dding-ctf-runner codex aliases >>>"
END_MARKER = "# <<< dding-ctf-runner codex aliases <<<"


def parse_semver(text: str) -> tuple[int, int, int]:
    match = VERSION_RE.search(text or "")
    if not match:
        return (0, 0, 0)
    return tuple(int(part) for part in match.groups())


def codex_version(path: Path) -> tuple[str, tuple[int, int, int]]:
    try:
        proc = subprocess.run(
            [str(path), "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 - summarize safely for operator review.
        return (f"error:{type(exc).__name__}", (0, 0, 0))
    text = (proc.stdout or "").strip().splitlines()[0] if (proc.stdout or "").strip() else ""
    match = VERSION_RE.search(text)
    return (match.group(0) if match else text, parse_semver(text))


def is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def is_openai_codex_symlink(path: Path) -> bool:
    if not path.is_symlink():
        return False
    try:
        return "node_modules/@openai/codex/" in str(path.resolve())
    except OSError:
        return False


def candidate_paths(home: Path) -> list[Path]:
    paths = [
        home / ".local/bin/codex",
        home / ".npm-global/bin/codex",
    ]
    for raw_dir in os.environ.get("PATH", "").split(os.pathsep):
        if raw_dir:
            paths.append(Path(raw_dir).expanduser() / "codex")
    seen: set[str] = set()
    out: list[Path] = []
    for path in paths:
        key = str(path)
        if key in seen or not path.exists():
            continue
        seen.add(key)
        out.append(path)
    return out


def bashrc_block(preferred: Path) -> list[str]:
    return [
        START_MARKER,
        f'export CTF_CODEX_BIN="{preferred}"',
        "alias ctf-runner='cd ~/dding-ctf-runner'",
        "alias ctf-worker-1='~/dding-ctf-runner/scripts/ctf-worker-1'",
        "alias ctf-worker-2='~/dding-ctf-runner/scripts/ctf-worker-2'",
        "alias ctf-worker-3='~/dding-ctf-runner/scripts/ctf-worker-3'",
        "alias ctf-worker-4='~/dding-ctf-runner/scripts/ctf-worker-4'",
        "alias ctf-worker-5='~/dding-ctf-runner/scripts/ctf-worker-5'",
        "# optional plain codex alias, preserving user's preference:",
        'alias codex="$CTF_CODEX_BIN -a never -s danger-full-access"',
        END_MARKER,
    ]


def planned_bashrc_text(path: Path, preferred: Path) -> str:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = text.splitlines()
    block = bashrc_block(preferred)
    out: list[str] = []
    inside = False
    replaced = False
    for line in lines:
        if line == START_MARKER:
            inside = True
            replaced = True
            if out and out[-1] != "":
                out.append("")
            out.extend(block)
            continue
        if inside and line == END_MARKER:
            inside = False
            continue
        if inside:
            continue
        out.append(line)
    if not replaced:
        if out and out[-1] != "":
            out.append("")
        out.extend(block)
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    apply = os.environ.get("FIX_CODEX_APPLY") == "1"
    home = Path.home()
    preferred = Path(os.environ["FIX_CODEX_PREFERRED_BIN"]).expanduser()
    preferred_version, preferred_semver = codex_version(preferred)
    timestamp = time.strftime("%Y%m%d%H%M%S")

    print(f"mode: {'apply' if apply else 'dry-run'}")
    print(f"preferred_codex_bin: {preferred}")
    print(f"preferred_version: {preferred_version or 'unknown'}")

    stale_items: list[dict[str, object]] = []
    for path in candidate_paths(home):
        if path.resolve() == preferred.resolve():
            continue
        version, semver = codex_version(path)
        stale = semver != (0, 0, 0) and semver < preferred_semver
        actionable = stale and is_under(path, home) and is_openai_codex_symlink(path)
        if stale:
            stale_items.append(
                {
                    "path": path,
                    "version": version,
                    "is_symlink": path.is_symlink(),
                    "openai_codex_symlink": is_openai_codex_symlink(path),
                    "actionable": actionable,
                }
            )

    if stale_items:
        print("stale_candidates:")
        for item in stale_items:
            path = item["path"]
            disabled = Path(path).with_name(f"{Path(path).name}.disabled.{timestamp}")
            action = f"rename_to={disabled}" if item["actionable"] else "review_only"
            print(
                f"- path={path} version={item['version']} "
                f"symlink={item['is_symlink']} openai_codex_symlink={item['openai_codex_symlink']} {action}"
            )
    else:
        print("stale_candidates: none")

    if apply:
        for item in stale_items:
            if not item["actionable"]:
                continue
            path = Path(item["path"])
            disabled = path.with_name(f"{path.name}.disabled.{timestamp}")
            path.rename(disabled)
            print(f"disabled_stale_symlink: {path} -> {disabled}")

    bashrc = home / ".bashrc"
    planned = planned_bashrc_text(bashrc, preferred)
    print("bashrc_block: will update CTF_CODEX_BIN and ctf-worker aliases" if apply else "bashrc_block: dry-run update planned")
    if apply:
        backup = home / f".bashrc.bak.{timestamp}"
        if bashrc.exists():
            backup.write_text(bashrc.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            backup.write_text("", encoding="utf-8")
        bashrc.write_text(planned, encoding="utf-8")
        print(f"bashrc_backup: {backup}")
        print(f"bashrc_updated: {bashrc}")
        print("next: run 'hash -r' and 'source ~/.bashrc' in your shell")
    else:
        print("dry-run only; no files changed")
        print("next: review candidates, then run scripts/fix-codex-install.sh --apply if appropriate")
    return 0


raise SystemExit(main())
PY
