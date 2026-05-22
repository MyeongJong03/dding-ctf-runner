#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
APPLY=0
REMOVE_LEGACY_DREAMHACK=0

usage() {
  cat >&2 <<'EOF'
usage: scripts/fix-codex-mcp.sh [--remove-legacy-dreamhack] [--apply]

Dry-runs by default. With --remove-legacy-dreamhack --apply, removes only the
legacy dreamhack_solver MCP entry from ~/.codex/config.toml and
~/.codex-workers/*/config.toml after creating per-file backups.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
      ;;
    --remove-legacy-dreamhack)
      REMOVE_LEGACY_DREAMHACK=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
  shift
done

cd "$REPO_ROOT"

export FIX_CODEX_MCP_APPLY="$APPLY"
export FIX_CODEX_MCP_REMOVE_LEGACY_DREAMHACK="$REMOVE_LEGACY_DREAMHACK"

python3 <<'PY'
from __future__ import annotations

import os
import time
import tomllib
from pathlib import Path

from ctf_runner.codex_doctor import LEGACY_DREAMHACK_MCP, detect_mcp_servers


def split_toml_key_path(raw: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in raw.strip():
        if quote:
            if quote == '"' and escaped:
                current.append(char)
                escaped = False
                continue
            if quote == '"' and char == "\\":
                escaped = True
                continue
            if char == quote:
                quote = None
                continue
            current.append(char)
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == ".":
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    parts.append("".join(current).strip())
    return [part for part in parts if part]


def section_path(line: str) -> list[str] | None:
    stripped = line.strip()
    if not stripped.startswith("["):
        return None
    if stripped.startswith("[["):
        end = stripped.find("]]")
        if end == -1:
            return None
        raw = stripped[2:end].strip()
    else:
        end = stripped.find("]")
        if end == -1:
            return None
        raw = stripped[1:end].strip()
    suffix = stripped[end + (2 if stripped.startswith("[[") else 1) :].strip()
    if suffix and not suffix.startswith("#"):
        return None
    return split_toml_key_path(raw)


def config_paths(home: Path) -> list[Path]:
    paths = [home / ".codex" / "config.toml"]
    workers = home / ".codex-workers"
    if workers.exists():
        paths.extend(sorted(path for path in workers.glob("*/config.toml") if path.is_file()))
    seen: set[str] = set()
    out: list[Path] = []
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def remove_with_tomlkit(text: str) -> tuple[str | None, str]:
    try:
        import tomlkit  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001 - optional dependency.
        return None, "tomlkit_unavailable"
    try:
        doc = tomlkit.parse(text)
    except Exception:  # noqa: BLE001 - keep output sanitized.
        return None, "tomlkit_parse_failed"
    servers = doc.get("mcp_servers")
    if servers is None or LEGACY_DREAMHACK_MCP not in servers:
        return text, "tomlkit"
    del servers[LEGACY_DREAMHACK_MCP]
    return tomlkit.dumps(doc), "tomlkit"


def remove_limited_sections(text: str) -> tuple[str, bool]:
    out: list[str] = []
    skip = False
    removed = False
    for line in text.splitlines(keepends=True):
        parts = section_path(line)
        if parts is not None:
            skip = len(parts) >= 2 and parts[0] == "mcp_servers" and parts[1] == LEGACY_DREAMHACK_MCP
            if skip:
                removed = True
                continue
        if skip:
            continue
        out.append(line)
    return "".join(out), removed


def plan_removal(text: str) -> tuple[str, str, bool]:
    rewritten, method = remove_with_tomlkit(text)
    if rewritten is not None:
        return rewritten, method, False

    rewritten, removed = remove_limited_sections(text)
    if not removed:
        return text, "manual_review_required", True
    try:
        tomllib.loads(rewritten)
    except tomllib.TOMLDecodeError:
        return text, "manual_review_required", True
    return rewritten, "limited_section_removal", False


def backup_path(path: Path, timestamp: str) -> Path:
    candidate = path.with_name(f"{path.name}.bak.{timestamp}")
    suffix = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.bak.{timestamp}.{suffix}")
        suffix += 1
    return candidate


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def main() -> int:
    apply = os.environ.get("FIX_CODEX_MCP_APPLY") == "1"
    remove_legacy = os.environ.get("FIX_CODEX_MCP_REMOVE_LEGACY_DREAMHACK") == "1"
    home = Path.home()
    timestamp = time.strftime("%Y%m%d%H%M%S")

    print(f"mode: {'apply' if apply else 'dry-run'}")
    print(f"remove_legacy_dreamhack: {yes_no(remove_legacy)}")
    for path in config_paths(home):
        print(f"config: {path}")
        if not path.exists():
            print("exists: no")
            print("found_server_names: <none>")
            print("would_remove: no")
            print("applied: no")
            print("backup_path: <none>")
            continue

        names = detect_mcp_servers(path)
        would_remove = remove_legacy and LEGACY_DREAMHACK_MCP in names
        print("exists: yes")
        print("found_server_names: " + (",".join(names) if names else "<none>"))
        print(f"would_remove: {yes_no(would_remove)}")

        if not would_remove:
            print("applied: no")
            print("backup_path: <none>")
            continue

        text = path.read_text(encoding="utf-8")
        rewritten, method, manual_review = plan_removal(text)
        print(f"method: {method}")
        print(f"manual_review_required: {yes_no(manual_review)}")
        if manual_review:
            print("applied: no")
            print("backup_path: <none>")
            continue
        if not apply:
            print("applied: no")
            print("backup_path: <none>")
            continue

        backup = backup_path(path, timestamp)
        backup.write_bytes(path.read_bytes())
        path.write_text(rewritten, encoding="utf-8")
        print("applied: yes")
        print(f"backup_path: {backup}")
    return 0


raise SystemExit(main())
PY
