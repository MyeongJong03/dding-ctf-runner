from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from glob import glob
from pathlib import Path
from typing import Any


_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
LEGACY_DREAMHACK_MCP = "dreamhack_solver"
CANONICAL_CTF_SOLVER_MCP = "ctf_solver"
REVA_MCP = "ReVa"


def _parse_semver(text: str) -> tuple[int, int, int]:
    match = _VERSION_RE.search(text or "")
    if not match:
        return (0, 0, 0)
    return tuple(int(part) for part in match.groups())


def _split_toml_key_path(raw: str) -> list[str]:
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


def _mcp_server_names_from_headers(text: str) -> list[str]:
    names: set[str] = set()
    header_re = re.compile(r"^\s*\[{1,2}\s*(?P<header>[^\]]+?)\s*\]{1,2}\s*(?:#.*)?$")
    for line in text.splitlines():
        match = header_re.match(line)
        if not match:
            continue
        parts = _split_toml_key_path(match.group("header"))
        if len(parts) >= 2 and parts[0] == "mcp_servers":
            names.add(parts[1])
    return sorted(names)


def detect_mcp_servers(config_path: str | Path) -> list[str]:
    """Return configured MCP server names without exposing command args or env."""
    path = Path(config_path).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="replace")

    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return _mcp_server_names_from_headers(text)

    servers = parsed.get("mcp_servers", {})
    if isinstance(servers, dict):
        return sorted(str(name) for name in servers)
    return _mcp_server_names_from_headers(text)


def _worker_mcp_config_paths(home: Path) -> list[Path]:
    root = home / ".codex-workers"
    if not root.exists():
        return []
    return sorted(path for path in root.glob("*/config.toml") if path.is_file())


def diagnose_mcp_legacy(home: str | Path | None = None) -> dict[str, Any]:
    home_path = Path(home).expanduser() if home is not None else Path.home()
    global_config = home_path / ".codex" / "config.toml"
    global_servers = detect_mcp_servers(global_config)
    worker_servers = [
        {"path": str(path), "servers": detect_mcp_servers(path)}
        for path in _worker_mcp_config_paths(home_path)
    ]
    all_names = set(global_servers)
    for worker in worker_servers:
        all_names.update(worker["servers"])

    legacy_worker_paths = [
        worker["path"]
        for worker in worker_servers
        if LEGACY_DREAMHACK_MCP in worker["servers"]
    ]
    legacy_present = LEGACY_DREAMHACK_MCP in global_servers or bool(legacy_worker_paths)
    canonical_present = CANONICAL_CTF_SOLVER_MCP in all_names
    reva_present = REVA_MCP in all_names

    if legacy_present:
        recommended_action = "run scripts/fix-codex-mcp.sh --remove-legacy-dreamhack --apply after reviewing the dry-run"
    elif not canonical_present:
        recommended_action = "no legacy MCP present; ctf_solver MCP is absent, which is acceptable for the shell-first runner"
    else:
        recommended_action = "no legacy MCP cleanup needed"

    return {
        "global_config": str(global_config),
        "global_servers": global_servers,
        "worker_servers": worker_servers,
        "legacy_dreamhack_present": legacy_present,
        "legacy_dreamhack_global": LEGACY_DREAMHACK_MCP in global_servers,
        "legacy_dreamhack_worker_paths": legacy_worker_paths,
        "canonical_ctf_solver_present": canonical_present,
        "reva_present": reva_present,
        "recommended_action": recommended_action,
    }


def _path_entries() -> list[str]:
    seen: set[str] = set()
    entries: list[str] = []
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        item = raw.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        entries.append(item)
    return entries


def _path_rank(path: str) -> int:
    parent = str(Path(path).expanduser().resolve().parent)
    try:
        return _path_entries().index(parent)
    except ValueError:
        return 10_000


def _shell_alias_status() -> dict[str, Any]:
    shell = os.environ.get("SHELL") or "/bin/bash"
    probe = "alias codex"
    shell_args = [shell, "-ic", probe] if Path(shell).name in {"bash", "zsh"} else [shell, "-lc", probe]
    try:
        proc = subprocess.run(
            shell_args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return {"detected": False, "error": str(exc)}
    if proc.returncode != 0:
        return {"detected": False, "definition": ""}
    return {"detected": True, "definition": proc.stdout.strip()}


def _candidate_paths() -> list[Path]:
    candidates: list[Path] = []
    home = Path.home()
    patterns = [
        home / ".local/bin/codex",
        home / ".npm-global/bin/codex",
        home / ".nvm/versions/node/*/bin/codex",
        Path("/usr/local/bin/codex"),
        Path("/usr/bin/codex"),
    ]
    seen: set[str] = set()
    for pattern in patterns:
        if "*" in str(pattern):
            paths = [Path(item) for item in sorted(glob(str(pattern)))]
        else:
            paths = [pattern]
        for path in paths:
            if not path.exists():
                continue
            resolved = str(path)
            if resolved in seen:
                continue
            seen.add(resolved)
            candidates.append(path)
    which = shutil.which("codex")
    if which and which not in seen:
        candidates.insert(0, Path(which))
    return candidates


def _read_candidate(path: Path) -> dict[str, Any]:
    raw_version = ""
    version = ""
    try:
        proc = subprocess.run(
            [str(path), "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
        )
        raw_version = (proc.stdout or "").strip().splitlines()[0] if (proc.stdout or "").strip() else ""
        version = _VERSION_RE.search(raw_version).group(0) if _VERSION_RE.search(raw_version) else ""
    except Exception as exc:  # noqa: BLE001
        raw_version = f"error: {exc}"
    resolved = path.resolve() if path.exists() else path
    file_kind = ""
    try:
        proc = subprocess.run(
            ["file", str(path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        file_kind = (proc.stdout or "").strip()
    except Exception:  # noqa: BLE001
        file_kind = ""
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        "version_text": raw_version,
        "version": version,
        "semver": _parse_semver(version or raw_version),
        "path_rank": _path_rank(str(path)),
        "in_path": _path_rank(str(path)) != 10_000,
        "exists": path.exists(),
        "file_kind": file_kind,
    }


def detect_codex_candidates() -> list[dict[str, Any]]:
    return [_read_candidate(path) for path in _candidate_paths()]


def choose_preferred_codex_binary() -> dict[str, Any]:
    override = os.environ.get("CTF_CODEX_BIN", "").strip()
    candidates = detect_codex_candidates()
    if override:
        override_path = Path(override).expanduser()
        preferred = _read_candidate(override_path)
        preferred["selected_reason"] = "env_override"
        return preferred
    if not candidates:
        return {
            "path": "",
            "resolved_path": "",
            "version_text": "",
            "version": "",
            "semver": (0, 0, 0),
            "path_rank": 10_000,
            "in_path": False,
            "exists": False,
            "file_kind": "",
            "selected_reason": "missing",
        }
    preferred = max(candidates, key=lambda item: (item["semver"][0], item["semver"][1], item["semver"][2], -item["path_rank"]))
    preferred = dict(preferred)
    preferred["selected_reason"] = "highest_semver_then_path"
    return preferred


def _stale_codex_binaries(candidates: list[dict[str, Any]], preferred: dict[str, Any]) -> list[dict[str, Any]]:
    preferred_semver = preferred.get("semver", (0, 0, 0))
    preferred_path = preferred.get("path", "")
    stale: list[dict[str, Any]] = []
    for item in candidates:
        semver = item.get("semver", (0, 0, 0))
        if not item.get("path") or item["path"] == preferred_path:
            continue
        if semver == (0, 0, 0) or semver >= preferred_semver:
            continue
        path = Path(item["path"])
        stale.append(
            {
                "path": item["path"],
                "version": item.get("version", ""),
                "preferred_version": preferred.get("version", ""),
                "is_symlink": path.is_symlink(),
                "file_kind": item.get("file_kind", ""),
            }
        )
    return stale


def diagnose_codex_update_issue() -> dict[str, Any]:
    candidates = detect_codex_candidates()
    preferred = choose_preferred_codex_binary()
    active = _read_candidate(Path(shutil.which("codex"))) if shutil.which("codex") else None
    alias = _shell_alias_status()
    env_override = bool(os.environ.get("CTF_CODEX_BIN", "").strip())
    candidate_versions = {item["path"]: item["version"] for item in candidates}
    stale_binaries = _stale_codex_binaries(candidates, preferred)
    path_conflict = bool(
        not env_override
        and active
        and preferred["path"]
        and active["resolved_path"] != preferred["resolved_path"]
    )
    update_mismatch = bool(
        not env_override
        and active
        and preferred["semver"] > active["semver"]
    )
    hints: list[str] = []
    if env_override:
        hints.append("CTF_CODEX_BIN explicitly selects the runner codex binary")
    if alias.get("detected"):
        hints.append("interactive shell alias may bypass PATH-selected codex binary")
    if path_conflict:
        hints.append("PATH resolves a different codex binary than the preferred newest candidate")
    if update_mismatch:
        hints.append("a newer codex install exists, but the active PATH binary is older")
    if active and active["path"].startswith(str(Path.home() / ".local/bin")) and any(
        item["path"].startswith(str(Path.home() / ".npm-global/bin")) and item["semver"] > active["semver"] for item in candidates
    ):
        hints.append("npm/global codex appears newer than ~/.local/bin, so shell order likely keeps running the older install")
    if not hints:
        hints.append("no obvious codex update mismatch detected")
    return {
        "active_binary": active,
        "preferred_binary": preferred,
        "candidates": candidates,
        "candidate_versions": candidate_versions,
        "stale_binary_present": bool(stale_binaries),
        "stale_binaries": stale_binaries,
        "alias_detected": alias.get("detected", False),
        "alias_definition": alias.get("definition", ""),
        "path_conflict": path_conflict,
        "update_mismatch": update_mismatch,
        "update_hint": "; ".join(hints),
        "env_override": env_override,
    }
