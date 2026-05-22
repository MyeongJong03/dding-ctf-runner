from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

from .codex_profile import DEFAULT_WORKER_IDS, worker_home


NOTICE_TOKENS = ("notice", "notification", "announcement", "onboarding", "tips", "tip", "update")
SAFE_NOTICE_SUFFIXES = {".json", ".txt", ".toml", ".cache", ".db", ".sqlite", ""}
PROTECTED_FILENAMES = {"auth.json", "config.toml", "AGENTS.md"}
PROTECTED_DIRS = {"sessions", ".git"}
SKIP_DIRS = {"sessions", ".git", "plugins"}


def _mtime_iso(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")


def _file_meta(path: Path, home: Path) -> dict[str, Any]:
    st = path.stat()
    return {
        "path": str(path.relative_to(home)),
        "size_bytes": st.st_size,
        "mtime": _mtime_iso(path),
    }


def _walk_files(home: Path) -> list[Path]:
    if not home.exists():
        return []
    files: list[Path] = []
    for root, dirs, names in os.walk(home):
        root_path = Path(root)
        rel = root_path.relative_to(home)
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        if rel == Path(".tmp") and "plugins" in dirs:
            dirs.remove("plugins")
        for name in names:
            files.append(root_path / name)
    return files


def _is_protected(rel: Path) -> bool:
    if rel.name in PROTECTED_FILENAMES:
        return True
    return any(part in PROTECTED_DIRS for part in rel.parts)


def _notice_token(name: str) -> str:
    lower = name.lower()
    return next((token for token in NOTICE_TOKENS if token in lower), "")


def _is_safe_notice_candidate(path: Path, home: Path) -> bool:
    rel = path.relative_to(home)
    if _is_protected(rel):
        return False
    token = _notice_token(rel.name)
    if not token:
        return False
    if path.suffix.lower() not in SAFE_NOTICE_SUFFIXES:
        return False
    if token == "update" and not any(part.lower() in {"cache", ".cache"} for part in rel.parts[:-1]):
        return False
    return True


def _is_manual_review_candidate(path: Path, home: Path) -> bool:
    rel = path.relative_to(home)
    if _is_protected(rel):
        return False
    lower = str(rel).lower()
    if _is_safe_notice_candidate(path, home):
        return False
    if "cache" not in lower:
        return False
    return len(rel.parts) <= 2


def worker_notice_status(worker_id: str) -> dict[str, Any]:
    home = worker_home(worker_id)
    safe: list[dict[str, Any]] = []
    manual: list[dict[str, Any]] = []
    for path in _walk_files(home):
        try:
            if _is_safe_notice_candidate(path, home):
                safe.append(_file_meta(path, home))
            elif _is_manual_review_candidate(path, home):
                manual.append(_file_meta(path, home))
        except OSError:
            continue
    return {
        "worker_id": worker_id,
        "worker_home": str(home),
        "safe_notice_candidates": sorted(safe, key=lambda item: item["path"]),
        "manual_review_required": sorted(manual, key=lambda item: item["path"]),
    }


def notice_status(worker_id: str | None = None) -> dict[str, Any]:
    worker_ids = (worker_id,) if worker_id else DEFAULT_WORKER_IDS
    workers = [worker_notice_status(wid) for wid in worker_ids]
    return {"workers": workers}


def clear_notices(worker_id: str, apply: bool = False) -> dict[str, Any]:
    home = worker_home(worker_id)
    status = worker_notice_status(worker_id)
    deleted: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if apply:
        for item in status["safe_notice_candidates"]:
            path = home / item["path"]
            try:
                path.unlink()
                deleted.append(item)
            except OSError as exc:
                errors.append({"path": item["path"], "error": type(exc).__name__})
    return {
        "worker_id": worker_id,
        "dry_run": not apply,
        "safe_notice_candidates": status["safe_notice_candidates"],
        "manual_review_required": status["manual_review_required"],
        "deleted": deleted,
        "errors": errors,
    }
