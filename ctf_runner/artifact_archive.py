from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any, Mapping

from .redact import redact_text


DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024
SENSITIVE_NAME_RE = re.compile(
    r"(auth\.json|storage[_-]?state|cookie|cookies|token|bearer|authorization|password|passwd|session|secret|private[_-]?key)",
    re.IGNORECASE,
)
SENSITIVE_CONTENT_RE = re.compile(
    rb"([A-Za-z0-9_]{2,32}\{[^{}\s]{4,256}\}|Bearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    rb"^\s*(authorization|cookie|set-cookie)\s*:|"
    rb"\b(token|password|passwd|secret|api[_-]?key|session)\s*[:=]\s*['\"]?[^'\"\s,}]+)",
    re.IGNORECASE | re.MULTILINE,
)
ARCHIVE_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}


def collect_artifacts(
    challenge_dir: str | Path,
    run_state: Mapping[str, Any] | None = None,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    include_large: bool = False,
) -> dict[str, Any]:
    root = Path(challenge_dir).expanduser().resolve()
    run_state = run_state or {}
    manifest: dict[str, Any] = {
        "status": "ok" if root.exists() else "missing",
        "challenge_dir": _display_path(root),
        "max_file_size": int(max_file_size),
        "include_large": bool(include_large),
        "files": [],
        "raw_attachments": [],
        "extracted": [],
        "exploits": [],
        "logs": [],
        "metadata_only": [],
        "skipped": [],
        "run_state": _safe_run_state(run_state),
    }
    if not root.exists():
        return manifest

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if _skip_tree(path, root):
            continue
        rel = path.relative_to(root).as_posix()
        item = _artifact_item(path, rel, max_file_size=max_file_size, include_large=include_large)
        manifest["files"].append(item)
        if item.get("metadata_only"):
            manifest["metadata_only"].append(item)
            continue
        if item.get("skipped"):
            manifest["skipped"].append(item)
            continue
        section = _section_for_rel(rel)
        if section:
            manifest[section].append(item)
    manifest["counts"] = {
        "files": len(manifest["files"]),
        "raw_attachments": len(manifest["raw_attachments"]),
        "extracted": len(manifest["extracted"]),
        "exploits": len(manifest["exploits"]),
        "logs": len(manifest["logs"]),
        "metadata_only": len(manifest["metadata_only"]),
        "skipped": len(manifest["skipped"]),
    }
    return _redact_object(manifest)


def archive_artifacts(
    challenge_dir: str | Path,
    destination: str | Path,
    *,
    mode: str = "copy",
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    include_large: bool = False,
    cleanup: bool = False,
) -> dict[str, Any]:
    if mode != "copy":
        raise ValueError("only copy mode is supported")
    if cleanup:
        raise ValueError("cleanup requires a future explicit destructive flag")

    root = Path(challenge_dir).expanduser().resolve()
    dest = _versioned_path(Path(destination).expanduser().resolve())
    manifest = collect_artifacts(root, {}, max_file_size=max_file_size, include_large=include_large)
    copied: list[dict[str, Any]] = []
    copy_root = dest / "files"
    copy_root.mkdir(parents=True, exist_ok=True)

    for item in manifest.get("files") or []:
        if not isinstance(item, Mapping):
            continue
        if item.get("metadata_only") or item.get("skipped"):
            continue
        rel = str(item.get("path") or "")
        if not rel or rel.startswith("../"):
            continue
        src = root / rel
        if not src.is_file():
            continue
        target = copy_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        copied.append({"path": rel, "archive_path": _display_path(target), "sha256": item.get("sha256"), "size": item.get("size")})

    archive_manifest = {
        "status": "ok",
        "archive_dir": _display_path(dest),
        "mode": mode,
        "copied_count": len(copied),
        "copied": copied,
        "source_manifest": manifest,
    }
    manifest_path = dest / "artifacts_manifest.json"
    manifest_path.write_text(redact_text(json.dumps(archive_manifest, indent=2, sort_keys=True)) + "\n", encoding="utf-8")
    archive_manifest["manifest_path"] = _display_path(manifest_path)
    return _redact_object(archive_manifest)


def _artifact_item(path: Path, rel: str, *, max_file_size: int, include_large: bool) -> dict[str, Any]:
    try:
        stat = path.stat()
    except OSError:
        return {"path": rel, "exists": False, "skipped": True, "reason": "stat_failed"}
    item: dict[str, Any] = {
        "path": redact_text(rel),
        "exists": True,
        "size": int(stat.st_size),
        "kind": _section_for_rel(rel) or "other",
    }
    if _sensitive_rel(rel):
        item.update({"metadata_only": True, "excluded_from_archive": True, "reason": "sensitive_filename"})
        return item
    if stat.st_size > max_file_size and not include_large:
        item.update({"skipped": True, "reason": "file_too_large"})
        return item
    digest = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                if SENSITIVE_CONTENT_RE.search(chunk):
                    item.update({"metadata_only": True, "excluded_from_archive": True, "reason": "sensitive_content"})
                    return item
                digest.update(chunk)
        item["sha256"] = digest.hexdigest()
    except OSError:
        item.update({"skipped": True, "reason": "read_failed"})
    return item


def _section_for_rel(rel: str) -> str | None:
    parts = rel.split("/")
    first = parts[0].lower() if parts else ""
    suffix = Path(rel).suffix.lower()
    name = Path(rel).name.lower()
    if first == "raw":
        return "raw_attachments"
    if first == "extracted":
        return "extracted"
    if first in {"logs", "log"} or suffix in {".log", ".jsonl"}:
        return "logs"
    if first in {"exploit", "exploits", "scripts"}:
        return "exploits"
    if name.startswith(("solve", "exploit", "poc")) and suffix in {".py", ".sh", ".js", ".c", ".cpp", ".rs", ".go"}:
        return "exploits"
    return None


def _skip_tree(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in ARCHIVE_SKIP_DIRS for part in rel_parts) or (bool(rel_parts) and rel_parts[0] == "postsolve")


def _sensitive_rel(rel: str) -> bool:
    return bool(SENSITIVE_NAME_RE.search(rel))


def _safe_run_state(run_state: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("challenge_id", "contest_id", "status", "worker_id", "run_mode", "target_kind")
    return {key: redact_text(str(run_state.get(key) or "")) for key in keys if run_state.get(key) not in (None, "")}


def _versioned_path(path: Path) -> Path:
    if not path.exists():
        return path
    index = 1
    while True:
        candidate = path.with_name(f"{path.name}.v{index}")
        if not candidate.exists():
            return candidate
        index += 1


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)
