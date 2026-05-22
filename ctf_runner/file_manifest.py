from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .archive import is_archive_path
from .redact import redact_text


PREVIEW_LIMIT_BYTES = 64 * 1024
LARGE_FILE_BYTES = 10 * 1024 * 1024
_HASH_CHUNK = 1024 * 1024
_FLAG_RE = re.compile(r"\b[A-Za-z0-9_]{2,32}\{[^{}\s]{4,256}\}")
_SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".s",
    ".scala",
    ".sh",
    ".sol",
    ".ts",
    ".tsx",
    ".wasm",
}
_CONFIG_NAMES = {
    ".env",
    "docker-compose.yml",
    "dockerfile",
    "gemfile",
    "go.mod",
    "package-lock.json",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "yarn.lock",
}
_CONFIG_EXTENSIONS = {".cfg", ".conf", ".ini", ".json", ".toml", ".yaml", ".yml", ".xml"}
_IMAGE_EXTENSIONS = {".bmp", ".gif", ".heic", ".ico", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"}
_AUDIO_EXTENSIONS = {".aac", ".flac", ".m4a", ".mid", ".mp3", ".ogg", ".wav"}
_VIDEO_EXTENSIONS = {".avi", ".m4v", ".mkv", ".mov", ".mp4", ".webm"}
_PCAP_EXTENSIONS = {".cap", ".pcap", ".pcapng"}
_DOCUMENT_EXTENSIONS = {".doc", ".docx", ".md", ".odt", ".pdf", ".ppt", ".pptx", ".rtf", ".xls", ".xlsx"}
_TEXT_EXTENSIONS = {".csv", ".log", ".md", ".rst", ".txt"}
_SENSITIVE_NAMES = {
    ".bash_history",
    ".env",
    "auth.json",
    "config.toml",
    "cookies.txt",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
    "storage_state.json",
}
_SENSITIVE_NAME_MARKERS = ("cookie", "token", "password", "passwd", "secret", "private_key", "apikey", "api_key")


def build_manifest(root_dir: str | Path) -> dict[str, Any]:
    root = Path(root_dir).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(str(root))

    files: list[dict[str, Any]] = []
    git_repositories: list[dict[str, Any]] = []
    for current, dirs, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        if ".git" in dirs:
            git_path = current_path / ".git"
            git_repositories.append(_summarize_git(root, git_path))
            dirs.remove(".git")
        for filename in sorted(filenames):
            path = current_path / filename
            rel = path.relative_to(root).as_posix()
            files.append(_manifest_entry(root, path, rel))

    summary = _summarize(files)
    return {
        "root_dir": _display_path(root),
        "file_count": len(files),
        "summary": summary,
        "git": {
            "repositories": git_repositories,
            "present": bool(git_repositories),
        },
        "files": files,
    }


def redact_ingest_text(text: str) -> str:
    text = _FLAG_RE.sub("[REDACTED_FLAG]", text)
    return redact_text(text)


def is_sensitive_path(path: str | Path) -> bool:
    parts = [part.lower() for part in Path(path).parts]
    for part in parts:
        if part in _SENSITIVE_NAMES:
            return True
        if any(marker in part for marker in _SENSITIVE_NAME_MARKERS):
            return True
        if part.endswith((".pem", ".key", ".p12", ".pfx")):
            return True
    return False


def _manifest_entry(root: Path, path: Path, rel: str) -> dict[str, Any]:
    extension = _extension(path)
    reasons: list[str] = []
    detected_type = ""
    readable_text = False
    preview = None
    sha256 = None
    size = 0
    sensitive = is_sensitive_path(rel)

    if path.is_symlink():
        category = "unknown"
        reasons.append("symlink not followed")
        return {
            "path": rel,
            "size": 0,
            "extension": extension,
            "detected_type": "symlink",
            "sha256": None,
            "category": category,
            "readable_text": False,
            "is_large": False,
            "interesting_score": 1,
            "reasons": reasons,
            "preview": None,
        }

    try:
        stat = path.stat()
        size = stat.st_size
        if sensitive:
            detected_type = _extension_detected_type(path)
            reasons.append("sensitive-name content hash and type sniff disabled")
        else:
            sha256 = _sha256(path)
            detected_type = _detect_type(path)
    except OSError as exc:
        reasons.append(f"metadata error: {exc}")
        detected_type = "unreadable"

    category = _categorize(path, detected_type)
    readable_text = _is_textual(category, detected_type)
    is_large = size > LARGE_FILE_BYTES
    if is_archive_path(rel):
        reasons.append("archive candidate")
    if is_large:
        reasons.append("large file")
    if path.name.lower() in {"package.json", "requirements.txt", "dockerfile", "docker-compose.yml", "go.mod", "pom.xml"}:
        reasons.append("dependency or runtime descriptor")
    if "elf" in detected_type.lower():
        reasons.append("ELF binary")
    if category == "shared_library":
        reasons.append("shared library")
    if path.name.lower() in {"libc.so.6", "ld-linux-x86-64.so.2"}:
        reasons.append("runtime library candidate")
    if path.name.lower() == "readme.md":
        reasons.append("readme")
    if sensitive:
        reasons.append("sensitive-name content preview disabled")
    if readable_text and size <= PREVIEW_LIMIT_BYTES and not sensitive:
        preview = _read_preview(path)

    score = _interesting_score(path, category, reasons, size)
    return {
        "path": rel,
        "size": size,
        "extension": extension,
        "detected_type": detected_type,
        "sha256": sha256,
        "category": category,
        "readable_text": readable_text,
        "is_large": is_large,
        "interesting_score": score,
        "reasons": reasons,
        "preview": preview,
    }


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _extension(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".tar.gz"):
        return ".tar.gz"
    return path.suffix.lower()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _detect_type(path: Path) -> str:
    if shutil.which("file"):
        try:
            result = subprocess.run(
                ["file", "-b", str(path)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if result.stdout.strip():
                return result.stdout.strip()[:500]
        except (OSError, subprocess.SubprocessError):
            pass
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or "unknown"


def _extension_detected_type(path: Path) -> str:
    guessed, _ = mimetypes.guess_type(path.name)
    return guessed or "sensitive-name"


def _categorize(path: Path, detected_type: str) -> str:
    lower_type = detected_type.lower()
    ext = _extension(path)
    name = path.name.lower()
    if is_archive_path(path):
        return "archive"
    if "shared object" in lower_type or ext == ".so" or ".so." in name or name.startswith("libc-"):
        return "shared_library"
    if "elf" in lower_type or "pe32" in lower_type or ext in {".exe", ".dll"}:
        return "binary"
    if ext in _IMAGE_EXTENSIONS or lower_type.startswith("image/") or " image data" in lower_type:
        return "image"
    if ext in _AUDIO_EXTENSIONS or lower_type.startswith("audio/"):
        return "audio"
    if ext in _VIDEO_EXTENSIONS or lower_type.startswith("video/"):
        return "video"
    if ext in _PCAP_EXTENSIONS or "capture file" in lower_type or "pcap" in lower_type:
        return "pcap"
    if ext in _DOCUMENT_EXTENSIONS or "pdf document" in lower_type:
        return "document"
    if ext in _SOURCE_EXTENSIONS:
        return "source"
    if name in _CONFIG_NAMES or ext in _CONFIG_EXTENSIONS:
        return "config"
    if ext in _TEXT_EXTENSIONS or "text" in lower_type or "json" in lower_type or "xml" in lower_type:
        return "text"
    return "unknown"


def _is_textual(category: str, detected_type: str) -> bool:
    lower_type = detected_type.lower()
    return category in {"source", "config", "text"} or "text" in lower_type or "json" in lower_type


def _read_preview(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if len(data) > PREVIEW_LIMIT_BYTES:
        data = data[:PREVIEW_LIMIT_BYTES]
    return redact_ingest_text(data.decode("utf-8", errors="replace"))


def _interesting_score(path: Path, category: str, reasons: list[str], size: int) -> int:
    score = 0
    name = path.name.lower()
    if category in {"source", "config"}:
        score += 4
    if category in {"binary", "shared_library", "archive", "pcap"}:
        score += 5
    if category in {"image", "audio", "video", "document"}:
        score += 2
    if name in {"package.json", "requirements.txt", "dockerfile", "docker-compose.yml", "go.mod", "pom.xml"}:
        score += 4
    if name.startswith("libc") or name.startswith("ld-"):
        score += 4
    if name in {"app.py", "server.js", "index.js", "main.py", "main.c", "chall", "challenge"}:
        score += 3
    if "large file" in reasons:
        score -= 1
    if size == 0:
        score -= 1
    return max(score, 0)


def _summarize(files: list[dict[str, Any]]) -> dict[str, Any]:
    by_category: dict[str, int] = {}
    total_size = 0
    large_files = 0
    for item in files:
        by_category[item["category"]] = by_category.get(item["category"], 0) + 1
        total_size += int(item.get("size") or 0)
        if item.get("is_large"):
            large_files += 1
    return {
        "total_size": total_size,
        "by_category": by_category,
        "large_files": large_files,
    }


def _summarize_git(root: Path, git_path: Path) -> dict[str, Any]:
    rel = git_path.relative_to(root).as_posix()
    objects = git_path / "objects"
    has_commit_objects = False
    if objects.is_dir():
        try:
            for child in objects.iterdir():
                if not child.is_dir() or len(child.name) != 2:
                    continue
                if any(grandchild.is_file() for grandchild in child.iterdir()):
                    has_commit_objects = True
                    break
        except OSError:
            has_commit_objects = False
    return {
        "path": rel,
        "head_exists": (git_path / "HEAD").exists(),
        "commit_object_exists": has_commit_objects,
    }
