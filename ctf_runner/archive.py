from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO


DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
DEFAULT_MAX_SINGLE_FILE_BYTES = 100 * 1024 * 1024
_COPY_CHUNK = 1024 * 1024
_REPORT_LIMIT = 200
_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".gz",
    ".7z",
    ".rar",
    ".bz2",
    ".xz",
)


@dataclass(frozen=True)
class ArchiveLimits:
    max_files: int = DEFAULT_MAX_FILES
    max_total_uncompressed_bytes: int = DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES
    max_single_file_bytes: int = DEFAULT_MAX_SINGLE_FILE_BYTES

    @classmethod
    def from_value(cls, value: dict[str, Any] | None) -> "ArchiveLimits":
        if value is None:
            return cls()
        return cls(
            max_files=int(value.get("max_files", DEFAULT_MAX_FILES)),
            max_total_uncompressed_bytes=int(
                value.get("max_total_uncompressed_bytes", DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES)
            ),
            max_single_file_bytes=int(value.get("max_single_file_bytes", DEFAULT_MAX_SINGLE_FILE_BYTES)),
        )


class _ExtractionState:
    def __init__(self, limits: ArchiveLimits) -> None:
        self.limits = limits
        self.files = 0
        self.total_bytes = 0
        self.skipped_entries: list[dict[str, str]] = []
        self.nested_archives: list[str] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def add_skip(self, path: str, reason: str) -> None:
        if len(self.skipped_entries) < _REPORT_LIMIT:
            self.skipped_entries.append({"path": path, "reason": reason})
        elif len(self.skipped_entries) == _REPORT_LIMIT:
            self.warnings.append("skipped_entries truncated")

    def add_nested(self, path: str) -> None:
        if len(self.nested_archives) < _REPORT_LIMIT:
            self.nested_archives.append(path)
        elif len(self.nested_archives) == _REPORT_LIMIT:
            self.warnings.append("nested_archives truncated")

    def can_add_file(self, path: str, size: int) -> bool:
        if self.files >= self.limits.max_files:
            self.add_skip(path, "max_files exceeded")
            return False
        if size > self.limits.max_single_file_bytes:
            self.add_skip(path, "max_single_file_bytes exceeded")
            return False
        if self.total_bytes + max(size, 0) > self.limits.max_total_uncompressed_bytes:
            self.add_skip(path, "max_total_uncompressed_bytes exceeded")
            return False
        return True

    def mark_file(self, size: int) -> None:
        self.files += 1
        self.total_bytes += max(size, 0)

    def result(self) -> dict[str, Any]:
        return {
            "extracted_files_count": self.files,
            "total_uncompressed_bytes": self.total_bytes,
            "skipped_entries": self.skipped_entries,
            "nested_archives": self.nested_archives,
            "warnings": self.warnings,
            "errors": self.errors,
        }


def is_archive_path(path: str | Path) -> bool:
    name = str(path).lower()
    return any(name.endswith(suffix) for suffix in _ARCHIVE_SUFFIXES)


def safe_extract_archive(archive_path: str | Path, dest_dir: str | Path, limits: dict[str, Any] | None = None) -> dict[str, Any]:
    """Safely extract supported archives without following archive-controlled links."""
    archive = Path(archive_path).expanduser().resolve()
    dest = Path(dest_dir).expanduser().resolve()
    dest.mkdir(parents=True, exist_ok=True)
    state = _ExtractionState(ArchiveLimits.from_value(limits))
    result: dict[str, Any] = {"archive": _display_path(archive), "destination": _display_path(dest)}

    try:
        lower_name = archive.name.lower()
        if lower_name.endswith(".zip"):
            _extract_zip(archive, dest, state)
        elif lower_name.endswith((".tar.gz", ".tgz", ".tar")):
            _extract_tar(archive, dest, state)
        elif lower_name.endswith(".gz"):
            _extract_gzip_file(archive, dest, state)
        elif lower_name.endswith(".7z"):
            _extract_7z(archive, dest, state)
        else:
            state.errors.append(f"unsupported archive type: {archive.name}")
    except (OSError, zipfile.BadZipFile, tarfile.TarError, gzip.BadGzipFile, subprocess.SubprocessError) as exc:
        state.errors.append(str(exc))

    result.update(state.result())
    return result


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _safe_relative_path(name: str) -> tuple[Path | None, str | None]:
    if "\x00" in name:
        return None, "NUL byte in path"
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or normalized.startswith("//"):
        return None, "absolute path entry"
    if len(normalized) >= 2 and normalized[1] == ":":
        return None, "drive-qualified path entry"
    pure = PurePosixPath(normalized)
    parts = [part for part in pure.parts if part not in ("", ".")]
    if any(part == ".." for part in parts):
        return None, "path traversal entry"
    if not parts:
        return None, "empty path entry"
    return Path(*parts), None


def _destination(dest: Path, relative: Path) -> Path:
    candidate = (dest / relative).resolve()
    if candidate == dest or dest not in candidate.parents:
        raise ValueError("resolved path escapes destination")
    return candidate


def _note_nested(path: str, state: _ExtractionState) -> None:
    if is_archive_path(path):
        state.add_nested(path)


def _copy_stream(source: BinaryIO, target: Path, expected_size: int, state: _ExtractionState, entry_name: str) -> None:
    if not state.can_add_file(entry_name, expected_size):
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with target.open("wb") as out:
        while True:
            chunk = source.read(_COPY_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > state.limits.max_single_file_bytes:
                out.close()
                target.unlink(missing_ok=True)
                state.add_skip(entry_name, "max_single_file_bytes exceeded while streaming")
                return
            if state.total_bytes + written > state.limits.max_total_uncompressed_bytes:
                out.close()
                target.unlink(missing_ok=True)
                state.add_skip(entry_name, "max_total_uncompressed_bytes exceeded while streaming")
                return
            out.write(chunk)
    state.mark_file(written)
    _note_nested(entry_name, state)


def _zipinfo_is_symlink(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def _extract_zip(archive: Path, dest: Path, state: _ExtractionState) -> None:
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            rel, reason = _safe_relative_path(info.filename)
            if rel is None:
                state.add_skip(info.filename, reason or "unsafe path")
                continue
            if info.is_dir():
                try:
                    _destination(dest, rel).mkdir(parents=True, exist_ok=True)
                except ValueError as exc:
                    state.add_skip(info.filename, str(exc))
                continue
            if info.flag_bits & 0x1:
                state.add_skip(info.filename, "encrypted zip entry")
                continue
            if _zipinfo_is_symlink(info):
                state.add_skip(info.filename, "symlink entry")
                continue
            try:
                target = _destination(dest, rel)
            except ValueError as exc:
                state.add_skip(info.filename, str(exc))
                continue
            with zf.open(info, "r") as src:
                _copy_stream(src, target, int(info.file_size), state, info.filename)


def _extract_tar(archive: Path, dest: Path, state: _ExtractionState) -> None:
    with tarfile.open(archive) as tf:
        for member in tf.getmembers():
            rel, reason = _safe_relative_path(member.name)
            if rel is None:
                state.add_skip(member.name, reason or "unsafe path")
                continue
            if member.isdir():
                try:
                    _destination(dest, rel).mkdir(parents=True, exist_ok=True)
                except ValueError as exc:
                    state.add_skip(member.name, str(exc))
                continue
            if member.issym() or member.islnk():
                state.add_skip(member.name, "symlink or hardlink entry")
                continue
            if not member.isfile():
                state.add_skip(member.name, f"unsupported tar member type {member.type!r}")
                continue
            try:
                target = _destination(dest, rel)
            except ValueError as exc:
                state.add_skip(member.name, str(exc))
                continue
            src = tf.extractfile(member)
            if src is None:
                state.add_skip(member.name, "unreadable tar member")
                continue
            with src:
                _copy_stream(src, target, int(member.size), state, member.name)


def _extract_gzip_file(archive: Path, dest: Path, state: _ExtractionState) -> None:
    output_name = archive.name[:-3] if archive.name.lower().endswith(".gz") else f"{archive.name}.out"
    rel, reason = _safe_relative_path(output_name)
    if rel is None:
        state.add_skip(output_name, reason or "unsafe gzip output name")
        return
    target = _destination(dest, rel)
    with gzip.open(archive, "rb") as src:
        _copy_stream(src, target, 0, state, output_name)


def _find_7z() -> str | None:
    return shutil.which("7z") or shutil.which("7za")


def _extract_7z(archive: Path, dest: Path, state: _ExtractionState) -> None:
    binary = _find_7z()
    if binary is None:
        state.errors.append("7z command not available")
        return
    listing = subprocess.run(
        [binary, "l", "-slt", str(archive)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if listing.returncode != 0:
        state.errors.append("7z listing failed")
        return
    entries = _parse_7z_listing(listing.stdout)
    for entry in entries:
        path = entry.get("Path", "")
        if not path or path == str(archive):
            continue
        rel, reason = _safe_relative_path(path)
        if rel is None:
            state.add_skip(path, reason or "unsafe path")
            state.errors.append("unsafe 7z path prevented extraction")
            return
        size = int(entry.get("Size") or 0)
        attributes = entry.get("Attributes", "").lower()
        if "l" in attributes:
            state.add_skip(path, "symlink entry")
            continue
        if not state.can_add_file(path, size):
            state.errors.append("7z limits prevented extraction")
            return
    with tempfile.TemporaryDirectory(prefix="ctf-ingest-7z-") as tmp:
        tmp_path = Path(tmp)
        extract = subprocess.run(
            [binary, "x", "-y", f"-o{tmp_path}", str(archive)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        if extract.returncode != 0:
            state.errors.append("7z extraction failed")
            return
        _copy_extracted_tree(tmp_path, dest, state)


def _parse_7z_listing(output: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        if key == "Path" and current.get("Path"):
            entries.append(current)
            current = {}
        current[key] = value
    if current:
        entries.append(current)
    return entries


def _copy_extracted_tree(src_root: Path, dest: Path, state: _ExtractionState) -> None:
    for root, dirs, files in os.walk(src_root, followlinks=False):
        root_path = Path(root)
        safe_dirs = []
        for dirname in dirs:
            dir_path = root_path / dirname
            rel_name = dir_path.relative_to(src_root).as_posix()
            if dir_path.is_symlink():
                state.add_skip(rel_name, "symlink directory entry")
                continue
            safe_dirs.append(dirname)
        dirs[:] = safe_dirs
        for filename in files:
            src = root_path / filename
            rel_name = src.relative_to(src_root).as_posix()
            if src.is_symlink():
                state.add_skip(rel_name, "symlink file entry")
                continue
            rel, reason = _safe_relative_path(rel_name)
            if rel is None:
                state.add_skip(rel_name, reason or "unsafe path")
                continue
            size = src.stat().st_size
            try:
                target = _destination(dest, rel)
            except ValueError as exc:
                state.add_skip(rel_name, str(exc))
                continue
            with src.open("rb") as fh:
                _copy_stream(fh, target, size, state, rel_name)
