from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from .archive import is_archive_path, safe_extract_archive
from .brief import render_challenge_brief
from .file_manifest import build_manifest, redact_ingest_text
from .paths import get_paths
from .source_scan import scan_source


def ingest_challenge(
    challenge_id: str,
    input_paths: list[str | Path],
    contest_id: str | None = None,
    category: str | None = None,
    name: str | None = None,
    output_root: str | Path | None = None,
) -> dict[str, Any]:
    if not input_paths:
        raise ValueError("at least one input path is required")
    challenge_slug = _safe_slug(challenge_id, "challenge_id")
    contest_slug = _safe_slug(contest_id or "manual", "contest_id")
    base = Path(output_root).expanduser().resolve() if output_root else get_paths().contests_root
    challenge_dir = (base / contest_slug / challenge_slug).resolve()
    raw_dir = challenge_dir / "raw"
    extracted_dir = challenge_dir / "extracted"
    manifest_dir = challenge_dir / "manifest"
    raw_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)

    input_summaries: list[dict[str, Any]] = []
    archive_summaries: list[dict[str, Any]] = []
    directory_inputs: list[str] = []
    scan_root: Path = challenge_dir

    for raw_input in input_paths:
        source = Path(raw_input).expanduser()
        if not source.exists():
            raise FileNotFoundError(str(source))
        source = source.resolve()
        if source.is_symlink():
            raise ValueError(f"refusing symlink input: {_display_path(source)}")
        if source.is_dir():
            directory_inputs.append(_display_path(source))
            input_summaries.append({"input": _display_path(source), "kind": "directory", "mode": "scan_in_place"})
            if len(input_paths) == 1:
                scan_root = source
            continue

        target = _copy_raw_file(source, raw_dir)
        input_summaries.append(
            {"input": _display_path(source), "kind": "file", "raw_copy": _display_path(target), "size": target.stat().st_size}
        )
        if is_archive_path(source):
            archive_dest = extracted_dir / _safe_slug(source.stem, "archive")
            archive_summary = safe_extract_archive(target, archive_dest, limits=None)
            archive_summaries.append(archive_summary)

    manifest = build_manifest(scan_root)
    scan_result = scan_source(_manifest_root_path(manifest, scan_root), manifest)
    metadata = {
        "challenge_id": challenge_slug,
        "contest_id": contest_slug,
        "name": name,
        "category": category,
        "inputs": input_summaries,
        "directory_inputs": directory_inputs,
        "archive_summaries": archive_summaries,
        "warnings": [],
    }
    if directory_inputs:
        metadata["warnings"].append("directory input scanned in place; raw directory copy was not created")
    brief = render_challenge_brief(challenge_dir, manifest, scan_result, metadata)

    manifest_path = manifest_dir / "manifest.json"
    scan_path = manifest_dir / "scan.json"
    summary_path = manifest_dir / "ingest_summary.json"
    brief_path = challenge_dir / "brief.md"
    _write_json(manifest_path, manifest)
    _write_json(scan_path, scan_result)
    brief_path.write_text(brief, encoding="utf-8")

    summary = {
        "status": "ok",
        "challenge_id": challenge_slug,
        "contest_id": contest_slug,
        "name": name,
        "category": category,
        "challenge_dir": _display_path(challenge_dir),
        "raw_dir": _display_path(raw_dir),
        "extracted_dir": _display_path(extracted_dir),
        "manifest_path": _display_path(manifest_path),
        "scan_path": _display_path(scan_path),
        "brief_path": _display_path(brief_path),
        "ingest_summary_path": _display_path(summary_path),
        "inputs": input_summaries,
        "archive_summaries": archive_summaries,
        "file_count": manifest.get("file_count", 0),
        "likely_categories": scan_result.get("likely_categories", []),
    }
    _write_json(summary_path, summary)
    return _redact_object(summary)


def ingest_text_challenge(
    challenge_id: str,
    *,
    text: str,
    contest_id: str | None = None,
    category: str | None = None,
    name: str | None = None,
    output_root: str | Path | None = None,
    points: int | None = None,
    solves: int | None = None,
    hints: list[Any] | None = None,
    tags: list[Any] | None = None,
    links: list[Any] | None = None,
    connection_info: str | None = None,
    author: str | None = None,
    state: str | None = None,
    deadline: str | None = None,
) -> dict[str, Any]:
    challenge_slug = _safe_slug(challenge_id, "challenge_id")
    contest_slug = _safe_slug(contest_id or "manual", "contest_id")
    base = Path(output_root).expanduser().resolve() if output_root else get_paths().contests_root
    challenge_dir = (base / contest_slug / challenge_slug).resolve()
    raw_dir = challenge_dir / "raw"
    extracted_dir = challenge_dir / "extracted"
    manifest_dir = challenge_dir / "manifest"
    raw_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)

    statement = redact_ingest_text(str(text or "").strip())
    challenge_md = _render_text_challenge_markdown(
        challenge_id=challenge_slug,
        name=name,
        category=category,
        points=points,
        solves=solves,
        statement=statement,
        hints=hints or [],
        tags=tags or [],
        links=links or [],
        connection_info=connection_info,
        author=author,
        state=state,
        deadline=deadline,
    )
    statement_path = raw_dir / "challenge.md"
    statement_path.write_text(challenge_md, encoding="utf-8")

    manifest = build_manifest(challenge_dir)
    scan_result = scan_source(_manifest_root_path(manifest, challenge_dir), manifest)
    metadata = {
        "challenge_id": challenge_slug,
        "contest_id": contest_slug,
        "name": name,
        "category": category,
        "points": points,
        "solves": solves,
        "statement": statement,
        "statement_path": _display_path(statement_path),
        "statement_bytes": len(statement.encode("utf-8")),
        "hints": _redact_object(hints or []),
        "tags": _redact_object(tags or []),
        "links": _redact_object(links or []),
        "connection_info": redact_ingest_text(connection_info or ""),
        "author": redact_ingest_text(author or ""),
        "state": redact_ingest_text(state or ""),
        "deadline": redact_ingest_text(deadline or ""),
        "inputs": [{"input": "metadata_text", "kind": "text", "raw_copy": _display_path(statement_path), "size": statement_path.stat().st_size}],
        "directory_inputs": [],
        "archive_summaries": [],
        "warnings": ["text-only ingest; no attachments were present"],
        "ingest_type": "text",
    }
    brief = render_challenge_brief(challenge_dir, manifest, scan_result, metadata)

    manifest_path = manifest_dir / "manifest.json"
    scan_path = manifest_dir / "scan.json"
    summary_path = manifest_dir / "ingest_summary.json"
    brief_path = challenge_dir / "brief.md"
    _write_json(manifest_path, manifest)
    _write_json(scan_path, scan_result)
    brief_path.write_text(brief, encoding="utf-8")

    summary = {
        "status": "ok",
        "ingest_type": "text",
        "challenge_id": challenge_slug,
        "contest_id": contest_slug,
        "name": name,
        "category": category,
        "points": points,
        "solves": solves,
        "challenge_dir": _display_path(challenge_dir),
        "raw_dir": _display_path(raw_dir),
        "extracted_dir": _display_path(extracted_dir),
        "manifest_path": _display_path(manifest_path),
        "scan_path": _display_path(scan_path),
        "brief_path": _display_path(brief_path),
        "ingest_summary_path": _display_path(summary_path),
        "statement_path": _display_path(statement_path),
        "statement_bytes": len(statement.encode("utf-8")),
        "hint_count": len(hints or []),
        "tag_count": len(tags or []),
        "link_count": len(links or []),
        "inputs": metadata["inputs"],
        "archive_summaries": [],
        "file_count": manifest.get("file_count", 0),
        "likely_categories": scan_result.get("likely_categories", []),
    }
    _write_json(summary_path, {**summary, "statement": statement, "hints": metadata["hints"], "tags": metadata["tags"], "links": metadata["links"]})
    return _redact_object(summary)


def ingest_text_file(
    challenge_id: str,
    *,
    text_file: str | Path,
    contest_id: str | None = None,
    category: str | None = None,
    name: str | None = None,
    output_root: str | Path | None = None,
) -> dict[str, Any]:
    path = Path(text_file).expanduser()
    if path.is_symlink():
        raise ValueError(f"refusing symlink text input: {_display_path(path)}")
    text = path.read_text(encoding="utf-8", errors="replace")
    return ingest_text_challenge(
        challenge_id,
        text=text,
        contest_id=contest_id,
        category=category,
        name=name,
        output_root=output_root,
    )


def manifest_path(path: str | Path) -> dict[str, Any]:
    return build_manifest(Path(path).expanduser().resolve())


def scan_path(path: str | Path) -> dict[str, Any]:
    root = Path(path).expanduser().resolve()
    manifest = build_manifest(root)
    return scan_source(root, manifest)


def brief_for_challenge(challenge_id: str, contest_id: str | None = None, output_root: str | Path | None = None) -> str:
    challenge_slug = _safe_slug(challenge_id, "challenge_id")
    contest_slug = _safe_slug(contest_id or "manual", "contest_id")
    base = Path(output_root).expanduser().resolve() if output_root else get_paths().contests_root
    challenge_dir = base / contest_slug / challenge_slug
    manifest_dir = challenge_dir / "manifest"
    manifest = json.loads((manifest_dir / "manifest.json").read_text(encoding="utf-8"))
    scan = json.loads((manifest_dir / "scan.json").read_text(encoding="utf-8"))
    summary_path = manifest_dir / "ingest_summary.json"
    metadata = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
    return render_challenge_brief(challenge_dir, manifest, scan, metadata)


def _copy_raw_file(source: Path, raw_dir: Path) -> Path:
    target = raw_dir / source.name
    if target.exists():
        stem = source.stem
        suffix = source.suffix
        index = 1
        while True:
            candidate = raw_dir / f"{stem}.{index}{suffix}"
            if not candidate.exists():
                target = candidate
                break
            index += 1
    shutil.copy2(source, target)
    return target


def _manifest_root_path(manifest: dict[str, Any], fallback: Path) -> Path:
    root = str(manifest.get("root_dir") or "")
    if root.startswith("~/"):
        return Path.home() / root[2:]
    if root:
        return Path(root)
    return fallback


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _render_text_challenge_markdown(
    *,
    challenge_id: str,
    name: str | None,
    category: str | None,
    points: int | None,
    solves: int | None,
    statement: str,
    hints: list[Any],
    tags: list[Any],
    links: list[Any],
    connection_info: str | None,
    author: str | None,
    state: str | None,
    deadline: str | None,
) -> str:
    lines = [
        f"# {redact_ingest_text(name or challenge_id)}",
        "",
        "## Metadata",
        f"- challenge_id: {redact_ingest_text(challenge_id)}",
    ]
    if category:
        lines.append(f"- category: {redact_ingest_text(category)}")
    if points is not None:
        lines.append(f"- points: {points}")
    if solves is not None:
        lines.append(f"- solves: {solves}")
    if author:
        lines.append(f"- author: {redact_ingest_text(author)}")
    if state:
        lines.append(f"- state: {redact_ingest_text(state)}")
    if deadline:
        lines.append(f"- deadline: {redact_ingest_text(deadline)}")
    if tags:
        lines.append("- tags: " + ", ".join(redact_ingest_text(str(item)) for item in tags[:20]))
    lines.extend(["", "## Statement", "", statement or "[no statement extracted]"])
    if hints:
        lines.extend(["", "## Hints"])
        for hint in hints[:20]:
            lines.append(f"- {redact_ingest_text(str(hint))}")
    if connection_info:
        lines.extend(["", "## Connection Info", "", redact_ingest_text(connection_info)])
    if links:
        lines.extend(["", "## Links"])
        for link in links[:50]:
            lines.append(f"- {redact_ingest_text(str(link))}")
    return redact_ingest_text("\n".join(lines).strip() + "\n")


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _safe_slug(value: str | None, label: str) -> str:
    value = str(value or "").strip()
    if not value:
        raise ValueError(f"{label} is required")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
    if not slug:
        raise ValueError(f"{label} has no safe path characters")
    return slug[:120]


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return redact_ingest_text(value)
    return value
