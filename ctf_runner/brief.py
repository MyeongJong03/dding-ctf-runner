from __future__ import annotations

from pathlib import Path
from typing import Any

from .file_manifest import redact_ingest_text


DEFAULT_BRIEF_LIMIT = 12 * 1024
TOP_FILES = 18
TOP_SIGNALS = 8


def render_challenge_brief(
    challenge_dir: str | Path,
    manifest: dict[str, Any],
    scan_result: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> str:
    metadata = metadata or {}
    lines: list[str] = ["# Challenge Brief", ""]
    lines.extend(_metadata_lines(challenge_dir, metadata))
    lines.extend(_statement_lines(metadata))
    lines.extend(_file_summary_lines(manifest))
    lines.extend(_likely_category_lines(scan_result, metadata))
    lines.extend(_interesting_files_lines(scan_result, manifest))
    lines.extend(_archive_summary_lines(metadata))
    lines.extend(_source_signal_lines(scan_result))
    lines.extend(_recommended_lines(scan_result))
    lines.extend(_warning_lines(scan_result, metadata, manifest))
    brief = "\n".join(lines).strip() + "\n"
    brief = redact_ingest_text(brief)
    if len(brief.encode("utf-8")) <= DEFAULT_BRIEF_LIMIT:
        return brief
    return _truncate_brief(brief, DEFAULT_BRIEF_LIMIT)


def _metadata_lines(challenge_dir: str | Path, metadata: dict[str, Any]) -> list[str]:
    fields = {
        "challenge_id": metadata.get("challenge_id"),
        "contest_id": metadata.get("contest_id"),
        "name": metadata.get("name"),
        "declared_category": metadata.get("category"),
        "points": metadata.get("points"),
        "solves": metadata.get("solves"),
        "state": metadata.get("state"),
        "deadline": metadata.get("deadline"),
        "author": metadata.get("author"),
        "challenge_dir": _display_path(Path(challenge_dir).expanduser()),
    }
    lines = ["## Metadata"]
    for key, value in fields.items():
        if value:
            lines.append(f"- {key}: {value}")
    return lines + [""]


def _statement_lines(metadata: dict[str, Any]) -> list[str]:
    statement = str(metadata.get("statement") or "").strip()
    hints = list(metadata.get("hints") or [])
    tags = list(metadata.get("tags") or [])
    links = list(metadata.get("links") or [])
    connection_info = str(metadata.get("connection_info") or "").strip()
    if not any((statement, hints, tags, links, connection_info)):
        return []
    lines = ["## Challenge Statement"]
    if statement:
        lines.append(_clip(statement, 5000))
    else:
        lines.append("- no statement text extracted")
    if hints:
        lines.extend(["", "### Hints"])
        for hint in hints[:12]:
            lines.append(f"- {_clip(str(hint), 600)}")
    if tags:
        lines.extend(["", "### Tags"])
        lines.append("- " + ", ".join(_clip(str(tag), 80) for tag in tags[:24]))
    if connection_info:
        lines.extend(["", "### Connection Info", _clip(connection_info, 1200)])
    if links:
        lines.extend(["", "### Links"])
        for link in links[:30]:
            lines.append(f"- {_clip(str(link), 300)}")
    return lines + [""]


def _file_summary_lines(manifest: dict[str, Any]) -> list[str]:
    summary = manifest.get("summary") or {}
    by_category = summary.get("by_category") or {}
    lines = ["## File Summary"]
    lines.append(f"- files: {manifest.get('file_count', 0)}")
    lines.append(f"- total_size: {summary.get('total_size', 0)} bytes")
    if by_category:
        compact = ", ".join(f"{key}={value}" for key, value in sorted(by_category.items()))
        lines.append(f"- categories: {compact}")
    git = manifest.get("git") or {}
    if git.get("present"):
        repos = git.get("repositories") or []
        git_bits = []
        for repo in repos[:4]:
            git_bits.append(
                f"{repo.get('path')} HEAD={bool(repo.get('head_exists'))} objects={bool(repo.get('commit_object_exists'))}"
            )
        lines.append(f"- git: present ({'; '.join(git_bits)})")
    return lines + [""]


def _likely_category_lines(scan_result: dict[str, Any], metadata: dict[str, Any]) -> list[str]:
    lines = ["## Likely Category"]
    declared = metadata.get("category")
    if declared:
        lines.append(f"- declared: {declared}")
    likely = scan_result.get("likely_categories") or []
    if likely:
        lines.append("- inferred: " + ", ".join(f"{item['category']}({item['score']})" for item in likely[:4]))
    else:
        lines.append("- inferred: unknown")
    return lines + [""]


def _interesting_files_lines(scan_result: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    interesting = list(scan_result.get("interesting_files") or [])
    if not interesting:
        interesting = sorted(
            manifest.get("files") or [],
            key=lambda item: (-int(item.get("interesting_score") or 0), str(item.get("path"))),
        )
    lines = ["## Top Interesting Files"]
    for item in interesting[:TOP_FILES]:
        reasons = ", ".join((item.get("reasons") or [])[:4])
        lines.append(
            f"- {item.get('path')} [{item.get('category', 'unknown')}] score={item.get('score', item.get('interesting_score', 0))}"
            + (f" reasons={reasons}" if reasons else "")
        )
    if len(interesting) > TOP_FILES:
        lines.append(f"- omitted: {len(interesting) - TOP_FILES} more")
    return lines + [""]


def _archive_summary_lines(metadata: dict[str, Any]) -> list[str]:
    archives = metadata.get("archive_summaries") or []
    lines = ["## Extracted Archive Summary"]
    if not archives:
        lines.append("- none")
        return lines + [""]
    for archive in archives[:8]:
        lines.append(
            "- "
            + f"{archive.get('archive', 'archive')}: files={archive.get('extracted_files_count', 0)} "
            + f"skipped={len(archive.get('skipped_entries') or [])} "
            + f"nested={len(archive.get('nested_archives') or [])} "
            + f"errors={len(archive.get('errors') or [])}"
        )
        nested = archive.get("nested_archives") or []
        if nested:
            lines.append(f"  nested_archives: {', '.join(nested[:5])}")
    if len(archives) > 8:
        lines.append(f"- omitted: {len(archives) - 8} more archives")
    return lines + [""]


def _source_signal_lines(scan_result: dict[str, Any]) -> list[str]:
    lines = ["## Source Scan Signals"]
    signals = scan_result.get("signals_by_category") or {}
    any_signal = False
    for category, values in signals.items():
        if not values:
            continue
        any_signal = True
        lines.append(f"- {category}:")
        for signal in values[:TOP_SIGNALS]:
            files = ", ".join((signal.get("files") or [])[:4])
            extra = ""
            if signal.get("keywords"):
                extra = f" keywords={','.join(signal['keywords'])}"
            lines.append(
                f"  - {signal.get('kind')}: count={signal.get('count', 0)} files={files}{extra}"
            )
    if not any_signal:
        lines.append("- none")
    return lines + [""]


def _recommended_lines(scan_result: dict[str, Any]) -> list[str]:
    lines = ["## Recommended First Actions"]
    for action in (scan_result.get("recommended_first_actions") or [])[:6]:
        lines.append(f"- {action}")
    if len(lines) == 1:
        lines.append("- Review manifest and select a bounded set of files for worker context.")
    return lines + [""]


def _warning_lines(scan_result: dict[str, Any], metadata: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    lines = ["## Warnings / Unknowns"]
    warnings = list(scan_result.get("warnings") or []) + list(metadata.get("warnings") or [])
    if (manifest.get("summary") or {}).get("large_files"):
        warnings.append("large files present; content previews omitted")
    if not warnings:
        warnings.append("none")
    for warning in warnings[:12]:
        lines.append(f"- {warning}")
    return lines + [""]


def _truncate_brief(brief: str, limit: int) -> str:
    suffix = "\n\n[brief truncated to budget]\n"
    encoded_suffix = suffix.encode("utf-8")
    budget = max(limit - len(encoded_suffix), 0)
    data = brief.encode("utf-8")[:budget]
    text = data.decode("utf-8", errors="ignore").rstrip()
    return redact_ingest_text(text + suffix)


def _clip(value: str, limit: int) -> str:
    text = redact_ingest_text(str(value or "").strip())
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + " [truncated]"


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve()).replace(str(Path.home()), "~", 1)
    except OSError:
        return str(path).replace(str(Path.home()), "~", 1)
