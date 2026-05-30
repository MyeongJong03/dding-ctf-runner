from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Mapping

from .auth import load_auth_secret, load_config_metadata
from .fake_ctfd import FakeCTFdServer, default_correct_flag, platform_config
from .file_manifest import is_sensitive_path
from .ingest import ingest_challenge, ingest_text_challenge
from .paths import get_paths
from .platform_base import PlatformAction, action_to_dict
from .platform_ctfd import load_platform_adapter
from .redact import redact_text
from .state import utc_now
from .submit import classify_flag_confidence, detect_flag_candidates, hash_flag, load_submit_policy, should_submit
from .toolchain import (
    choose_command_or_fallback,
    collect_toolchain_capabilities,
    command_available,
    detect_missing_tool_failure,
    fallback_suggestions,
    render_capabilities_markdown,
    summarize_capabilities_for_category,
    toolchain_doctor,
)


MEMO_KINDS = ("memory", "evidence", "attempts", "next_steps", "operator_notes")
BOARD_FILES = ("BOARD.md", "board.json", "solved.jsonl", "external_solved.txt", "stalled.jsonl")
METRICS_FILES = (
    "events.jsonl",
    "sessions.jsonl",
    "challenge_metrics.jsonl",
    "tool_benchmarks.jsonl",
    "summary.json",
    "regression_report.md",
)
SAFE_CLEANUP_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist", "tmp", "temp"}
SAFE_CLEANUP_SUFFIXES = {".pyc", ".pyo", ".log", ".tmp", ".dump", ".dmp"}
KEEP_NAMES = {
    "memory.md",
    "evidence.md",
    "attempts.md",
    "next_steps.md",
    "operator_notes.md",
    "solve.py",
    "solver.py",
    "exploit.py",
    "README.md",
}
PLAYBOOK_CATEGORIES = ("web", "pwn", "rev", "crypto", "forensics/misc", "osint", "ai/ml")
SERVICE_TOKEN_SOURCES = ("none", "profile", "file", "env")
SERVICE_TRANSPORTS = ("auto", "plain", "tls")
SERVICE_TRANSCRIPT_LIMIT = 64 * 1024
WEB_AUTH_SOURCES = ("none", "profile", "cookie-file", "header-file", "storage-state", "env")
WEB_RESPONSE_LIMIT = 2 * 1024 * 1024
WEB_TEXT_SCAN_LIMIT = 512 * 1024
WEB_BROWSER_NETWORK_LIMIT = 160
WEB_BROWSER_CONSOLE_LIMIT = 120


def init_operator(
    contest_id: str,
    *,
    profile: str | Path | None = None,
    writeup_root: str | Path | None = None,
    agents: int | None = None,
) -> dict[str, Any]:
    root = operator_root(contest_id)
    root.mkdir(parents=True, exist_ok=True)
    lock = root / ".init.lock"
    acquired = _try_lock(lock, {"contest_id": contest_id, "created_at": utc_now(), "pid": os.getpid()})
    try:
        paths = _ensure_operator_files(root, contest_id, profile=profile, writeup_root=writeup_root, agents=agents)
    finally:
        if acquired:
            _unlink(lock)
    return {
        "status": "ok",
        "contest_id": contest_id,
        "operator_root": _display(root),
        "created": paths["created"],
        "preserved": paths["preserved"],
        "paths": {key: _display(path) for key, path in paths["paths"].items()},
    }


def capabilities_report(
    contest_id: str | None = None,
    *,
    category: str | None = None,
    refresh: bool = False,
) -> dict[str, Any]:
    report = collect_toolchain_capabilities(category=category, probe_docker=True)
    report["refresh"] = bool(refresh)
    if not contest_id:
        return report
    init_operator(contest_id)
    root = operator_root(contest_id)
    saved = _save_toolchain_report(root, report)
    report.update(
        {
            "contest_id": contest_id,
            "capabilities_json_path": _display(saved["json"]),
            "capabilities_md_path": _display(saved["md"]),
        }
    )
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="toolchain_checked",
        data=_toolchain_metric_payload(report),
    )
    return report


def toolchain_doctor_report(*, category: str | None = None) -> dict[str, Any]:
    return toolchain_doctor(category=category)


def fallback_report(*, tool: str) -> dict[str, Any]:
    return fallback_suggestions(tool)


def sync_operator(
    contest_id: str,
    *,
    profile: str | Path | None = None,
    live: bool = False,
    download: bool = False,
    ingest: bool = False,
    pull_solved: bool = False,
) -> dict[str, Any]:
    init_operator(contest_id, profile=profile)
    root = operator_root(contest_id)
    resolved_profile = _refresh_profile_path(root, profile)
    if not resolved_profile:
        return {"status": "blocked", "contest_id": contest_id, "reason": "profile_required_for_sync"}
    board = _read_board(root, contest_id)
    platform = load_platform_adapter(resolved_profile)
    previous_items = [dict(item) for item in board.get("challenges", []) if isinstance(item, Mapping)]
    previous_board = {**board, "challenges": previous_items}
    _apply_runtime_statuses(root, previous_board)
    previous_items = [dict(item) for item in previous_board.get("challenges", []) if isinstance(item, Mapping)]
    previous_signatures = _sync_signatures(root, previous_items)
    previous_statuses = _sync_statuses(root, previous_items)

    discover_action = platform.discover_challenges(live=live)
    discover_payload = action_to_dict(discover_action)
    source_challenges = list(discover_payload.get("details", {}).get("challenges") or [])
    warnings: list[str] = []
    if not source_challenges and live:
        text_candidates = getattr(platform, "text_ingest_candidates", None)
        if text_candidates is not None:
            text_result = text_candidates(live=True)
            source_challenges = list(text_result.get("public_challenges") or text_result.get("challenges") or [])
            warnings.extend(str(item) for item in text_result.get("warnings") or [])

    canonical = _canonicalize_challenges(source_challenges)
    discovered_solved = _discover_solved_status(source_challenges)
    adapter_solved = _collect_platform_solved_status(platform, live=live) if pull_solved else _empty_solved_status("not_requested")
    solved_records = [*discovered_solved["records"], *adapter_solved["records"]]
    solved_status_source = _combine_solved_status_sources(discovered_solved, adapter_solved, pull_solved=pull_solved)
    solved_sync_available = bool(discovered_solved["available"] or adapter_solved["available"])
    previous_by_key: dict[str, dict[str, Any]] = {}
    for previous in previous_items:
        for key in _challenge_keys(previous):
            previous_by_key.setdefault(key, previous)

    merged_challenges: list[dict[str, Any]] = []
    source_keys = {_normalize(str(key)) for key in canonical["map"].keys()}
    canonical_ids = {_normalize(str(item.get("challenge_id") or "")) for item in canonical["challenges"]}
    for item in canonical["challenges"]:
        previous = _previous_challenge(previous_by_key, item)
        merged = _merge_challenge_entry(previous, item)
        merged["path"] = _challenge_path(contest_id, merged).as_posix()
        merged_challenges.append(merged)
        _ensure_challenge_memos(_challenge_path(contest_id, merged))

    for previous in previous_items:
        previous_id = _normalize(str(previous.get("challenge_id") or previous.get("name") or ""))
        if not previous_id or previous_id in source_keys or previous_id in canonical_ids:
            continue
        if previous.get("is_alias") or previous.get("is_static_alias") or previous.get("canonical_id") not in (None, "", previous.get("challenge_id")):
            continue
        preserved = _normalize_challenge_entry(previous)
        preserved["path"] = _challenge_path(contest_id, preserved).as_posix()
        merged_challenges.append(preserved)

    board["profile_path"] = _display(Path(resolved_profile).expanduser())
    board["updated_at"] = utc_now()
    board["last_sync_at"] = board["updated_at"]
    board["canonical_map"] = canonical["map"]
    board["canonical_counts"] = canonical["counts"]
    board["challenges"] = sorted(merged_challenges, key=lambda row: (int(row.get("priority") or 100), str(row.get("name") or "")))
    solved_sync = _apply_platform_solved_records(
        root,
        board,
        solved_records,
        available=solved_sync_available,
        source=solved_status_source,
        synced_at=str(board["updated_at"]),
    )
    _apply_runtime_statuses(root, board)
    solved_sync = _refresh_solved_sync_counts(board, solved_sync)
    after_items = [dict(item) for item in board.get("challenges", []) if isinstance(item, Mapping)]
    after_signatures = _sync_signatures(root, after_items)
    after_statuses = _sync_statuses(root, after_items)
    after_public_ids = _sync_public_ids(after_items)
    new_keys = sorted(set(after_signatures) - set(previous_signatures))
    updated_keys = sorted(key for key in set(after_signatures) & set(previous_signatures) if after_signatures[key] != previous_signatures[key])
    status_changes = [
        {
            "challenge_id": after_public_ids.get(key, key),
            "from": previous_statuses.get(key, "missing"),
            "to": after_statuses.get(key, "missing"),
        }
        for key in sorted(set(previous_statuses) | set(after_statuses))
        if previous_statuses.get(key, "missing") != after_statuses.get(key, "missing")
    ]
    stale_before_release = _stale_claims(root, board)
    for challenge in board["challenges"]:
        if _item_solved_by_platform_or_external(challenge):
            _release_locks_for_item(root, agent=None, item=challenge)
    _write_board(root, board)
    _write_board_md(root, board)

    download_results: list[dict[str, Any]] = []
    ingest_results: list[dict[str, Any]] = []
    if live and (download or ingest):
        for challenge in board["challenges"]:
            if not _claimable_source(challenge):
                continue
            challenge_id = str(challenge.get("challenge_id") or "")
            if download:
                action = platform.download_attachments(challenge_id, dest_dir=str(_challenge_path(contest_id, challenge) / "handout"), live=True)
                download_results.append(_public_action(action))
            if ingest:
                text = _challenge_text_for_ingest(challenge)
                if text:
                    result = ingest_text_challenge(
                        challenge_id,
                        text=text,
                        contest_id=contest_id,
                        category=str(challenge.get("category") or ""),
                        name=str(challenge.get("name") or challenge_id),
                        output_root=get_paths().contests_root,
                    )
                    ingest_results.append({"challenge_id": challenge_id, "status": result.get("status"), "brief_path": result.get("brief_path")})
                else:
                    handout = _challenge_path(contest_id, challenge) / "handout"
                    if handout.exists():
                        result = ingest_challenge(
                            challenge_id,
                            input_paths=[handout],
                            contest_id=contest_id,
                            category=str(challenge.get("category") or ""),
                            name=str(challenge.get("name") or challenge_id),
                            output_root=get_paths().contests_root,
                        )
                        ingest_results.append({"challenge_id": challenge_id, "status": result.get("status"), "brief_path": result.get("brief_path")})
                    else:
                        ingest_results.append({"challenge_id": challenge_id, "status": "skipped", "reason": "no_text_or_handout"})

    claimable_count = sum(1 for item in board["challenges"] if _claimable(root, item))
    sync_metrics = {
        "status": "ok" if discover_action.status in {"ok", "planned"} else discover_action.status,
        "challenge_count": len(source_challenges),
        "canonical_count": canonical["counts"]["canonical_count"],
        "new_count": len(new_keys),
        "updated_count": len(updated_keys),
        "alias_count": canonical["counts"]["alias_count"],
        "claimable_count": claimable_count,
        "status_change_count": len(status_changes),
        "new_challenge_ids": [after_public_ids.get(key, key) for key in new_keys],
        "updated_challenge_ids": [after_public_ids.get(key, key) for key in updated_keys],
        "solved_synced_count": solved_sync["solved_synced_count"],
        "external_solved_count": solved_sync["external_solved_count"],
        "solved_alias_resolved_count": solved_sync["solved_alias_resolved_count"],
        "solved_status_source": solved_status_source,
        "solved_sync_available": solved_sync_available,
    }
    _record_metrics_event(root, contest_id=contest_id, event="sync_completed", data=sync_metrics)
    if pull_solved or solved_sync_available:
        _record_metrics_event(root, contest_id=contest_id, event="solved_sync_completed", data=solved_sync)
    if new_keys:
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="new_challenges_detected",
            data={"new_count": len(new_keys), "challenge_ids": [after_public_ids.get(key, key) for key in new_keys]},
        )
    solved_changes = [row for row in status_changes if row["to"] in {"solved", "external_solved"} or row["from"] in {"solved", "external_solved"}]
    if solved_changes:
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="challenge_status_changed",
            data={"change_count": len(solved_changes), "changes": solved_changes[:50]},
        )
    if stale_before_release:
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="stale_claims_detected",
            data={"source": "sync", "stale_count": len(stale_before_release), "claims": _claim_metric_rows(stale_before_release)},
        )

    return {
        "status": "ok" if discover_action.status in {"ok", "planned"} else discover_action.status,
        "contest_id": contest_id,
        "challenge_count": len(source_challenges),
        "canonical_count": canonical["counts"]["canonical_count"],
        "new_count": len(new_keys),
        "updated_count": len(updated_keys),
        "target_count": canonical["counts"]["claimable_count"],
        "alias_count": canonical["counts"]["alias_count"],
        "skipped_static_count": canonical["counts"]["skipped_static_count"],
        "claimable_count": claimable_count,
        "solved_synced_count": solved_sync["solved_synced_count"],
        "external_solved_count": solved_sync["external_solved_count"],
        "solved_alias_resolved_count": solved_sync["solved_alias_resolved_count"],
        "solved_status_source": solved_status_source,
        "solved_sync_available": solved_sync_available,
        "status_changes": status_changes[:50],
        "stale_claim_count": len(stale_before_release),
        "canonical_map": canonical["map"],
        "warnings": sorted(set(warnings + canonical["warnings"])),
        "discover": _interactive_discover_public(discover_payload),
        "download": download_results,
        "ingest": ingest_results,
        "board_path": _display(root / "board.json"),
    }


def operator_status(contest_id: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    _write_board(root, board)
    _write_board_md(root, board)
    summary = _operator_status_summary(contest_id, root, board)
    _record_no_work_metrics(root, contest_id, summary, source="status")
    return summary


def board_status(contest_id: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    _write_board(root, board)
    _write_board_md(root, board)
    buckets: dict[str, list[dict[str, Any]]] = {key: [] for key in ("solved", "claimed", "stalled", "todo", "skipped")}
    for item in board.get("challenges", []):
        status = _challenge_status(root, item)
        summary = _challenge_public(item)
        buckets.setdefault(status, []).append(summary)
    canonical_count = sum(1 for item in board.get("challenges", []) if not item.get("is_alias"))
    alias_count = sum(len(_list_values(item.get("aliases"))) for item in board.get("challenges", []) if isinstance(item, Mapping))
    artifact_source_count = sum(len(_list_values(item.get("artifact_sources"))) for item in board.get("challenges", []) if isinstance(item, Mapping))
    skipped_static_count = sum(1 for item in board.get("challenges", []) if item.get("is_static_shell") or item.get("is_static_alias")) + artifact_source_count
    claimable_count = sum(1 for item in board.get("challenges", []) if _claimable(root, item))
    return {
        "status": "ok",
        "contest_id": contest_id,
        "operator_root": _display(root),
        "canonical_count": canonical_count,
        "alias_count": alias_count,
        "skipped_static_count": skipped_static_count,
        "claimable_count": claimable_count,
        "counts": {
            **{key: len(value) for key, value in buckets.items()},
            "canonical_count": canonical_count,
            "alias_count": alias_count,
            "skipped_static_count": skipped_static_count,
            "claimable_count": claimable_count,
        },
        "challenges": buckets,
        "canonical_map": board.get("canonical_map", {}),
    }


def claim_challenge(
    contest_id: str,
    *,
    agent: str,
    challenge: str | None = None,
    allow_duplicate: bool = False,
    allow_stalled_retry: bool = False,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    if challenge:
        item = _find_challenge(board, challenge)
        if item is None:
            return {"status": "empty", "contest_id": contest_id, "reason": "challenge_not_found"}
        status = _challenge_status(root, item)
        if status in {"solved", "skipped"} or (status == "stalled" and not allow_stalled_retry):
            return {"status": "empty", "contest_id": contest_id, "reason": f"challenge_{status}", "challenge_id": item.get("challenge_id")}
        if not _claimable_source(item):
            return {"status": "empty", "contest_id": contest_id, "reason": "challenge_not_claimable", "challenge_id": item.get("challenge_id")}
        candidates = [item]
    else:
        candidates = [item for item in board.get("challenges", []) if _claimable(root, item)]
    if not candidates:
        return {"status": "empty", "contest_id": contest_id, "reason": "no_claimable_challenge"}
    item = candidates[0]
    norm = _normalize(str(item.get("canonical_id") or item.get("challenge_id") or item.get("name")))
    claims_dir = root / "claims"
    claims_dir.mkdir(parents=True, exist_ok=True)
    lock = claims_dir / f"{norm}.lock"
    if allow_duplicate:
        duplicate_lock = claims_dir / f"{norm}.{_normalize(agent)}.{hashlib.sha1(utc_now().encode()).hexdigest()[:8]}.lock"
        _write_json(duplicate_lock, _claim_payload(contest_id, agent, item, duplicate=True))
        lock_path = duplicate_lock
    else:
        if not _try_lock(lock, _claim_payload(contest_id, agent, item, duplicate=False)):
            return {"status": "blocked", "reason": "already_claimed_on_this_machine", "challenge_id": item.get("challenge_id")}
        lock_path = lock
    item["status"] = "claimed"
    item["claimed_by"] = agent
    item["claimed_at"] = utc_now()
    _write_board(root, board)
    _write_board_md(root, board)
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    _record_metrics_event(root, contest_id=contest_id, event="claim", agent=agent, challenge_id=str(item.get("challenge_id") or ""), data={"status": "claimed"})
    return {
        "status": "claimed",
        "contest_id": contest_id,
        "agent": agent,
        "challenge_id": item.get("challenge_id"),
        "name": item.get("name"),
        "category": item.get("category", ""),
        "path": _display(challenge_dir),
        "lock_path": _display(lock_path),
        "notes_paths": {kind: _display(challenge_dir / f"{kind}.md") for kind in MEMO_KINDS},
        "writeup_paths": _writeup_paths(contest_id, item),
    }


def next_challenge(
    contest_id: str,
    *,
    agent: str,
    category: str | None = None,
    allow_duplicate: bool = False,
    dry_run: bool = False,
    refresh: bool = False,
    profile: str | Path | None = None,
    pull_solved: bool = False,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    refresh_result: dict[str, Any] | None = None
    if refresh:
        refresh_result = _refresh_operator_once(contest_id, root, profile, pull_solved=True)
        if refresh_result.get("status") in {"blocked", "error", "auth_required", "rate_limited", "unexpected_response"}:
            board = _read_board(root, contest_id)
            _apply_runtime_statuses(root, board)
            status_summary = _operator_status_summary(contest_id, root, board)
            return {
                "status": refresh_result.get("status") or "blocked",
                "contest_id": contest_id,
                "agent": agent,
                "reason": refresh_result.get("reason") or "refresh_failed",
                "refresh": refresh_result,
                "completion_status": status_summary["completion_status"],
                "no_useful_work": status_summary["no_useful_work"],
                "status_summary": _compact_status_summary(status_summary),
            }
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    ranked = _rank_next_targets(root, contest_id, board, category=category, allow_duplicate=allow_duplicate)
    if not ranked:
        status_summary = _operator_status_summary(contest_id, root, board)
        _record_no_work_metrics(root, contest_id, status_summary, source="next")
        return {
            "status": "empty",
            "contest_id": contest_id,
            "agent": agent,
            "reason": "no_ranked_target",
            "category": category or "",
            "completion_status": status_summary["completion_status"],
            "no_useful_work": status_summary["no_useful_work"],
            "status_summary": _compact_status_summary(status_summary),
            **({"refresh": refresh_result} if refresh_result else {}),
        }

    selected = ranked[0]
    item = selected["item"]
    challenge_id = str(item.get("challenge_id") or item.get("canonical_id") or item.get("name") or "")
    pack = target_pack(contest_id, challenge_id=challenge_id, agent=agent)
    common = {
        "contest_id": contest_id,
        "agent": agent,
        "challenge_id": challenge_id,
        "name": item.get("name"),
        "category": item.get("category", ""),
        "score": selected["score"],
        "score_reasons": selected["reasons"],
        "target_pack_path": pack.get("target_pack_path", ""),
        "ranked_considered": len(ranked),
        "selected_status": selected["status"],
        **({"refresh": refresh_result} if refresh_result else {}),
    }
    if dry_run:
        return {"status": "planned", **common, "claim": {"status": "dry_run"}}

    claim = claim_challenge(
        contest_id,
        agent=agent,
        challenge=challenge_id,
        allow_duplicate=allow_duplicate,
        allow_stalled_retry=selected["status"] == "stalled",
    )
    if claim.get("status") == "claimed":
        pack = target_pack(contest_id, challenge_id=challenge_id, agent=agent)
        common["target_pack_path"] = pack.get("target_pack_path", "")
    return {**common, **{key: value for key, value in claim.items() if key not in common}, "claim": claim}


def target_pack(contest_id: str, *, challenge_id: str, agent: str | None = None) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}

    context = _target_context(contest_id, root, item)
    if context.get("service_metadata") and not _service_metadata_for_item(root, board, item, str(item.get("challenge_id") or challenge_id)):
        _save_challenge_service_metadata(root, board, str(item.get("challenge_id") or challenge_id), context["service_metadata"])
    _attach_toolchain_context(root, contest_id, context)
    pack_path = root / "target-packs" / f"{_safe_slug(str(item.get('canonical_id') or item.get('challenge_id') or challenge_id))}.md"
    text = _render_target_pack(contest_id, item, context, agent=agent)
    pack_path.parent.mkdir(parents=True, exist_ok=True)
    pack_path.write_text(_target_safe_text(text), encoding="utf-8")
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": item.get("challenge_id"),
        "canonical_name": item.get("canonical_name") or item.get("name"),
        "agent": agent or "",
        "category": context["category_guess"]["category"],
        "category_confidence": context["category_guess"]["confidence"],
        "target_pack_path": _display(pack_path),
        "brief_path": _display(context["brief_path"]) if context.get("brief_path") else "",
        "challenge_path": _display(context["challenge_dir"]),
        "remote_endpoint_count": len(context["remote_endpoints"]),
        "service_metadata": _service_public_metadata(context.get("service_metadata") or {}) if context.get("service_metadata") else {},
        "web_metadata": _web_public_metadata(context.get("web_metadata") or {}) if context.get("web_metadata") else {},
        "toolchain": context.get("toolchain_summary") or {},
    }


def challenge_brief(contest_id: str, *, challenge_id: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}
    context = _target_context(contest_id, root, item)
    _attach_toolchain_context(root, contest_id, context)
    text = _render_compact_brief(contest_id, item, context)
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": item.get("challenge_id"),
        "canonical_name": item.get("canonical_name") or item.get("name"),
        "category": context["category_guess"]["category"],
        "brief": _target_safe_text(text),
        "target_pack_path": _display(root / "target-packs" / f"{_safe_slug(str(item.get('canonical_id') or item.get('challenge_id') or challenge_id))}.md"),
    }


def triage_challenge(
    contest_id: str,
    *,
    challenge_id: str,
    agent: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}

    challenge_key = str(item.get("challenge_id") or challenge_id)
    pack = target_pack(contest_id, challenge_id=challenge_key, agent=agent)
    context = _target_context(contest_id, root, item)
    effective_category = _effective_triage_category(category, context)
    _attach_toolchain_context(root, contest_id, context, category=effective_category)
    started = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="triage_started",
        agent=agent,
        challenge_id=challenge_key,
        data={"category": effective_category},
    )

    files = _triage_file_inventory(context)
    command_rows = _run_category_triage_commands(effective_category, context, files)
    web_probe_result: dict[str, Any] = {}
    if effective_category == "web" and (context.get("web_metadata") or {}).get("base_url"):
        web_probe_result = web_probe(contest_id, challenge_id=challenge_key, timeout=10)
        context["web_probe_result"] = web_probe_result
    for fallback in _selected_fallback_rows(command_rows):
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="fallback_selected",
            agent=agent,
            challenge_id=challenge_key,
            data=fallback,
        )
    findings = _category_triage_findings(effective_category, item, context, files, command_rows)
    next_steps = _triage_next_steps(effective_category, findings, context)

    triage_dir = Path(context["challenge_dir"]) / "triage"
    triage_dir.mkdir(parents=True, exist_ok=True)
    summary_path = triage_dir / "summary.md"
    files_path = triage_dir / "files.json"
    commands_path = triage_dir / "commands.jsonl"
    findings_path = triage_dir / "findings.jsonl"

    summary = _render_triage_summary(
        contest_id,
        item,
        context,
        effective_category,
        files,
        command_rows,
        findings,
        next_steps,
        target_pack_path=str(pack.get("target_pack_path") or ""),
        started_at=str(started.get("timestamp") or ""),
    )
    summary_path.write_text(_target_safe_text(summary), encoding="utf-8")
    _write_json(
        files_path,
        {
            "schema": "interactive_triage_files_v1",
            "contest_id": contest_id,
            "challenge_id": challenge_key,
            "category": effective_category,
            "generated_at": utc_now(),
            "files": files,
        },
    )
    _write_jsonl(commands_path, command_rows)
    _write_jsonl(findings_path, findings)

    _append_triage_memos(
        Path(context["challenge_dir"]),
        category=effective_category,
        summary_path=summary_path,
        files_path=files_path,
        commands_path=commands_path,
        findings_path=findings_path,
        findings=findings,
        next_steps=next_steps,
    )
    metadata = {
        "challenge_id": challenge_key,
        "category": effective_category,
        "summary_path": _display(summary_path),
        "files_path": _display(files_path),
        "commands_path": _display(commands_path),
        "findings_path": _display(findings_path),
        "target_pack_path": pack.get("target_pack_path") or "",
        "updated_at": utc_now(),
    }
    _save_challenge_triage_metadata(root, board, challenge_key, metadata)
    completed = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="triage_completed",
        agent=agent,
        challenge_id=challenge_key,
        data={
            "category": effective_category,
            "finding_count": len(findings),
            "command_count": len(command_rows),
            "fallback_count": len(_selected_fallback_rows(command_rows)),
            "summary_path": _display(summary_path),
        },
    )
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "category": effective_category,
        "target_pack_path": pack.get("target_pack_path") or "",
        "triage_summary_path": _display(summary_path),
        "files_path": _display(files_path),
        "commands_path": _display(commands_path),
        "findings_path": _display(findings_path),
        "top_files": [_display(_triage_file_path(row)) for row in files[:8]],
        "first_commands": [str(row.get("command") or "") for row in command_rows if row.get("status") != "skipped"][:8],
        "skipped_tools": _skipped_tool_rows(command_rows),
        "next_steps": next_steps,
        "toolchain": context.get("toolchain_summary") or {},
        "metrics": {"started_at": started.get("timestamp"), "completed_at": completed.get("timestamp")},
    }


def starter_challenge(
    contest_id: str,
    *,
    challenge_id: str,
    category: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}

    context = _target_context(contest_id, root, item)
    challenge_key = str(item.get("challenge_id") or challenge_id)
    effective_category = _effective_triage_category(category, context)
    _attach_toolchain_context(root, contest_id, context, category=effective_category)
    starter_path = Path(context["challenge_dir"]) / _starter_filename(effective_category)
    starter_path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    if not starter_path.exists():
        starter_path.write_text(_starter_source(effective_category, contest_id, item, context), encoding="utf-8")
        created = True

    metadata = {
        "challenge_id": challenge_key,
        "category": effective_category,
        "starter_path": _display(starter_path),
        "status": "created" if created else "preserved",
        "toolchain": context.get("toolchain_summary") or {},
        "updated_at": utc_now(),
    }
    _save_challenge_solver_metadata(root, board, challenge_key, metadata)
    _append_starter_memos(Path(context["challenge_dir"]), starter_path=starter_path, category=effective_category, created=created)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="starter_created",
        challenge_id=challenge_key,
        data={
            "category": effective_category,
            "starter_path": _display(starter_path),
            "status": metadata["status"],
            "missing_critical_tools": list((context.get("toolchain_summary") or {}).get("missing_critical_tools") or [])[:20],
        },
    )
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "category": effective_category,
        "starter_path": _display(starter_path),
        "created": created,
        "metadata": metadata,
        "toolchain": context.get("toolchain_summary") or {},
    }


def prepare_target(
    contest_id: str,
    *,
    agent: str,
    challenge_id: str | None = None,
    refresh: bool = False,
    profile: str | Path | None = None,
    pull_solved: bool = False,
) -> dict[str, Any]:
    init_operator(contest_id)
    selected: dict[str, Any] = {}
    effective_challenge = challenge_id
    refresh_result: dict[str, Any] | None = None
    if refresh and effective_challenge:
        root = operator_root(contest_id)
        refresh_result = _refresh_operator_once(contest_id, root, profile, pull_solved=True)
        if refresh_result.get("status") in {"blocked", "error", "auth_required", "rate_limited", "unexpected_response"}:
            board = _read_board(root, contest_id)
            _apply_runtime_statuses(root, board)
            status_summary = _operator_status_summary(contest_id, root, board)
            return {
                "status": refresh_result.get("status") or "blocked",
                "contest_id": contest_id,
                "agent": agent,
                "reason": refresh_result.get("reason") or "refresh_failed",
                "refresh": refresh_result,
                "completion_status": status_summary["completion_status"],
                "no_useful_work": status_summary["no_useful_work"],
                "status_summary": _compact_status_summary(status_summary),
            }
    if not effective_challenge:
        selected = next_challenge(contest_id, agent=agent, refresh=refresh, profile=profile, pull_solved=pull_solved)
        refresh_result = selected.get("refresh") if isinstance(selected.get("refresh"), dict) else refresh_result
        if selected.get("status") not in {"claimed", "planned"}:
            completion_status = selected.get("completion_status")
            no_useful_work = bool(selected.get("no_useful_work"))
            return {
                "status": selected.get("status") or "blocked",
                "contest_id": contest_id,
                "agent": agent,
                "reason": selected.get("reason") or "no_target",
                "selection": selected,
                "completion_status": completion_status or "no_claimable",
                "no_useful_work": no_useful_work,
                "status_summary": selected.get("status_summary") or {},
            }
        effective_challenge = str(selected.get("challenge_id") or "")
    if not effective_challenge:
        return {"status": "blocked", "contest_id": contest_id, "agent": agent, "reason": "challenge_id_missing"}

    triage = triage_challenge(contest_id, challenge_id=effective_challenge, agent=agent)
    if triage.get("status") != "ok":
        return {"status": triage.get("status") or "blocked", "contest_id": contest_id, "agent": agent, "triage": triage}
    starter = starter_challenge(contest_id, challenge_id=str(triage.get("challenge_id") or effective_challenge), category=str(triage.get("category") or ""))
    if starter.get("status") != "ok":
        return {"status": starter.get("status") or "blocked", "contest_id": contest_id, "agent": agent, "triage": triage, "starter": starter}
    return {
        "status": "ok",
        "contest_id": contest_id,
        "agent": agent,
        "challenge_id": triage.get("challenge_id") or effective_challenge,
        "category": triage.get("category") or starter.get("category") or "",
        "target_pack_path": triage.get("target_pack_path") or selected.get("target_pack_path") or "",
        "triage_summary_path": triage.get("triage_summary_path") or "",
        "starter_path": starter.get("starter_path") or "",
        "top_files": triage.get("top_files") or [],
        "first_commands": triage.get("first_commands") or [],
        "next_steps": triage.get("next_steps") or [],
        "selection": selected,
        **({"refresh": refresh_result} if refresh_result else {}),
    }


def run_attempt(
    contest_id: str,
    *,
    challenge_id: str,
    agent: str | None = None,
    command: str | None = None,
    script: str | Path | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": ""}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    challenge_dir.mkdir(parents=True, exist_ok=True)

    resolved = _resolve_attempt_invocation(root, board, item, challenge_key, challenge_dir, command=command, script=script)
    if resolved.get("status") != "ok":
        _append_text(
            challenge_dir / "next_steps.md",
            f"\n- {utc_now()} run-attempt blocked: {resolved.get('reason') or 'command_or_script_missing'}\n",
        )
        return {
            "status": "blocked",
            "contest_id": contest_id,
            "challenge_id": challenge_key,
            "agent": agent or "",
            "reason": resolved.get("reason") or "command_or_script_missing",
        }

    timeout = max(1, int(timeout or 120))
    command_display = str(resolved["command_display"])
    started = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="attempt_started",
        agent=agent,
        challenge_id=challenge_key,
        data={"command": redact_text(command_display), "timeout_sec": timeout},
    )
    started_at = str(started.get("timestamp") or utc_now())
    attempt_dir = challenge_dir / "attempts"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    attempt_path = attempt_dir / f"{_timestamp_filename(started_at)}.json"

    start = time.perf_counter()
    stdout = ""
    stderr = ""
    timed_out = False
    returncode: int | None = None
    error = ""
    try:
        completed = subprocess.run(
            resolved["argv"],
            cwd=challenge_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=bool(resolved.get("shell")),
            timeout=timeout,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        returncode = int(completed.returncode)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = _process_output_text(exc.stdout)
        stderr = _process_output_text(exc.stderr)
        returncode = None
        error = "timeout"
    except OSError as exc:
        stdout = ""
        stderr = str(exc)
        returncode = -1
        error = "execution_error"
    runtime_sec = round(time.perf_counter() - start, 3)
    completed_at = utc_now()
    missing_tool = detect_missing_tool_failure(stdout, stderr) if returncode not in (0, None) or error else None

    policy = load_submit_policy()
    detected = _detect_attempt_candidates(
        contest_id,
        challenge_key,
        stdout=stdout,
        stderr=stderr,
        command=command_display,
        attempt_path=attempt_path,
        timestamp=completed_at,
        policy=policy,
    )
    stored_candidates = _append_detected_candidates(challenge_dir, detected)
    attempt_record = {
        "schema": "interactive_attempt_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "started_at": started_at,
        "completed_at": completed_at,
        "cwd": _display(challenge_dir),
        "command": command_display,
        "script": _display(Path(resolved["script_path"])) if resolved.get("script_path") else "",
        "timeout_sec": timeout,
        "timed_out": timed_out,
        "returncode": returncode,
        "runtime_sec": runtime_sec,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_len": len(stdout),
        "stderr_len": len(stderr),
        "error": error,
        "missing_tool": missing_tool or {},
        "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
        "candidate_count": len(detected),
        "stored_candidate_count": len(stored_candidates),
    }
    _write_json_raw(attempt_path, attempt_record)
    _append_attempt_markdown(challenge_dir, attempt_record, attempt_path, detected)
    _append_attempt_evidence(challenge_dir, attempt_record, attempt_path, detected)
    if missing_tool:
        _append_missing_tool_notes(challenge_dir, missing_tool, attempt_path)
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="missing_tool_observed",
            agent=agent,
            challenge_id=challenge_key,
            data=_missing_tool_metric_payload(missing_tool),
        )

    completed_event = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="attempt_completed",
        agent=agent,
        challenge_id=challenge_key,
        data={
            "command": redact_text(command_display),
            "returncode": returncode,
            "runtime_sec": runtime_sec,
            "timed_out": timed_out,
            "stdout_len": len(stdout),
            "stderr_len": len(stderr),
            "candidate_count": len(detected),
            "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
            "attempt_path": _display(attempt_path),
            "missing_tool": str((missing_tool or {}).get("tool") or ""),
        },
    )
    return {
        "status": "ok" if not timed_out and returncode == 0 else ("timeout" if timed_out else ("missing_tool" if missing_tool else "completed_nonzero")),
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "attempt_path": _display(attempt_path),
        "cwd": _display(challenge_dir),
        "command": command_display,
        "returncode": returncode,
        "runtime_sec": runtime_sec,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "missing_tool": missing_tool or {},
        "candidates": [_candidate_local_payload(row) for row in detected],
        "stored_candidates": [_candidate_local_payload(row) for row in stored_candidates],
        "metrics": {"started_at": started_at, "completed_at": completed_event.get("timestamp")},
    }


def web_config(
    contest_id: str,
    *,
    challenge_id: str,
    base_url: str | None = None,
    auth_source: str | None = None,
    cookie_file: str | Path | None = None,
    header_file: str | Path | None = None,
    storage_state: str | Path | None = None,
    auth_env: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    existing = _web_metadata_for_item(root, board, item, challenge_key)
    context = _target_context(contest_id, root, item)
    resolved_base = str(base_url or existing.get("base_url") or _web_base_url_from_context(context) or "").strip()
    if not resolved_base:
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "reason": "base_url_missing"}
    url_check = _validate_endpoint_url_syntax(resolved_base, label="base_url")
    if not url_check.get("allowed"):
        return {
            "status": "blocked",
            "contest_id": contest_id,
            "challenge_id": challenge_key,
            "reason": url_check.get("reason") or "base_url_invalid",
            "validation": url_check,
        }
    auth = _normalize_web_auth_source(
        auth_source,
        cookie_file=cookie_file,
        header_file=header_file,
        storage_state=storage_state,
        auth_env=auth_env,
        existing=existing.get("auth_source") if isinstance(existing.get("auth_source"), Mapping) else None,
    )
    if auth.get("status") != "ok":
        return {
            "status": "blocked",
            "contest_id": contest_id,
            "challenge_id": challenge_key,
            "reason": auth.get("reason") or "invalid_auth_source",
        }
    metadata = _build_web_metadata(
        challenge_key,
        base_url=resolved_base,
        base_url_source="cli" if base_url else (str(existing.get("base_url_source") or "") or "challenge_metadata"),
        auth_source=auth,
    )
    warnings = _web_config_warnings(root, metadata)
    metadata["warnings"] = warnings
    _save_challenge_web_metadata(root, board, challenge_key, metadata)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="web_configured",
        challenge_id=challenge_key,
        data=_web_metric_payload(metadata, status="ok", extra={"warning_count": len(warnings)}),
    )
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "metadata": _web_public_metadata(metadata),
        "warnings": warnings,
    }


def web_probe(contest_id: str, *, challenge_id: str, timeout: int = 20) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    metadata = _ensure_web_metadata(root, board, item, challenge_key)
    if not metadata or not metadata.get("base_url"):
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "reason": "base_url_missing"}
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    timeout = max(1, int(timeout or 20))
    started_at = utc_now()
    probe_dir = challenge_dir / "web" / "probes"
    probe_path = probe_dir / f"{_timestamp_filename(started_at)}.json"
    auth = _web_live_headers(root, metadata)
    if auth.get("status") != "ok":
        record = _web_probe_error_record(
            contest_id,
            challenge_key,
            metadata,
            started_at=started_at,
            timeout=timeout,
            status="blocked",
            reason=str(auth.get("reason") or "auth_source_unavailable"),
        )
        _write_json_raw(probe_path, record)
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="web_probe_completed",
            challenge_id=challenge_key,
            data=_web_metric_payload(metadata, status="blocked", extra={"reason": record["error"], "probe_path": _display(probe_path)}),
        )
        return _web_probe_public_result(record, probe_path)

    response = _web_fetch(str(metadata["base_url"]), headers=auth.get("headers") or {}, timeout=timeout)
    completed_at = utc_now()
    parsed = _parse_web_probe_response(response, str(metadata["base_url"]))
    record = {
        "schema": "interactive_web_probe_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "started_at": started_at,
        "completed_at": completed_at,
        "timeout_sec": timeout,
        "base_url": _web_public_url(str(metadata.get("base_url") or "")),
        "auth_source": _web_public_auth_source(metadata),
        "client": response.get("client") or "",
        "status": response.get("status") or "error",
        "http_status": response.get("http_status"),
        "final_url": _web_public_url(str(response.get("final_url") or "")),
        "final_path": _web_url_path(str(response.get("final_url") or metadata.get("base_url") or "")),
        "content_type": response.get("content_type") or "",
        "headers_summary": _web_headers_summary(response.get("headers") if isinstance(response.get("headers"), Mapping) else {}),
        "title": parsed.get("title") or "",
        "forms": parsed.get("forms") or [],
        "links": parsed.get("links") or [],
        "scripts": parsed.get("scripts") or [],
        "static_links": parsed.get("static_links") or [],
        "endpoint_candidates": parsed.get("endpoint_candidates") or [],
        "body_len": int(response.get("body_len") or 0),
        "body_sha256": response.get("body_sha256") or "",
        "error": _web_safe_text(str(response.get("error") or ""), limit=300),
    }
    _write_json_raw(probe_path, record)
    _append_text(
        challenge_dir / "attempts.md",
        f"\n- web_probe: status={record['status']} http={record['http_status']} title={record['title'] or 'none'} record={_display(probe_path)} ({completed_at})\n",
    )
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="web_probe_completed",
        challenge_id=challenge_key,
        data=_web_metric_payload(
            metadata,
            status=str(record["status"]),
            extra={
                "http_status": record["http_status"],
                "form_count": len(record["forms"]),
                "link_count": len(record["links"]),
                "script_count": len(record["scripts"]),
                "endpoint_candidate_count": len(record["endpoint_candidates"]),
                "probe_path": _display(probe_path),
            },
        ),
    )
    return _web_probe_public_result(record, probe_path)


def browser_probe(contest_id: str, *, challenge_id: str, timeout: int = 30) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    metadata = _ensure_web_metadata(root, board, item, challenge_key)
    if not metadata or not metadata.get("base_url"):
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "reason": "base_url_missing"}
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    timeout = max(1, int(timeout or 30))
    started_at = utc_now()
    browser_dir = challenge_dir / "web" / "browser_probes"
    browser_dir.mkdir(parents=True, exist_ok=True)
    probe_path = browser_dir / f"{_timestamp_filename(started_at)}.json"
    screenshot_path = challenge_dir / "web" / "screenshots" / f"probe-{_timestamp_filename(started_at)}.png"

    capture = _web_browser_capture(
        root,
        metadata,
        screenshot_path=screenshot_path,
        timeout=timeout,
        kind="probe",
    )
    completed_at = utc_now()
    record = {
        "schema": "interactive_browser_probe_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "started_at": started_at,
        "completed_at": completed_at,
        "timeout_sec": timeout,
        "base_url": _web_public_url(str(metadata.get("base_url") or "")),
        "auth_source": _web_public_auth_source(metadata),
        **capture,
    }
    _write_json_raw(probe_path, record)
    _append_text(
        challenge_dir / "attempts.md",
        f"\n- browser_probe: status={record['status']} title={record.get('title') or 'none'} screenshot={record.get('screenshot_path') or 'none'} record={_display(probe_path)} ({completed_at})\n",
    )
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="browser_probe_completed",
        challenge_id=challenge_key,
        data=_web_metric_payload(
            metadata,
            status=str(record["status"]),
            extra={
                "network_count": len(record.get("network_summary") or []),
                "console_count": len(record.get("console_summary") or []),
                "screenshot_present": bool(record.get("screenshot_path")),
                "probe_path": _display(probe_path),
            },
        ),
    )
    return _browser_probe_public_result(record, probe_path)


def web_attempt(
    contest_id: str,
    *,
    challenge_id: str,
    script: str | Path | None = None,
    request_json: str | Path | None = None,
    timeout: int = 60,
    agent: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": "web"}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    challenge_dir.mkdir(parents=True, exist_ok=True)
    metadata = _ensure_web_metadata(root, board, item, challenge_key)
    if not metadata or not metadata.get("base_url"):
        _append_text(challenge_dir / "next_steps.md", f"\n- {utc_now()} web-attempt blocked: base URL missing\n")
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "agent": agent or "", "reason": "base_url_missing"}
    if script and request_json:
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "agent": agent or "", "reason": "script_and_request_json_are_mutually_exclusive"}
    timeout = max(1, int(timeout or 60))
    started = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="web_attempt_started",
        agent=agent,
        challenge_id=challenge_key,
        data=_web_metric_payload(metadata, status="started", extra={"timeout_sec": timeout, "mode": "script" if script else "request_json"}),
    )
    started_at = str(started.get("timestamp") or utc_now())
    attempt_dir = challenge_dir / "web" / "attempts"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    attempt_path = attempt_dir / f"{_timestamp_filename(started_at)}.json"

    if request_json:
        execution = _run_web_request_json(request_json, root=root, challenge_dir=challenge_dir, metadata=metadata, timeout=timeout)
    else:
        execution = _run_web_attempt_script(script, root=root, challenge_dir=challenge_dir, contest_id=contest_id, challenge_id=challenge_key, metadata=metadata, timeout=timeout)
    if execution.get("status") == "blocked":
        reason = str(execution.get("reason") or "web_attempt_unavailable")
        _append_text(challenge_dir / "next_steps.md", f"\n- {utc_now()} web-attempt blocked: {reason}\n")
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "agent": agent or "", "reason": reason}

    completed_at = utc_now()
    stdout = _web_auth_sanitize_text(str(execution.get("stdout") or ""))
    stderr = _web_auth_sanitize_text(str(execution.get("stderr") or ""))
    runtime_sec = float(execution.get("runtime_sec") or 0.0)
    timed_out = bool(execution.get("timed_out"))
    returncode = execution.get("returncode")
    command_display = str(execution.get("command") or "")
    missing_tool = detect_missing_tool_failure(stdout, stderr) if returncode not in (0, None) or execution.get("error") else None
    policy = load_submit_policy()
    detected = _detect_attempt_candidates(
        contest_id,
        challenge_key,
        stdout=stdout,
        stderr=stderr,
        command=command_display,
        attempt_path=attempt_path,
        timestamp=completed_at,
        policy=policy,
    )
    for row in detected:
        if str(row.get("source") or "") == "attempt_stdout":
            row["source"] = "web_response" if request_json else "web_stdout"
        elif str(row.get("source") or "") == "attempt_stderr":
            row["source"] = "web_stderr"
        row["derivation"] = "detected by interactive web-attempt"
    stored_candidates = _append_detected_candidates(challenge_dir, detected)
    attempt_record = {
        "schema": "interactive_web_attempt_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "started_at": started_at,
        "completed_at": completed_at,
        "cwd": _display(challenge_dir),
        "command": command_display,
        "script": _display(Path(script).expanduser()) if script else "",
        "request_json": _display(Path(request_json).expanduser()) if request_json else "",
        "timeout_sec": timeout,
        "timed_out": timed_out,
        "returncode": returncode,
        "runtime_sec": runtime_sec,
        "base_url": _web_public_url(str(metadata.get("base_url") or "")),
        "auth_source": _web_public_auth_source(metadata),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_len": len(stdout),
        "stderr_len": len(stderr),
        "error": _web_safe_text(str(execution.get("error") or ""), limit=300),
        "response": execution.get("response") if isinstance(execution.get("response"), Mapping) else {},
        "missing_tool": missing_tool or {},
        "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
        "candidate_count": len(detected),
        "stored_candidate_count": len(stored_candidates),
        "attempt_kind": "web",
    }
    _write_json_raw(attempt_path, attempt_record)
    _append_attempt_markdown(challenge_dir, attempt_record, attempt_path, detected)
    _append_attempt_evidence(challenge_dir, attempt_record, attempt_path, detected)
    if missing_tool:
        _append_missing_tool_notes(challenge_dir, missing_tool, attempt_path)
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="missing_tool_observed",
            agent=agent,
            challenge_id=challenge_key,
            data=_missing_tool_metric_payload(missing_tool),
        )
    if detected:
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="web_candidate_found",
            agent=agent,
            challenge_id=challenge_key,
            data={"candidate_count": len(detected), "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected]},
        )
    completed_event = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="web_attempt_completed",
        agent=agent,
        challenge_id=challenge_key,
        data=_web_metric_payload(
            metadata,
            status="timeout" if timed_out else ("ok" if returncode in {0, None} and not execution.get("error") else "completed_nonzero"),
            extra={
                "runtime_sec": runtime_sec,
                "timed_out": timed_out,
                "returncode": returncode,
                "stdout_len": len(stdout),
                "stderr_len": len(stderr),
                "candidate_count": len(detected),
                "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
                "attempt_path": _display(attempt_path),
            },
        ),
    )
    status = "timeout" if timed_out else ("missing_tool" if missing_tool else ("ok" if returncode in {0, None} and not execution.get("error") else "completed_nonzero"))
    return {
        "status": status,
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "attempt_path": _display(attempt_path),
        "cwd": _display(challenge_dir),
        "command": command_display,
        "returncode": returncode,
        "runtime_sec": runtime_sec,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "response": attempt_record["response"],
        "missing_tool": missing_tool or {},
        "candidates": [_candidate_local_payload(row) for row in detected],
        "stored_candidates": [_candidate_local_payload(row) for row in stored_candidates],
        "metrics": {"started_at": started_at, "completed_at": completed_event.get("timestamp")},
        "attempt_kind": "web",
    }


def browser_attempt(
    contest_id: str,
    *,
    challenge_id: str,
    script: str | Path,
    timeout: int = 90,
    agent: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": "web"}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    challenge_dir.mkdir(parents=True, exist_ok=True)
    metadata = _ensure_web_metadata(root, board, item, challenge_key)
    if not metadata or not metadata.get("base_url"):
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "agent": agent or "", "reason": "base_url_missing"}
    timeout = max(1, int(timeout or 90))
    started = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="browser_attempt_started",
        agent=agent,
        challenge_id=challenge_key,
        data=_web_metric_payload(metadata, status="started", extra={"timeout_sec": timeout}),
    )
    started_at = str(started.get("timestamp") or utc_now())
    attempt_dir = challenge_dir / "web" / "browser_attempts"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    timestamp_slug = _timestamp_filename(started_at)
    attempt_path = attempt_dir / f"{timestamp_slug}.json"
    artifact_dir = attempt_dir / timestamp_slug
    artifact_dir.mkdir(parents=True, exist_ok=True)
    env = _web_script_env(root, contest_id=contest_id, challenge_id=challenge_key, metadata=metadata)
    env.update(
        {
            "CTF_BROWSER_ARTIFACT_DIR": _display(artifact_dir),
            "CTF_BROWSER_SCREENSHOT": _display(artifact_dir / "screenshot.png"),
            "CTF_BROWSER_CONSOLE_JSONL": _display(artifact_dir / "console.jsonl"),
            "CTF_BROWSER_NETWORK_JSONL": _display(artifact_dir / "network.jsonl"),
        }
    )
    execution = _run_script_with_env(
        script,
        challenge_dir=challenge_dir,
        env_updates=env,
        timeout=timeout,
    )
    if execution.get("status") == "blocked":
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "agent": agent or "", "reason": execution.get("reason") or "script_not_found"}
    script_screenshot = _existing_artifact_path(artifact_dir / "screenshot.png")
    script_console = _read_jsonl(artifact_dir / "console.jsonl")
    script_network = _read_jsonl(artifact_dir / "network.jsonl")
    capture: dict[str, Any] = {}
    if not script_screenshot:
        capture = _web_browser_capture(
            root,
            metadata,
            screenshot_path=artifact_dir / "post-script-screenshot.png",
            timeout=min(timeout, 30),
            kind="attempt",
        )
    completed_at = utc_now()
    stdout = _web_auth_sanitize_text(str(execution.get("stdout") or ""))
    stderr = _web_auth_sanitize_text(str(execution.get("stderr") or ""))
    runtime_sec = float(execution.get("runtime_sec") or 0.0)
    timed_out = bool(execution.get("timed_out"))
    returncode = execution.get("returncode")
    command_display = str(execution.get("command") or "")
    console_summary = _web_artifact_console_summary(script_console) or list(capture.get("console_summary") or [])
    network_summary = _web_artifact_network_summary(script_network) or list(capture.get("network_summary") or [])
    screenshot = script_screenshot or str(capture.get("screenshot_path") or "")
    policy = load_submit_policy()
    detected = _detect_attempt_candidates(
        contest_id,
        challenge_key,
        stdout="\n".join([stdout, _jsonl_text_for_candidate_scan(script_console), _jsonl_text_for_candidate_scan(script_network)]),
        stderr=stderr,
        command=command_display,
        attempt_path=attempt_path,
        timestamp=completed_at,
        policy=policy,
    )
    for row in detected:
        if str(row.get("source") or "") == "attempt_stdout":
            row["source"] = "browser_output"
        elif str(row.get("source") or "") == "attempt_stderr":
            row["source"] = "browser_stderr"
        row["derivation"] = "detected by interactive browser-attempt"
    stored_candidates = _append_detected_candidates(challenge_dir, detected)
    missing_tool = detect_missing_tool_failure(stdout, stderr) if returncode not in (0, None) or execution.get("error") else None
    attempt_record = {
        "schema": "interactive_browser_attempt_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "started_at": started_at,
        "completed_at": completed_at,
        "cwd": _display(challenge_dir),
        "command": command_display,
        "script": _display(Path(script).expanduser()),
        "timeout_sec": timeout,
        "timed_out": timed_out,
        "returncode": returncode,
        "runtime_sec": runtime_sec,
        "base_url": _web_public_url(str(metadata.get("base_url") or "")),
        "auth_source": _web_public_auth_source(metadata),
        "artifact_dir": _display(artifact_dir),
        "screenshot_path": screenshot,
        "console_summary": console_summary[:WEB_BROWSER_CONSOLE_LIMIT],
        "network_summary": network_summary[:WEB_BROWSER_NETWORK_LIMIT],
        "browser_capture_status": capture.get("status") or ("script_artifacts" if script_screenshot else "not_attempted"),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_len": len(stdout),
        "stderr_len": len(stderr),
        "error": _web_safe_text(str(execution.get("error") or capture.get("error") or ""), limit=300),
        "missing_tool": missing_tool or {},
        "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
        "candidate_count": len(detected),
        "stored_candidate_count": len(stored_candidates),
        "attempt_kind": "browser",
    }
    _write_json_raw(attempt_path, attempt_record)
    _append_attempt_markdown(challenge_dir, attempt_record, attempt_path, detected)
    _append_attempt_evidence(challenge_dir, attempt_record, attempt_path, detected)
    if missing_tool:
        _append_missing_tool_notes(challenge_dir, missing_tool, attempt_path)
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="missing_tool_observed",
            agent=agent,
            challenge_id=challenge_key,
            data=_missing_tool_metric_payload(missing_tool),
        )
    completed_event = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="browser_attempt_completed",
        agent=agent,
        challenge_id=challenge_key,
        data=_web_metric_payload(
            metadata,
            status="timeout" if timed_out else ("ok" if returncode == 0 else "completed_nonzero"),
            extra={
                "runtime_sec": runtime_sec,
                "timed_out": timed_out,
                "returncode": returncode,
                "stdout_len": len(stdout),
                "stderr_len": len(stderr),
                "network_count": len(attempt_record["network_summary"]),
                "console_count": len(attempt_record["console_summary"]),
                "screenshot_present": bool(screenshot),
                "candidate_count": len(detected),
                "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
                "attempt_path": _display(attempt_path),
            },
        ),
    )
    status = "timeout" if timed_out else ("missing_tool" if missing_tool else ("ok" if returncode == 0 else "completed_nonzero"))
    return {
        "status": status,
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "attempt_path": _display(attempt_path),
        "cwd": _display(challenge_dir),
        "command": command_display,
        "returncode": returncode,
        "runtime_sec": runtime_sec,
        "timed_out": timed_out,
        "screenshot_path": screenshot,
        "console_summary": attempt_record["console_summary"],
        "network_summary": attempt_record["network_summary"],
        "stdout": stdout,
        "stderr": stderr,
        "missing_tool": missing_tool or {},
        "candidates": [_candidate_local_payload(row) for row in detected],
        "stored_candidates": [_candidate_local_payload(row) for row in stored_candidates],
        "metrics": {"started_at": started_at, "completed_at": completed_event.get("timestamp")},
        "attempt_kind": "browser",
    }


def web_status(contest_id: str, *, challenge_id: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    metadata = _web_metadata_for_item(root, board, item, challenge_key)
    derived = False
    if not metadata:
        context = _target_context(contest_id, root, item)
        base_url = _web_base_url_from_context(context)
        if base_url:
            metadata = _build_web_metadata(
                challenge_key,
                base_url=base_url,
                base_url_source="challenge_metadata",
                auth_source={"status": "ok", "type": "none"},
            )
            derived = True
    challenge_dir = _challenge_path(contest_id, item)
    last_probe = _last_web_record(challenge_dir / "web" / "probes")
    last_browser_probe = _last_web_record(challenge_dir / "web" / "browser_probes")
    last_attempt = _last_web_record(challenge_dir / "web" / "attempts")
    last_browser_attempt = _last_web_record(challenge_dir / "web" / "browser_attempts")
    candidates = _coalesced_candidates(challenge_dir)
    screenshot_present = bool(
        _record_has_screenshot(last_browser_probe)
        or _record_has_screenshot(last_browser_attempt)
        or list((challenge_dir / "web" / "screenshots").glob("*.png"))
    )
    return {
        "status": "ok" if metadata else "unconfigured",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "configured": bool(metadata and not derived),
        "derived_from_challenge_metadata": derived,
        "base_url": _web_public_url(str(metadata.get("base_url") or "")) if metadata else "",
        "auth_source": _web_public_auth_source(metadata) if metadata else {"type": "none"},
        "auth_source_present": _web_auth_source_present(root, metadata) if metadata else False,
        "last_probe": _web_record_summary(last_probe),
        "last_browser_probe": _web_record_summary(last_browser_probe),
        "last_attempt": _web_record_summary(last_attempt),
        "last_browser_attempt": _web_record_summary(last_browser_attempt),
        "screenshot_present": screenshot_present,
        "candidate_count": len(candidates),
    }


def service_config(
    contest_id: str,
    *,
    challenge_id: str,
    host: str | None = None,
    port: int | None = None,
    tls: bool = False,
    plain: bool = False,
    token_source: str | None = None,
    token_file: str | Path | None = None,
    token_env: str | None = None,
    pow_helper: str | Path | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    if tls and plain:
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_id, "reason": "tls_and_plain_are_mutually_exclusive"}
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    context = _target_context(contest_id, root, item)
    endpoint = _service_endpoint_from_args(host=host, port=port, tls=tls, plain=plain)
    source = "cli"
    if endpoint is None:
        endpoint = _service_endpoint_from_context(context)
        source = "challenge_metadata"
    if endpoint is None:
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "reason": "service_endpoint_missing"}
    if tls:
        endpoint["transport"] = "tls"
    elif plain:
        endpoint["transport"] = "plain"

    token = _normalize_service_token_source(token_source, token_file=token_file, token_env=token_env)
    if token.get("status") != "ok":
        return {
            "status": "blocked",
            "contest_id": contest_id,
            "challenge_id": challenge_key,
            "reason": token.get("reason") or "invalid_token_source",
        }

    metadata = _build_service_metadata(
        challenge_key,
        endpoint=endpoint,
        endpoint_source=source,
        token_source=token,
        pow_helper=pow_helper,
    )
    warnings = _service_config_warnings(root, metadata)
    metadata["warnings"] = warnings
    _save_challenge_service_metadata(root, board, challenge_key, metadata)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="service_configured",
        challenge_id=challenge_key,
        data=_service_metric_payload(metadata, status="ok", extra={"warning_count": len(warnings)}),
    )
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "metadata": _service_public_metadata(metadata),
        "warnings": warnings,
    }


def service_probe(
    contest_id: str,
    *,
    challenge_id: str,
    timeout: int = 10,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    metadata = _ensure_service_metadata(root, board, item, challenge_key)
    if not metadata:
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "reason": "service_endpoint_missing"}
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    timeout = max(1, int(timeout or 10))
    started_at = utc_now()
    probe = _service_probe_connection(metadata, timeout=timeout)
    completed_at = utc_now()
    transcript = _service_sanitize_text(str(probe.get("transcript") or ""))
    prompts = _detect_service_prompts(transcript)
    probe_dir = challenge_dir / "service" / "probes"
    probe_path = probe_dir / f"{_timestamp_filename(started_at)}.json"
    record = {
        "schema": "interactive_service_probe_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "started_at": started_at,
        "completed_at": completed_at,
        "timeout_sec": timeout,
        "endpoint": _service_endpoint_public(metadata),
        "status": probe.get("status") or "error",
        "transport": probe.get("transport") or _service_endpoint_public(metadata).get("transport"),
        "connector": probe.get("connector") or "",
        "error": _safe_public_note(str(probe.get("error") or ""), limit=240),
        "banner": _service_text_preview(transcript, 4000),
        "transcript": transcript,
        "transcript_len": len(transcript),
        "prompts": prompts,
    }
    _write_json_raw(probe_path, record)
    _append_text(
        challenge_dir / "attempts.md",
        f"\n- service_probe: status={record['status']} transport={record['transport']} prompts={_service_prompt_summary(prompts)} record={_display(probe_path)} ({completed_at})\n",
    )
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="service_probe_completed",
        challenge_id=challenge_key,
        data=_service_metric_payload(
            metadata,
            status=str(record["status"]),
            extra={
                "transport": record["transport"],
                "token_prompt_detected": bool(prompts["token_prompt"]),
                "pow_prompt_detected": bool(prompts["pow_prompt"]),
                "menu_prompt_detected": bool(prompts["menu_prompt"]),
                "transcript_len": len(transcript),
                "probe_path": _display(probe_path),
            },
        ),
    )
    if prompts["token_prompt"]:
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="service_token_prompt_detected",
            challenge_id=challenge_key,
            data=_service_metric_payload(metadata, status=str(record["status"])),
        )
    if prompts["pow_prompt"]:
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="service_pow_prompt_detected",
            challenge_id=challenge_key,
            data=_service_metric_payload(metadata, status=str(record["status"])),
        )
    return {
        "status": record["status"],
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "endpoint": record["endpoint"],
        "transport": record["transport"],
        "connector": record["connector"],
        "banner": record["banner"],
        "prompts": prompts,
        "token_prompt_detected": bool(prompts["token_prompt"]),
        "pow_prompt_detected": bool(prompts["pow_prompt"]),
        "menu_prompt_detected": bool(prompts["menu_prompt"]),
        "probe_path": _display(probe_path),
        "error": record["error"],
    }


def service_attempt(
    contest_id: str,
    *,
    challenge_id: str,
    script: str | Path | None = None,
    payload_file: str | Path | None = None,
    timeout: int = 60,
    agent: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": ""}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    challenge_dir.mkdir(parents=True, exist_ok=True)
    metadata = _ensure_service_metadata(root, board, item, challenge_key)
    if not metadata:
        _append_text(challenge_dir / "next_steps.md", f"\n- {utc_now()} service-attempt blocked: service endpoint missing\n")
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "agent": agent or "", "reason": "service_endpoint_missing"}

    timeout = max(1, int(timeout or 60))
    started = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="service_attempt_started",
        agent=agent,
        challenge_id=challenge_key,
        data=_service_metric_payload(metadata, status="started", extra={"timeout_sec": timeout}),
    )
    started_at = str(started.get("timestamp") or utc_now())
    attempt_dir = challenge_dir / "service" / "attempts"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    attempt_path = attempt_dir / f"{_timestamp_filename(started_at)}.json"

    script_result = _run_service_payload_script(
        script,
        root=root,
        challenge_dir=challenge_dir,
        contest_id=contest_id,
        challenge_id=challenge_key,
        metadata=metadata,
        timeout=timeout,
    )
    payload_result = _read_service_payload_file(payload_file, challenge_dir=challenge_dir)
    if script_result.get("status") == "blocked" or payload_result.get("status") == "blocked":
        reason = str(script_result.get("reason") or payload_result.get("reason") or "payload_unavailable")
        return {"status": "blocked", "contest_id": contest_id, "challenge_id": challenge_key, "agent": agent or "", "reason": reason}
    script_missing_tool = detect_missing_tool_failure(str(script_result.get("stdout") or ""), str(script_result.get("stderr") or ""))

    secrets: list[str] = []
    transcript_chunks: list[str] = []
    token_injected = False
    pow_injected = False
    connection_status = "error"
    transport = ""
    connector = ""
    error = ""
    timed_out = False
    start = time.perf_counter()
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        if script_missing_tool:
            connection_status = "missing_tool"
            error = "missing_tool"
            raise StopIteration
        opened = _open_service_connection(metadata, timeout=timeout)
        sock = opened["socket"]
        transport = str(opened.get("transport") or "")
        connector = str(opened.get("connector") or "")
        initial = _service_recv_text(sock, timeout=min(timeout, 8), limit=SERVICE_TRANSCRIPT_LIMIT)
        transcript_chunks.append(initial)
        prompts = _detect_service_prompts(initial)
        if prompts["token_prompt"]:
            token_result = _read_service_token(root, metadata)
            if token_result.get("status") != "ok":
                connection_status = "blocked"
                error = str(token_result.get("reason") or "service_token_unavailable")
                _record_metrics_event(
                    root,
                    contest_id=contest_id,
                    event="service_token_prompt_detected",
                    agent=agent,
                    challenge_id=challenge_key,
                    data=_service_metric_payload(metadata, status="blocked"),
                )
            else:
                token_value = str(token_result.get("value") or "")
                if token_value:
                    secrets.append(token_value)
                    _service_send_line(sock, token_value.encode("utf-8", errors="replace"))
                    token_injected = True
                    transcript_chunks.append("[SERVICE_TOKEN_INJECTED]\n")
                    transcript_chunks.append(_service_recv_text(sock, timeout=min(timeout, 8), limit=SERVICE_TRANSCRIPT_LIMIT))
                    _record_metrics_event(
                        root,
                        contest_id=contest_id,
                        event="service_token_prompt_detected",
                        agent=agent,
                        challenge_id=challenge_key,
                        data=_service_metric_payload(metadata, status="injected"),
                    )
        if connection_status != "blocked":
            current = "".join(transcript_chunks)
            prompts = _detect_service_prompts(current)
            if prompts["pow_prompt"]:
                pow_result = _run_service_pow_helper(metadata, current, timeout=timeout, challenge_dir=challenge_dir)
                if pow_result.get("status") == "ok" and pow_result.get("solution"):
                    _service_send_line(sock, str(pow_result["solution"]).encode("utf-8", errors="replace"))
                    pow_injected = True
                    transcript_chunks.append("[SERVICE_POW_RESPONSE_INJECTED]\n")
                    transcript_chunks.append(_service_recv_text(sock, timeout=min(timeout, 8), limit=SERVICE_TRANSCRIPT_LIMIT))
                else:
                    connection_status = "blocked"
                    error = str(pow_result.get("reason") or "service_pow_unavailable")
                _record_metrics_event(
                    root,
                    contest_id=contest_id,
                    event="service_pow_prompt_detected",
                    agent=agent,
                    challenge_id=challenge_key,
                    data=_service_metric_payload(metadata, status="injected" if pow_injected else "blocked"),
                )
        if connection_status != "blocked":
            payloads = []
            payloads.extend(payload_result.get("payloads") or [])
            payloads.extend(script_result.get("payloads") or [])
            for payload in payloads:
                data = bytes(payload)
                if data and not data.endswith(b"\n"):
                    data += b"\n"
                if data:
                    sock.sendall(data)
            if payloads:
                transcript_chunks.append(f"[SERVICE_PAYLOAD_SENT bytes={sum(len(bytes(item)) for item in payloads)}]\n")
                transcript_chunks.append(_service_recv_text(sock, timeout=min(timeout, 8), limit=SERVICE_TRANSCRIPT_LIMIT))
            connection_status = "ok"
    except TimeoutError:
        timed_out = True
        connection_status = "timeout"
        error = "timeout"
    except StopIteration:
        pass
    except OSError as exc:
        connection_status = "error"
        error = _safe_public_note(str(exc), limit=240)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    runtime_sec = round(time.perf_counter() - start, 3)
    completed_at = utc_now()
    raw_transcript = "".join(transcript_chunks)
    stdout = _service_sanitize_text(str(script_result.get("stdout") or ""), secrets=secrets)
    stderr = _service_sanitize_text(str(script_result.get("stderr") or ""), secrets=secrets)
    transcript = _service_sanitize_text(raw_transcript, secrets=secrets)
    command_display = _service_attempt_command_display(metadata, script=script, payload_file=payload_file)
    policy = load_submit_policy()
    detected = _detect_attempt_candidates(
        contest_id,
        challenge_key,
        stdout="\n".join([transcript, stdout]),
        stderr=stderr,
        command=command_display,
        attempt_path=attempt_path,
        timestamp=completed_at,
        policy=policy,
    )
    for row in detected:
        if str(row.get("source") or "") == "attempt_stdout":
            row["source"] = "service_transcript"
            row["derivation"] = "detected by interactive service-attempt"
        elif str(row.get("source") or "") == "attempt_stderr":
            row["source"] = "service_script_stderr"
            row["derivation"] = "detected by interactive service-attempt"
    stored_candidates = _append_detected_candidates(challenge_dir, detected)
    attempt_record = {
        "schema": "interactive_service_attempt_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "started_at": started_at,
        "completed_at": completed_at,
        "cwd": _display(challenge_dir),
        "command": command_display,
        "script": _display(Path(script).expanduser()) if script else "",
        "payload_file": _display(Path(payload_file).expanduser()) if payload_file else "",
        "timeout_sec": timeout,
        "timed_out": timed_out,
        "returncode": script_result.get("returncode"),
        "runtime_sec": runtime_sec,
        "endpoint": _service_endpoint_public(metadata),
        "transport": transport,
        "connector": connector,
        "token_injected": token_injected,
        "pow_injected": pow_injected,
        "transcript": transcript,
        "transcript_len": len(transcript),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_len": len(stdout),
        "stderr_len": len(stderr),
        "error": error,
        "missing_tool": script_missing_tool or {},
        "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
        "candidate_count": len(detected),
        "stored_candidate_count": len(stored_candidates),
        "attempt_kind": "service",
    }
    _write_json_raw(attempt_path, attempt_record)
    _append_attempt_markdown(challenge_dir, attempt_record, attempt_path, detected)
    _append_attempt_evidence(challenge_dir, attempt_record, attempt_path, detected)
    if script_missing_tool:
        _append_missing_tool_notes(challenge_dir, script_missing_tool, attempt_path)
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="missing_tool_observed",
            agent=agent,
            challenge_id=challenge_key,
            data=_missing_tool_metric_payload(script_missing_tool),
        )
    if detected:
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="service_candidate_found",
            agent=agent,
            challenge_id=challenge_key,
            data={
                "candidate_count": len(detected),
                "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
                "sources": _dedupe_strings(str(row.get("source") or "") for row in detected),
            },
        )
    completed_event = _record_metrics_event(
        root,
        contest_id=contest_id,
        event="service_attempt_completed",
        agent=agent,
        challenge_id=challenge_key,
        data=_service_metric_payload(
            metadata,
            status=connection_status,
            extra={
                "transport": transport,
                "runtime_sec": runtime_sec,
                "timed_out": timed_out,
                "token_injected": token_injected,
                "pow_injected": pow_injected,
                "transcript_len": len(transcript),
                "stdout_len": len(stdout),
                "stderr_len": len(stderr),
                "candidate_count": len(detected),
                "candidate_hashes": [str(row.get("flag_hash") or "") for row in detected],
                "attempt_path": _display(attempt_path),
            },
        ),
    )
    return {
        "status": connection_status,
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "agent": agent or "",
        "attempt_path": _display(attempt_path),
        "cwd": _display(challenge_dir),
        "endpoint": _service_endpoint_public(metadata),
        "transport": transport,
        "connector": connector,
        "command": command_display,
        "returncode": script_result.get("returncode"),
        "runtime_sec": runtime_sec,
        "timed_out": timed_out,
        "token_injected": token_injected,
        "pow_injected": pow_injected,
        "transcript": transcript,
        "stdout": stdout,
        "stderr": stderr,
        "error": error,
        "missing_tool": script_missing_tool or {},
        "candidates": [_candidate_local_payload(row) for row in detected],
        "stored_candidates": [_candidate_local_payload(row) for row in stored_candidates],
        "metrics": {"started_at": started_at, "completed_at": completed_event.get("timestamp")},
        "attempt_kind": "service",
    }


def service_status(contest_id: str, *, challenge_id: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    item = _find_challenge(board, challenge_id)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge_id": challenge_id}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    metadata = _service_metadata_for_item(root, board, item, challenge_key)
    derived = False
    if not metadata:
        context = _target_context(contest_id, root, item)
        endpoint = _service_endpoint_from_context(context)
        if endpoint:
            metadata = _build_service_metadata(
                challenge_key,
                endpoint=endpoint,
                endpoint_source="challenge_metadata",
                token_source={"type": "none"},
                pow_helper=None,
            )
            derived = True
    challenge_dir = _challenge_path(contest_id, item)
    last_probe = _last_service_record(challenge_dir / "service" / "probes")
    last_attempt = _last_service_record(challenge_dir / "service" / "attempts")
    token_present = _service_token_source_present(root, metadata) if metadata else False
    return {
        "status": "ok" if metadata else "unconfigured",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "configured": bool(metadata and not derived),
        "derived_from_challenge_metadata": derived,
        "endpoint": _service_endpoint_public(metadata) if metadata else {},
        "recommended_connect_command": metadata.get("recommended_connect_command") if metadata else "",
        "last_probe": _service_record_summary(last_probe),
        "last_attempt": _service_record_summary(last_attempt),
        "prompt_type": _service_prompt_summary((last_probe or {}).get("prompts") if isinstance(last_probe, Mapping) else {}),
        "token_source": _service_public_token_source(metadata) if metadata else {"type": "none"},
        "token_source_present": token_present,
        "pow_helper_present": bool(metadata and (metadata.get("pow_helper") or {}).get("path")),
    }


def list_candidates(contest_id: str, *, challenge_id: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": ""}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    challenge_dir = _challenge_path(contest_id, item)
    rows = _coalesced_candidates(challenge_dir)
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "candidate_store": _display(_candidate_store_path(challenge_dir)),
        "count": len(rows),
        "candidates": [_candidate_local_payload(row) for row in rows],
    }


def verify_candidate(
    contest_id: str,
    *,
    challenge_id: str,
    candidate: str | None = None,
    candidate_file: str | Path | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": ""}
    challenge_key = str(item.get("challenge_id") or challenge_id)
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)

    selected = _select_candidate_for_verification(challenge_dir, candidate=candidate, candidate_file=candidate_file)
    value = str(selected.get("value") or "")
    if not value:
        return {"status": "blocked", "reason": "candidate_missing", "contest_id": contest_id, "challenge_id": challenge_key}

    policy = load_submit_policy()
    submissions = _read_jsonl(root / "submissions.jsonl")
    previous = [row for row in submissions if str(row.get("challenge_id")) == challenge_key]
    context = _verification_context(selected)
    classification = classify_flag_confidence(value, context=context, policy=policy)
    decision = should_submit(
        value,
        policy,
        previous_submissions=previous,
        challenge_state={"challenge_id": challenge_key, "status": item.get("status") or "todo", "solved": _is_solved(root, item)},
        context=context,
    )
    digest = str(classification.get("flag_hash") or hash_flag(value))
    duplicate = any(str(row.get("flag_hash") or "") == digest and str(row.get("status") or "").lower() in {"submitted", "accepted", "rejected", "rate_limited", "wrong", "incorrect"} for row in previous)
    previous_wrong = [row for row in previous if str(row.get("status") or "").lower() in {"wrong", "incorrect", "rejected"}]
    confidence = str(classification.get("confidence") or "none")
    verification_status = _verification_status(confidence, decision, classification, duplicate)

    record = {
        "schema": "interactive_candidate_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "value": value,
        "flag_hash": digest,
        "length": len(value),
        "source": str(selected.get("source") or "manual_candidate"),
        "evidence_source": str(selected.get("evidence_source") or ""),
        "command": str(selected.get("command") or ""),
        "timestamp": utc_now(),
        "status": verification_status,
        "confidence": confidence,
        "fake_likely": bool(classification.get("fake_likely")),
        "matches_flag_regex": bool(classification.get("matches_flag_regex")),
        "duplicate": duplicate,
        "previous_wrong_count": len(previous_wrong),
        "decision": {key: value for key, value in decision.items() if key != "candidate_preview"},
    }
    _append_jsonl_raw(_candidate_store_path(challenge_dir), record)
    _append_candidate_verification_evidence(challenge_dir, record)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="candidate_verified",
        challenge_id=challenge_key,
        data={
            "flag_hash": digest,
            "length": len(value),
            "source": record["source"],
            "status": verification_status,
            "confidence": confidence,
            "fake_likely": bool(classification.get("fake_likely")),
            "duplicate": duplicate,
            "previous_wrong_count": len(previous_wrong),
            "submit_allowed": bool(decision.get("allowed")),
            "reason": decision.get("reason"),
        },
    )
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "candidate": value,
        "candidate_hash": digest,
        "length": len(value),
        "confidence": confidence,
        "verification_status": verification_status,
        "format_valid": bool(classification.get("matches_flag_regex")),
        "fake_likely": bool(classification.get("fake_likely")),
        "duplicate": duplicate,
        "previous_wrong_count": len(previous_wrong),
        "submit_allowed": bool(decision.get("allowed")),
        "reason": decision.get("reason"),
        "classification": classification,
        "decision": {key: value for key, value in decision.items() if key != "candidate_preview"},
        "candidate_store": _display(_candidate_store_path(challenge_dir)),
    }


def solve_loop(
    contest_id: str,
    *,
    agent: str,
    challenge_id: str | None = None,
    max_attempts: int = 5,
) -> dict[str, Any]:
    init_operator(contest_id)
    prepared = prepare_target(contest_id, agent=agent, challenge_id=challenge_id)
    if prepared.get("status") != "ok":
        return {
            "status": prepared.get("status") or "blocked",
            "contest_id": contest_id,
            "agent": agent,
            "reason": prepared.get("reason") or "prepare_target_failed",
            "prepare_target": prepared,
        }

    challenge_key = str(prepared.get("challenge_id") or challenge_id or "")
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_key) or {"challenge_id": challenge_key, "name": challenge_key, "category": prepared.get("category") or ""}
    challenge_dir = _challenge_path(contest_id, item)
    starter_path = str(prepared.get("starter_path") or "")
    if not starter_path:
        starter = starter_challenge(contest_id, challenge_id=challenge_key, category=str(prepared.get("category") or ""))
        starter_path = str(starter.get("starter_path") or "")
    starter_fs_path = _undisplay_path(starter_path) if starter_path else None
    if not starter_fs_path or not starter_fs_path.exists():
        _append_text(challenge_dir / "next_steps.md", f"\n- {utc_now()} solve-loop blocked: starter file missing\n")
        stalled = mark_stalled(contest_id, agent=agent, challenge=challenge_key, reason="solve-loop could not find a starter file to execute")
        return {
            "status": "stalled",
            "contest_id": contest_id,
            "agent": agent,
            "challenge_id": challenge_key,
            "reason": "starter_missing",
            "prepare_target": prepared,
            "stalled": stalled,
            "next_action": "Run ctfctl interactive solve-loop again to continue with the next challenge.",
        }

    attempts: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    submit_results: list[dict[str, Any]] = []
    limit = max(1, int(max_attempts or 5))
    service_metadata = _service_metadata_for_item(root, board, item, challenge_key)
    use_service_attempt = _service_solve_loop_eligible(service_metadata)
    web_metadata = _web_metadata_for_item(root, board, item, challenge_key)
    use_web_attempt = bool(web_metadata and web_metadata.get("base_url") and not use_service_attempt)
    use_browser_attempt = bool(use_web_attempt and starter_fs_path and _starter_looks_browser_based(starter_fs_path))
    for attempt_index in range(1, limit + 1):
        if use_service_attempt:
            attempt = service_attempt(
                contest_id,
                challenge_id=challenge_key,
                agent=agent,
                script=starter_fs_path,
                timeout=120,
            )
        elif use_browser_attempt:
            attempt = browser_attempt(
                contest_id,
                challenge_id=challenge_key,
                agent=agent,
                script=starter_fs_path,
                timeout=120,
            )
        elif use_web_attempt:
            attempt = web_attempt(
                contest_id,
                challenge_id=challenge_key,
                agent=agent,
                script=starter_fs_path,
                timeout=120,
            )
        else:
            attempt = run_attempt(
                contest_id,
                challenge_id=challenge_key,
                agent=agent,
                script=starter_fs_path,
                timeout=120,
            )
        attempts.append(attempt)
        if attempt.get("status") == "missing_tool":
            tool = str((attempt.get("missing_tool") or {}).get("tool") or "unknown")
            reason = f"solve-loop blocked by missing tool {tool}; fallback recorded in attempts and next_steps"
            stalled = mark_stalled(contest_id, agent=agent, challenge=challenge_key, reason=reason)
            summary = metrics_summary(contest_id)
            return {
                "status": "stalled",
                "contest_id": contest_id,
                "agent": agent,
                "challenge_id": challenge_key,
                "reason": "missing_tool",
                "missing_tool": attempt.get("missing_tool") or {},
                "prepare_target": prepared,
                "attempts": attempts,
                "verifications": verifications,
                "submit_results": submit_results,
                "stalled": stalled,
                "metrics_summary": summary,
                "next_action": "Continue with ctfctl interactive solve-loop --contest-id <contest> --agent <agent> --json for the next challenge.",
            }
        for candidate_row in attempt.get("candidates") or []:
            value = str(candidate_row.get("value") or "")
            if not value:
                continue
            verification = verify_candidate(contest_id, challenge_id=challenge_key, candidate=value)
            verifications.append(verification)
            if verification.get("confidence") != "high" or not verification.get("submit_allowed"):
                continue
            submit_plan = _solve_loop_submit_plan(contest_id, challenge_key, verification)
            submit_result = _submit_candidate_value(contest_id, challenge_key, value, challenge_dir=challenge_dir)
            submit_result["submit_plan"] = submit_plan
            submit_results.append(submit_result)
            if submit_result.get("status") == "accepted":
                category = str(prepared.get("category") or item.get("category") or "misc")
                _write_solve_loop_summary(challenge_dir, contest_id=contest_id, challenge_id=challenge_key, category=category, verification=verification, submit_result=submit_result)
                writeup = writeup_challenge(
                    contest_id,
                    challenge_id=challenge_key,
                    category=category,
                    languages="ko,en",
                    include_code=True,
                )
                cleanup = cleanup_challenge(contest_id, challenge_id=challenge_key, safe=True)
                summary = metrics_summary(contest_id)
                return {
                    "status": "solved",
                    "contest_id": contest_id,
                    "agent": agent,
                    "challenge_id": challenge_key,
                    "category": category,
                    "prepare_target": prepared,
                    "attempts": attempts,
                    "verifications": verifications,
                    "submit": submit_result,
                    "writeup": writeup,
                    "cleanup": cleanup,
                    "metrics_summary": summary,
                    "next_action": "Continue with ctfctl interactive solve-loop --contest-id <contest> --agent <agent> --json for the next challenge.",
                }
            if submit_result.get("status") in {"planned", "blocked"}:
                _append_text(
                    challenge_dir / "next_steps.md",
                    f"\n- {utc_now()} submit not accepted yet: {submit_result.get('status')} ({submit_result.get('reason') or 'no reason'}). Continue with the next experiment or submit manually when ready.\n",
                )
                return {
                    "status": "submit_planned",
                    "contest_id": contest_id,
                    "agent": agent,
                    "challenge_id": challenge_key,
                    "prepare_target": prepared,
                    "attempts": attempts,
                    "verifications": verifications,
                    "submit": submit_result,
                    "next_action": "Resolve the submit blocker, then continue the solve loop without stopping after this challenge.",
                }
        _append_text(
            challenge_dir / "next_steps.md",
            f"\n- {utc_now()} solve-loop attempt {attempt_index}/{limit}: no accepted high-confidence candidate yet; inspect {attempt.get('attempt_path') or 'latest attempt'} and run the next experiment.\n",
        )

    reason = f"solve-loop reached max attempts ({limit}) without an accepted high-confidence candidate"
    stalled = mark_stalled(contest_id, agent=agent, challenge=challenge_key, reason=reason)
    summary = metrics_summary(contest_id)
    return {
        "status": "stalled",
        "contest_id": contest_id,
        "agent": agent,
        "challenge_id": challenge_key,
        "prepare_target": prepared,
        "attempts": attempts,
        "verifications": verifications,
        "submit_results": submit_results,
        "stalled": stalled,
        "metrics_summary": summary,
        "next_action": "Continue with ctfctl interactive solve-loop --contest-id <contest> --agent <agent> --json for the next challenge.",
    }


def release_claim(contest_id: str, *, agent: str, challenge: str | None = None, reason: str = "") -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    released = _release_locks(root, agent=agent, challenge=challenge)
    board = _read_board(root, contest_id)
    for item in board.get("challenges", []):
        if challenge and _normalize(challenge) not in _challenge_keys(item):
            continue
        if not challenge or released:
            if item.get("status") == "claimed" and (not item.get("claimed_by") or item.get("claimed_by") == agent):
                item["status"] = "todo"
                item.pop("claimed_by", None)
                item.pop("claimed_at", None)
    _write_board(root, board)
    _write_board_md(root, board)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="release",
        agent=agent,
        challenge_id=challenge,
        data={"released_count": released, "reason": redact_text(reason)},
    )
    return {"status": "ok", "contest_id": contest_id, "agent": agent, "released_count": released, "reason": redact_text(reason)}


def mark_stalled(contest_id: str, *, agent: str, challenge: str, reason: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge": challenge}
    event = {
        "contest_id": contest_id,
        "challenge_id": item.get("challenge_id"),
        "name": item.get("name"),
        "agent": agent,
        "reason": redact_text(reason),
        "timestamp": utc_now(),
    }
    _append_jsonl(root / "stalled.jsonl", event)
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    _append_text(challenge_dir / "operator_notes.md", f"\n## Stalled {event['timestamp']}\n\n{event['reason']}\n")
    _append_text(challenge_dir / "memory.md", f"\n- stalled: {event['reason']} ({event['timestamp']})\n")
    item["status"] = "stalled"
    item["stalled_reason"] = event["reason"]
    _release_locks(root, agent=agent, challenge=challenge)
    _write_board(root, board)
    _write_board_md(root, board)
    _record_metrics_event(root, contest_id=contest_id, event="stalled", agent=agent, challenge_id=str(item.get("challenge_id") or challenge), data={"reason": event["reason"]})
    return {"status": "stalled", "event": event, "released": True, "notes_path": _display(challenge_dir / "operator_notes.md")}


def mark_external_solved(contest_id: str, *, challenge: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge)
    if item is None:
        return {"status": "not_found", "contest_id": contest_id, "challenge": challenge}
    lines = _external_solved_lines(item, challenge)
    existing = {row.strip() for row in (root / "external_solved.txt").read_text(encoding="utf-8").splitlines() if row.strip()}
    for line in lines:
        if line not in existing:
            _append_text(root / "external_solved.txt", line + "\n")
            existing.add(line)
    item["status"] = "external_solved"
    item["solved_by_external"] = True
    item["solved_source"] = "external_solved_txt"
    item["solved_synced_at"] = utc_now()
    if _record_resolved_alias(item, challenge):
        item["solved_aliases"] = _dedupe_strings([*_list_values(item.get("solved_aliases")), challenge])
    released = _release_locks_for_item(root, agent=None, item=item)
    _write_board(root, board)
    _write_board_md(root, board)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="external_solved_recorded",
        challenge_id=str(item.get("challenge_id") or challenge),
        data={"released_count": released, "matched": redact_text(challenge)},
    )
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": item.get("challenge_id"),
        "canonical_id": item.get("canonical_id") or item.get("challenge_id"),
        "canonical_name": item.get("canonical_name") or item.get("name"),
        "released_count": released,
    }


def submit_flag_file(contest_id: str, *, challenge_id: str, flag_file: str | Path, confirm: bool) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": ""}
    candidate = Path(flag_file).expanduser().read_text(encoding="utf-8").strip()
    policy = load_submit_policy()
    submissions = _read_jsonl(root / "submissions.jsonl")
    previous = [row for row in submissions if str(row.get("challenge_id")) == str(item.get("challenge_id"))]
    decision = should_submit(
        candidate,
        policy,
        previous_submissions=previous,
        challenge_state={"challenge_id": item.get("challenge_id"), "status": item.get("status") or "todo", "solved": _is_solved(root, item)},
        context={"source": "known_flag_source" if confirm else "interactive_submit"},
    )
    profile = _operator_config(root).get("profile_path")
    action_payload: dict[str, Any]
    status = "blocked"
    if not confirm:
        action_payload = {"status": "blocked", "reason": "confirm_required"}
    elif not decision.get("allowed"):
        action_payload = {"status": "blocked", "reason": f"submit_guard_{decision.get('reason')}"}
    elif not profile or str(profile).startswith("TODO"):
        action_payload = {"status": "planned", "reason": "profile_missing"}
        status = "planned"
    else:
        platform = load_platform_adapter(str(profile))
        action = platform.submit_flag(str(item.get("challenge_id") or challenge_id), candidate, live=True, confirm=True)
        action_payload = action_to_dict(action)
        status = str(action.status)
    flag_digest = str(decision.get("flag_hash") or hash_flag(candidate))
    record = {
        "contest_id": contest_id,
        "challenge_id": item.get("challenge_id") or challenge_id,
        "flag_hash": flag_digest,
        "status": status if status != "blocked" else str(action_payload.get("status") or "blocked"),
        "confidence": decision.get("confidence"),
        "reason": action_payload.get("reason") or action_payload.get("details", {}).get("reason") or decision.get("reason"),
        "timestamp": utc_now(),
    }
    _append_jsonl(root / "submissions.jsonl", record)
    if record["status"] == "accepted":
        solved = {**record, "name": item.get("name"), "category": item.get("category")}
        _append_jsonl(root / "solved.jsonl", solved)
        item["status"] = "solved"
        item["solved_at"] = solved["timestamp"]
        item["solved_source"] = "submit"
        item["solved_by_external"] = False
        item["flag_hash"] = flag_digest
        _release_locks_for_item(root, agent=None, item=item)
        _write_board(root, board)
        _write_board_md(root, board)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="submit",
        challenge_id=str(record["challenge_id"]),
        data={"status": record["status"], "confidence": record.get("confidence"), "reason": record.get("reason")},
    )
    return {
        "status": record["status"],
        "contest_id": contest_id,
        "challenge_id": record["challenge_id"],
        "flag_hash": flag_digest,
        "decision": {key: value for key, value in decision.items() if key != "candidate_preview"},
        "platform_action": _redact_object(action_payload),
        "record": record,
    }


def submit_config(
    contest_id: str,
    *,
    challenge_id: str,
    submit_type: str,
    endpoint: str | None = None,
    field_name: str | None = None,
    status_url: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": ""}
    normalized_type = str(submit_type or "").strip()
    if normalized_type not in {"flag", "artifact_upload", "manual"}:
        return {"status": "blocked", "reason": "unsupported_submit_type", "contest_id": contest_id, "challenge_id": challenge_id}
    metadata = _normalize_submit_metadata(
        {
            "challenge_id": str(item.get("challenge_id") or challenge_id),
            "submit_type": normalized_type,
            "endpoint": endpoint,
            "method": "multipart" if normalized_type == "artifact_upload" else None,
            "field_name": field_name or ("file" if normalized_type == "artifact_upload" else None),
            "auth_source": "profile",
            "status_url": status_url,
            "status_check": "optional" if status_url or normalized_type == "artifact_upload" else None,
        }
    )
    syntax = _validate_submit_metadata_urls(metadata)
    if not syntax["allowed"]:
        return {
            "status": "blocked",
            "reason": syntax["reason"],
            "contest_id": contest_id,
            "challenge_id": str(item.get("challenge_id") or challenge_id),
            "metadata": _redact_object(metadata),
        }
    _save_challenge_submit_metadata(root, board, str(item.get("challenge_id") or challenge_id), metadata)
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": str(item.get("challenge_id") or challenge_id),
        "metadata": _redact_object(metadata),
        "warnings": syntax.get("warnings", []),
        "operator_config": _display(root / "operator.json"),
        "board_path": _display(root / "board.json"),
    }


def upload_submit(
    contest_id: str,
    *,
    challenge_id: str,
    artifact: str | Path,
    confirm: bool,
    endpoint: str | None = None,
    field_name: str | None = None,
    method: str | None = None,
    status_url: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": ""}
    path = Path(artifact).expanduser()
    artifact_info = _artifact_info(path)
    stored_metadata = _challenge_submit_metadata(root, board, str(item.get("challenge_id") or challenge_id))
    effective_metadata = _normalize_submit_metadata(
        {
            **stored_metadata,
            "challenge_id": str(item.get("challenge_id") or challenge_id),
            "submit_type": stored_metadata.get("submit_type") or ("artifact_upload" if endpoint else None),
            "endpoint": endpoint or stored_metadata.get("endpoint"),
            "method": method or stored_metadata.get("method") or "multipart",
            "field_name": field_name or stored_metadata.get("field_name") or "file",
            "auth_source": stored_metadata.get("auth_source") or "profile",
            "status_url": status_url or stored_metadata.get("status_url"),
            "status_check": stored_metadata.get("status_check") or "optional",
        }
    )
    challenge_key = str(effective_metadata.get("challenge_id") or challenge_id)
    base_record = {
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "submit_type": "artifact_upload",
        "artifact_path": artifact_info["path"],
        "artifact_exists": artifact_info["exists"],
        "artifact_size": artifact_info["size"],
        "artifact_sha256": artifact_info["sha256"],
        "method": str(effective_metadata.get("method") or "multipart"),
        "field_name": str(effective_metadata.get("field_name") or "file"),
        "endpoint": str(effective_metadata.get("endpoint") or ""),
        "status_url": str(effective_metadata.get("status_url") or ""),
        "auth_source": str(effective_metadata.get("auth_source") or "profile"),
        "timestamp": utc_now(),
    }
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="artifact_submit_planned",
        challenge_id=challenge_key,
        data=_artifact_metric_data({**base_record, "status": "planned"}),
    )

    def finish(status: str, reason: str = "", **extra: Any) -> dict[str, Any]:
        timestamp = str(base_record["timestamp"])
        record = {
            **base_record,
            **extra,
            "status": status,
            "reason": reason,
            "submitted_at": timestamp,
            "active_status": str(extra.get("active_status") or ("active" if status == "accepted" else "unknown")),
        }
        _append_jsonl(root / "submissions.jsonl", record)
        terminal_event = _artifact_terminal_event(status)
        if terminal_event:
            _record_metrics_event(
                root,
                contest_id=contest_id,
                event=terminal_event,
                challenge_id=challenge_key,
                data=_artifact_metric_data(record),
            )
        if status == "accepted" and record.get("active_status") == "active":
            solved = {
                "contest_id": contest_id,
                "challenge_id": challenge_key,
                "name": item.get("name"),
                "category": item.get("category"),
                "status": "accepted",
                "submit_type": "artifact_upload",
                "artifact_sha256": record.get("artifact_sha256"),
                "artifact_size": record.get("artifact_size"),
                "active_status": record.get("active_status"),
                "timestamp": timestamp,
            }
            _append_jsonl(root / "solved.jsonl", solved)
            if isinstance(item, dict):
                item["status"] = "solved"
                item["solved_at"] = timestamp
                item["solved_source"] = "submit"
                item["solved_by_external"] = False
                item["artifact_sha256"] = record.get("artifact_sha256")
            _release_locks_for_item(root, agent=None, item=item)
            _write_board(root, board)
            _write_board_md(root, board)
        return {
            "status": status,
            "reason": reason,
            "contest_id": contest_id,
            "challenge_id": challenge_key,
            "artifact": artifact_info,
            "metadata": _redact_object(effective_metadata),
            "record": _redact_object(record),
        }

    if not stored_metadata.get("submit_type") and not endpoint:
        return finish("blocked", "official_upload_endpoint_metadata_missing")
    if str(effective_metadata.get("submit_type") or "") != "artifact_upload":
        return finish("blocked", "submit_type_not_artifact_upload")
    if not artifact_info["exists"]:
        return finish("blocked", "artifact_missing")
    if str(effective_metadata.get("method") or "").strip().lower() != "multipart":
        return finish("blocked", "unsupported_upload_method")
    if not effective_metadata.get("endpoint"):
        return finish("blocked", "official_upload_endpoint_metadata_missing")

    endpoint_check = _validate_official_upload_endpoint(root, str(effective_metadata["endpoint"]), label="endpoint")
    if not endpoint_check["allowed"]:
        return finish("blocked", endpoint_check["reason"], validation=endpoint_check)
    if effective_metadata.get("status_url"):
        status_check_url = _validate_official_upload_endpoint(root, str(effective_metadata["status_url"]), label="status_url")
        if not status_check_url["allowed"]:
            return finish("blocked", status_check_url["reason"], validation=status_check_url)

    if not confirm:
        return finish("planned", "confirm_required")

    if endpoint or status_url or field_name or method:
        _save_challenge_submit_metadata(root, board, challenge_key, effective_metadata)

    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="artifact_submit_attempted",
        challenge_id=challenge_key,
        data=_artifact_metric_data({**base_record, "status": "attempted"}),
    )
    try:
        headers = _upload_auth_headers(root, str(effective_metadata["endpoint"]))
        upload_result = _multipart_upload(
            str(effective_metadata["endpoint"]),
            artifact_path=path,
            field_name=str(effective_metadata.get("field_name") or "file"),
            headers=headers,
        )
    except (FileNotFoundError, KeyError, ValueError) as exc:
        return finish("blocked", "auth_or_config_missing", response_status="blocked", response_summary=redact_text(str(exc))[:500])
    except urllib.error.HTTPError as exc:
        upload_result = _upload_http_error(exc)
    except urllib.error.URLError as exc:
        return finish("rejected", "network_error", response_status="network_error", response_summary=redact_text(str(getattr(exc, "reason", exc)))[:500])

    final = dict(upload_result)
    if effective_metadata.get("status_url"):
        try:
            status_headers = _upload_auth_headers(root, str(effective_metadata["status_url"]))
            status_result = _status_check(str(effective_metadata["status_url"]), headers=status_headers)
            final["status_check"] = status_result
            final = _merge_upload_status(upload_result, status_result)
        except (FileNotFoundError, KeyError, ValueError) as exc:
            final["status_check"] = {"response_status": "blocked", "response_summary": redact_text(str(exc))[:500]}
        except urllib.error.HTTPError as exc:
            final["status_check"] = _upload_http_error(exc)
            final = _merge_upload_status(upload_result, final["status_check"])
        except urllib.error.URLError as exc:
            final["status_check"] = {"response_status": "network_error", "response_summary": redact_text(str(getattr(exc, "reason", exc)))[:500]}

    response_status = str(final.get("response_status") or "unknown")
    active_status = str(final.get("active_status") or ("active" if response_status == "accepted" else "unknown"))
    if response_status == "accepted" and active_status == "active":
        final_status = "accepted"
        reason = "accepted"
    elif response_status in {"auth_required", "blocked"}:
        final_status = "blocked"
        reason = response_status
    elif response_status == "rate_limited":
        final_status = "rejected"
        reason = "rate_limited"
    else:
        final_status = "rejected"
        reason = response_status if response_status != "unknown" else "unexpected_response"
    final["active_status"] = active_status
    return finish(final_status, reason, **final)


def writeup_challenge(
    contest_id: str,
    *,
    challenge_id: str,
    category: str,
    writeup_root: str | Path | None = None,
    languages: str = "ko,en",
    include_code: bool = False,
) -> dict[str, Any]:
    init_operator(contest_id, writeup_root=writeup_root)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": category}
    if not _is_accepted(root, str(item.get("challenge_id") or challenge_id)):
        return {"status": "blocked", "reason": "accepted_solve_required", "contest_id": contest_id, "challenge_id": challenge_id}
    out_root = Path(writeup_root).expanduser() if writeup_root else Path(_operator_config(root).get("writeup_root") or root / "writeups").expanduser()
    out_root.mkdir(parents=True, exist_ok=True)
    langs = [part.strip() for part in languages.split(",") if part.strip()] or ["ko", "en"]
    challenge_dir = _challenge_path(contest_id, item)
    code_blocks = _collect_code_blocks(challenge_dir) if include_code else []
    solved = _accepted_record(root, str(item.get("challenge_id") or challenge_id)) or {}
    written: dict[str, str] = {}
    for lang in langs:
        filename = f"[{_safe_filename(category)}]{_safe_filename(str(item.get('name') or challenge_id))}Writeup.{lang}.md"
        text = _render_writeup(lang, contest_id, item, category, challenge_dir, solved, code_blocks)
        path = out_root / filename
        path.write_text(redact_text(text), encoding="utf-8")
        written[lang] = _display(path)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="writeup",
        challenge_id=str(item.get("challenge_id") or challenge_id),
        data={"languages": langs, "files": written, "included_code_count": len(code_blocks)},
    )
    return {"status": "ok", "contest_id": contest_id, "challenge_id": item.get("challenge_id"), "files": written, "included_code_count": len(code_blocks)}


def cleanup_challenge(contest_id: str, *, challenge_id: str, safe: bool) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id}
    challenge_dir = _challenge_path(contest_id, item)
    planned = _cleanup_candidates(challenge_dir)
    removed: list[str] = []
    if safe:
        for path in planned:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
            removed.append(_display(path))
    _record_metrics_event(root, contest_id=contest_id, event="cleanup", challenge_id=challenge_id, data={"status": "ok" if safe else "planned", "removed_count": len(removed)})
    return {"status": "ok" if safe else "planned", "contest_id": contest_id, "challenge_id": challenge_id, "planned": [_display(path) for path in planned], "removed": removed}


def metrics_record(
    contest_id: str,
    *,
    event: str,
    agent: str | None = None,
    challenge_id: str | None = None,
    data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    row = _record_metrics_event(root, contest_id=contest_id, event=event, agent=agent, challenge_id=challenge_id, data=data or {})
    summary = metrics_summary(contest_id)
    return {"status": "ok", "contest_id": contest_id, "event": row, "summary_path": summary["summary_path"]}


def metrics_summary(contest_id: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    metrics_dir = _ensure_metrics_files(root)
    events = _read_jsonl(metrics_dir / "events.jsonl")
    sessions_rows = _read_jsonl(metrics_dir / "sessions.jsonl")
    summary = _build_metrics_summary(contest_id, events, sessions_rows)
    _write_json(metrics_dir / "summary.json", summary)
    return {**summary, "status": "ok", "summary_path": _display(metrics_dir / "summary.json")}


def metrics_compare(before: str | Path, after: str | Path) -> dict[str, Any]:
    before_data = _read_json_file(Path(before).expanduser())
    after_data = _read_json_file(Path(after).expanduser())
    keys = [
        "total_events",
        "sessions",
        "claimed_count",
        "attempt_count",
        "solved_count",
        "stalled_count",
        "submitted_count",
        "accepted_count",
        "artifact_submitted_count",
        "artifact_accepted_count",
        "artifact_rejected_count",
        "artifact_blocked_count",
        "writeup_ko_count",
        "writeup_en_count",
        "cleanup_count",
        "tokens_total_observed",
    ]
    deltas: dict[str, Any] = {}
    for key in keys:
        before_value = before_data.get(key)
        after_value = after_data.get(key)
        if isinstance(before_value, (int, float)) and isinstance(after_value, (int, float)):
            deltas[key] = after_value - before_value
        elif before_value is None and isinstance(after_value, (int, float)):
            deltas[key] = after_value
        elif isinstance(before_value, (int, float)) and after_value is None:
            deltas[key] = -before_value
        else:
            deltas[key] = None
    return {"status": "ok", "before": _display(Path(before).expanduser()), "after": _display(Path(after).expanduser()), "deltas": deltas}


def metrics_publish_snapshot(
    contest_id: str,
    *,
    output_root: str | Path | None = None,
    contest_ended: bool = False,
    confirm_public_safe: bool = False,
    allow_active_contest: bool = False,
) -> dict[str, Any]:
    if not contest_ended and not (allow_active_contest and confirm_public_safe):
        return {
            "status": "blocked",
            "reason": "active_contest_public_snapshot_requires_contest_ended_or_allow_active_contest_with_confirm_public_safe",
            "contest_id": contest_id,
            "public_safe": False,
        }

    init_operator(contest_id)
    root = operator_root(contest_id)
    metrics_dir = _ensure_metrics_files(root)
    events = _read_jsonl(metrics_dir / "events.jsonl")
    sessions_rows = _read_jsonl(metrics_dir / "sessions.jsonl")
    summary = _build_metrics_summary(contest_id, events, sessions_rows)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    contest_events = [row for row in events if row.get("contest_id") == contest_id]
    challenge_index = _public_challenge_index(board, contest_events, root)
    attempts_total = _attempts_total(contest_events)
    artifact_submissions = _public_artifact_submissions(root, contest_id)
    candidates_public = _public_candidates(root, board)

    summary_public = {
        **summary,
        "schema": "interactive_metrics_public_snapshot_v1",
        "public_safe": True,
        "source": "local_operator_metrics",
        "contest_ended": bool(contest_ended),
        "snapshot_generated_at": utc_now(),
        "challenge_count": len(challenge_index),
        "attempts_total": attempts_total,
        "candidate_count": len(candidates_public),
        "candidates": candidates_public,
        "artifact_submissions": artifact_submissions,
        "artifact_submission_count": len(artifact_submissions),
    }

    out_root = Path(output_root).expanduser() if output_root else get_paths().repo / "metrics" / "contests" / _safe_slug(contest_id)
    out_root.mkdir(parents=True, exist_ok=True)
    files = {
        "summary": out_root / "summary.public.json",
        "solved": out_root / "solved.public.md",
        "stalled": out_root / "stalled.public.md",
        "approaches": out_root / "approaches.public.md",
        "regression": out_root / "regression.public.md",
    }
    _write_json(files["summary"], summary_public)
    files["solved"].write_text(_render_public_solved(contest_id, challenge_index, root), encoding="utf-8")
    files["stalled"].write_text(_render_public_stalled(contest_id, challenge_index, root), encoding="utf-8")
    files["approaches"].write_text(_render_public_approaches(contest_id, challenge_index, contest_events), encoding="utf-8")
    files["regression"].write_text(_render_public_regression(contest_id, summary_public), encoding="utf-8")
    return {
        "status": "ok",
        "contest_id": contest_id,
        "public_safe": True,
        "output_root": _display(out_root),
        "files": {key: _display(path) for key, path in files.items()},
    }


def metrics_dashboard(*, output: str | Path | None = None) -> dict[str, Any]:
    repo = get_paths().repo
    path = Path(output).expanduser() if output else repo / "metrics" / "dashboard.md"
    metrics_root = path.parent if output else repo / "metrics"
    run_files = sorted((metrics_root / "runs").glob("*.json"))
    snapshot_files = sorted((metrics_root / "contests").glob("*/summary.public.json"))
    snapshots = [_read_json_file(item) for item in snapshot_files]
    runs = [_read_json_file(item) for item in run_files]
    latest_commit = _git_value(["rev-parse", "--short", "HEAD"]) or "unknown"

    solved = sum(_number(item.get("solved_count")) for item in snapshots)
    stalled = sum(_number(item.get("stalled_count")) for item in snapshots)
    writeup_ko = sum(_number(item.get("writeup_ko_count")) for item in snapshots)
    writeup_en = sum(_number(item.get("writeup_en_count")) for item in snapshots)
    cleanup = sum(_number(item.get("cleanup_count")) for item in snapshots)
    tokens = sum(_number(item.get("tokens_total_observed")) for item in snapshots if item.get("tokens_total_observed") is not None)
    avg_values = [_number(item.get("avg_time_to_solve_sec")) for item in snapshots if item.get("avg_time_to_solve_sec") is not None]
    avg_time = round(sum(avg_values) / len(avg_values), 3) if avg_values else None

    lines = [
        "# Interactive Metrics Dashboard",
        "",
        f"- generated_at: {utc_now()}",
        f"- latest_commit: {latest_commit}",
        f"- total_public_snapshots: {len(snapshots)}",
        f"- baseline_runs: {len(runs)}",
        f"- solved_total: {solved}",
        f"- stalled_total: {stalled}",
        f"- writeup_ko_total: {writeup_ko}",
        f"- writeup_en_total: {writeup_en}",
        f"- cleanup_total: {cleanup}",
        f"- tokens_total_observed: {tokens if any(item.get('tokens_total_observed') is not None for item in snapshots) else 'unknown'}",
        f"- avg_time_to_solve_sec: {avg_time if avg_time is not None else 'unknown'}",
        "",
    ]
    if snapshots:
        lines.extend(["## Public Snapshots", "", "| Contest | Solved | Stalled | Tokens | Avg Solve Sec | Generated |", "| --- | ---: | ---: | ---: | ---: | --- |"])
        for item in snapshots:
            lines.append(
                f"| {_md(str(item.get('contest_id') or 'unknown'))} | {_number(item.get('solved_count'))} | {_number(item.get('stalled_count'))} | "
                f"{item.get('tokens_total_observed') if item.get('tokens_total_observed') is not None else 'unknown'} | "
                f"{item.get('avg_time_to_solve_sec') if item.get('avg_time_to_solve_sec') is not None else 'unknown'} | "
                f"{_md(str(item.get('snapshot_generated_at') or item.get('generated_at') or ''))} |"
            )
    else:
        lines.extend(["## Public Snapshots", "", "No public-safe contest snapshots exist yet. After a contest ends, run `ctfctl interactive metrics publish-snapshot` and then regenerate this dashboard."])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"status": "ok", "dashboard_path": _display(path), "public_snapshot_count": len(snapshots), "baseline_run_count": len(runs)}


def metrics_baseline(*, name: str | None = None, output_dir: str | Path | None = None) -> dict[str, Any]:
    repo = get_paths().repo
    commit = _git_value(["rev-parse", "--short", "HEAD"]) or "unknown"
    branch = _git_value(["rev-parse", "--abbrev-ref", "HEAD"]) or "unknown"
    timestamp = utc_now()
    safe_name = _safe_slug(name or "baseline")
    filename = f"{timestamp.replace(':', '').replace('-', '').split('.')[0]}-{_safe_slug(commit)}-{safe_name}.json"
    out_dir = Path(output_dir).expanduser() if output_dir else repo / "metrics" / "runs"
    path = out_dir / filename
    data = {
        "schema": "interactive_metrics_baseline_v1",
        "timestamp": timestamp,
        "git_commit": commit,
        "branch": branch,
        "pytest_status": "unknown",
        "pytest_note": "not_run_lightweight_baseline",
        "interactive_commands": {
            "metrics_record": True,
            "metrics_summary": True,
            "metrics_compare": True,
            "metrics_report": True,
            "metrics_publish_snapshot": True,
            "metrics_dashboard": True,
            "metrics_baseline": True,
            "metrics_compare_public": True,
            "submit_config": True,
            "upload_submit": True,
            "next": True,
            "target_pack": True,
            "triage": True,
            "starter": True,
            "prepare_target": True,
            "brief": True,
            "run_attempt": True,
            "web_config": True,
            "web_probe": True,
            "browser_probe": True,
            "web_attempt": True,
            "browser_attempt": True,
            "web_status": True,
            "candidates": True,
            "verify_candidate": True,
            "solve_loop": True,
        },
        "prompt_policy_summary": {
            "local_raw_flag_output_allowed": True,
            "public_upload_commit_paste_flags_writeups_exploits_secrets_forbidden_during_contest": True,
            "public_snapshot_requires_contest_ended_or_explicit_confirm": True,
            "stalled_challenges_get_metrics_not_writeups": True,
        },
    }
    _write_json(path, data)
    return {"status": "ok", "baseline_path": _display(path), "baseline": data}


def metrics_compare_public(before: str | Path, after: str | Path) -> dict[str, Any]:
    before_data = _read_json_file(Path(before).expanduser())
    after_data = _read_json_file(Path(after).expanduser())
    keys = [
        "solved_count",
        "stalled_count",
        "accepted_count",
        "artifact_submitted_count",
        "artifact_accepted_count",
        "artifact_rejected_count",
        "artifact_blocked_count",
        "writeup_ko_count",
        "writeup_en_count",
        "cleanup_count",
        "tokens_total_observed",
        "avg_time_to_solve_sec",
        "attempts_total",
    ]
    deltas: dict[str, Any] = {}
    for key in keys:
        deltas[key] = _delta(before_data.get(key), after_data.get(key))
    return {"status": "ok", "before": _display(Path(before).expanduser()), "after": _display(Path(after).expanduser()), "public_safe": True, "deltas": deltas}


def e2e_smoke(
    contest_id: str,
    *,
    agents: int = 2,
    writeup_root: str | Path | None = None,
    keep_runtime: bool = False,
) -> dict[str, Any]:
    if int(agents) < 1:
        return {"status": "error", "reason": "agents_must_be_positive", "contest_id": contest_id}
    if not _is_fake_or_local_contest_id(contest_id):
        return {"status": "blocked", "reason": "e2e_smoke_requires_fake_or_local_contest_id", "contest_id": contest_id}

    contest_root = get_paths().contests_root / _safe_slug(contest_id)
    root = operator_root(contest_id)
    if contest_root.exists():
        shutil.rmtree(contest_root)
    profile_path = contest_root / "operator" / "fake_platform.local.json"
    writeup_out = Path(writeup_root).expanduser() if writeup_root else root / "writeups"
    validation: dict[str, Any] = {}

    try:
        with FakeCTFdServer() as server:
            profile_path.parent.mkdir(parents=True, exist_ok=True)
            _write_json(profile_path, platform_config(server.base_url, downloads_root=get_paths().contests_root))

            init_result = init_operator(contest_id, profile=profile_path, writeup_root=writeup_out, agents=agents)
            sync_result = sync_operator(contest_id, profile=profile_path, live=True, download=True, ingest=True)

            duplicate_first = claim_challenge(contest_id, agent="agent-1", challenge="duplicate-decoy-1")
            duplicate_blocked = claim_challenge(contest_id, agent="agent-2", challenge="duplicate-decoy-1")
            duplicate_allowed = claim_challenge(contest_id, agent="agent-2", challenge="duplicate-decoy-1", allow_duplicate=True)
            release_claim(contest_id, agent="agent-1", challenge="duplicate-decoy-1", reason="e2e duplicate guard checked")
            release_claim(contest_id, agent="agent-2", challenge="duplicate-decoy-1", reason="e2e duplicate guard checked")

            solve_claim = claim_challenge(contest_id, agent="agent-1", challenge="easy-misc-1")
            solve_payload = _write_e2e_solver(contest_id, "easy-misc-1")
            submit_result = submit_flag_file(contest_id, challenge_id="easy-misc-1", flag_file=solve_payload["flag_file"], confirm=True)
            writeup_result = writeup_challenge(
                contest_id,
                challenge_id="easy-misc-1",
                category="misc",
                writeup_root=writeup_out,
                languages="ko,en",
                include_code=True,
            )
            cleanup_result = cleanup_challenge(contest_id, challenge_id="easy-misc-1", safe=True)

            stalled_claim = claim_challenge(contest_id, agent="agent-2", challenge="stalled-1")
            stalled_result = mark_stalled(contest_id, agent="agent-2", challenge="stalled-1", reason="fixture has no locally verified candidate")
            next_claim = claim_challenge(contest_id, agent="agent-1")
            if next_claim.get("status") == "claimed":
                release_claim(contest_id, agent="agent-1", challenge=str(next_claim.get("challenge_id") or ""), reason="e2e next-claim check complete")
            summary = metrics_summary(contest_id)
            board = board_status(contest_id)

            validation = _validate_e2e_smoke(
                root=root,
                writeup_result=writeup_result,
                summary=summary,
                duplicate_blocked=duplicate_blocked,
                duplicate_allowed=duplicate_allowed,
                submit_result=submit_result,
                stalled_result=stalled_result,
                next_claim=next_claim,
            )
            return {
                "status": "ok" if validation["ok"] else "error",
                "contest_id": contest_id,
                "operator_root": _display(root),
                "writeup_root": _display(writeup_out),
                "keep_runtime": bool(keep_runtime),
                "checks": validation["checks"],
                "init": _e2e_public(init_result),
                "sync": _e2e_public(sync_result),
                "claims": {
                    "duplicate_first": _e2e_public(duplicate_first),
                    "duplicate_blocked": _e2e_public(duplicate_blocked),
                    "duplicate_allowed": _e2e_public(duplicate_allowed),
                    "solved_fixture": _e2e_public(solve_claim),
                    "stalled_fixture": _e2e_public(stalled_claim),
                    "next_after_solved": _e2e_public(next_claim),
                },
                "submit": _e2e_public(submit_result),
                "writeup": _e2e_public(writeup_result),
                "cleanup": _e2e_public(cleanup_result),
                "stalled": _e2e_public(stalled_result),
                "metrics_summary": _e2e_public(summary),
                "board_counts": board.get("counts"),
                "fake_platform": {
                    "request_count": len(server.request_log),
                    "submission_count": len(server.submission_log),
                    "submission_statuses": sorted({str(row.get("status") or "") for row in server.submission_log}),
                },
            }
    finally:
        if not keep_runtime and contest_root.exists():
            shutil.rmtree(contest_root)


def metrics_report(contest_id: str, *, output: str | Path | None = None) -> dict[str, Any]:
    summary = metrics_summary(contest_id)
    root = operator_root(contest_id)
    metrics_dir = _ensure_metrics_files(root)
    path = Path(output).expanduser() if output else metrics_dir / "regression_report.md"
    lines = [
        f"# Interactive Metrics Report: {contest_id}",
        "",
        f"- total_events: {summary['total_events']}",
        f"- sessions: {summary['sessions']}",
        f"- claimed_count: {summary['claimed_count']}",
        f"- attempt_count: {summary.get('attempt_count', 0)}",
        f"- solved_count: {summary['solved_count']}",
        f"- stalled_count: {summary['stalled_count']}",
        f"- submitted_count: {summary['submitted_count']}",
        f"- accepted_count: {summary['accepted_count']}",
        f"- artifact_submitted_count: {summary.get('artifact_submitted_count', 0)}",
        f"- artifact_accepted_count: {summary.get('artifact_accepted_count', 0)}",
        f"- artifact_rejected_count: {summary.get('artifact_rejected_count', 0)}",
        f"- artifact_blocked_count: {summary.get('artifact_blocked_count', 0)}",
        f"- writeup_ko_count: {summary['writeup_ko_count']}",
        f"- writeup_en_count: {summary['writeup_en_count']}",
        f"- cleanup_count: {summary['cleanup_count']}",
        f"- tokens_total_observed: {summary['tokens_total_observed']}",
        f"- avg_time_to_solve_sec: {summary['avg_time_to_solve_sec']}",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return {"status": "ok", "contest_id": contest_id, "report_path": _display(path), "summary": summary}


def memo_update(contest_id: str, *, challenge_id: str, kind: str, append: str | None = None) -> dict[str, Any]:
    if kind not in MEMO_KINDS:
        raise ValueError(f"kind must be one of {', '.join(MEMO_KINDS)}")
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id}
    challenge_dir = _challenge_path(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    path = challenge_dir / f"{kind}.md"
    if append:
        _append_text(path, f"\n- {redact_text(append)}\n")
    return {"status": "ok", "contest_id": contest_id, "challenge_id": challenge_id, "kind": kind, "path": _display(path), "size": path.stat().st_size}


def solver_prompt(contest_id: str, *, agent: str) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    profile_path = str(_operator_config(root).get("profile_path") or "").strip()
    refresh_profile_arg = f" --profile {shlex.quote(profile_path)}" if profile_path and profile_path != "TODO" else ""
    first_prepare = (
        f"ctfctl interactive prepare-target --contest-id {contest_id} --agent {agent} --refresh{refresh_profile_arg} --json"
        if profile_path and profile_path != "TODO"
        else f"ctfctl interactive prepare-target --contest-id {contest_id} --agent {agent} --json"
    )
    next_command = (
        f"ctfctl interactive next --contest-id {contest_id} --agent {agent} --refresh{refresh_profile_arg} --json"
        if profile_path and profile_path != "TODO"
        else f"ctfctl interactive next --contest-id {contest_id} --agent {agent} --json"
    )
    text = f"""You are an autonomous interactive Codex CTF solver for contest {contest_id}, agent {agent}.

Work from ~/CTF. Use ctfctl interactive commands as your coordination surface.

Loop policy:
- Start with: {first_prepare}
- Do not solve one challenge and stop. Continue next/claim -> read target pack -> solve -> verify -> submit -> writeup -> cleanup -> next challenge until the contest ends, the user stops you, or completion_status is all_solved or all_solved_or_stalled.
- If completion_status is active, no_claimable, or needs_sync, keep going with ctfctl interactive status, prepare-target, next, or solve-loop as appropriate; do not stop after one problem.
- Do not split into controller/solver roles. This Codex session is the solver.
- Keep user-facing progress compact unless the user asks for detail.
- Local terminal output may include raw flags, solver output, and exploit output when needed for solving, verification, and local operator visibility.
- During an active contest, do not publish, upload, commit, push, paste publicly, or place flags, writeups, or exploits in public locations such as public services, public repositories, public pastes, issue trackers, public snapshots, or external writeup locations.
- Treat tokens, cookies, sessions, browser storage/storage_state, private keys, auth headers, and auth material as secrets. Do not commit, push, paste publicly, publish, upload, or include them in public snapshots.
- Public-safe metrics and snapshots may use hashes, lengths, statuses, and high-level blockers only; they must exclude raw flags, raw candidates, tokens, auth, and session material.
- If the user asks what you are doing, answer from ctfctl interactive brief or the current target pack without stopping the loop.

Coordination:
- Use ctfctl interactive status --contest-id {contest_id} --json when no target is returned; stop only for all_solved or all_solved_or_stalled.
- Prefer the automated harness after a target is prepared: ctfctl interactive solve-loop --contest-id {contest_id} --agent {agent} --challenge-id <id> --json.
- Use {next_command} to claim the next target, with a single live refresh when a profile is configured.
- If you need manual control, prepare the target with: {first_prepare}, then run ctfctl interactive run-attempt, inspect ctfctl interactive candidates, and verify with ctfctl interactive verify-candidate.
- The prepare-target result claims or selects a challenge, writes target_pack_path, triage_summary_path, and starter_path. Read the target pack, triage summary, and starter before manual analysis.
- If you manually claim with ctfctl interactive claim, immediately run ctfctl interactive prepare-target --contest-id {contest_id} --agent {agent} --challenge-id <id> --json.
- If prepare-target is unavailable, run ctfctl interactive target-pack, then ctfctl interactive triage, then ctfctl interactive starter for the same challenge.
- Same-machine duplicate claims are blocked by default. Use --allow-duplicate only when the user explicitly wants duplicate solving.
- If stuck, update memory/evidence/attempts/next_steps, run ctfctl interactive stalled with a compact reason, then call status and continue with prepare-target/next/solve-loop unless completion_status says all_solved or all_solved_or_stalled.
- Maintain memory.md, evidence.md, attempts.md, next_steps.md, and operator_notes.md for each challenge using ctfctl interactive memo.

Submission and writeups:
- Submit only high-confidence candidates through ctfctl interactive submit with --confirm and a flag file.
- For wasm/file artifact challenges, first save official metadata with ctfctl interactive submit-config, then use ctfctl interactive upload-submit --artifact <path> --confirm.
- If accepted, write Korean and English writeups with ctfctl interactive writeup --languages ko,en --include-code.
- Writeups are local-only during the contest and accepted-only. Never write a challenge writeup for unsolved/stalled work.
- If solver/exploit code exists, include the complete code in the writeup.

After each challenge:
- Run safe cleanup with ctfctl interactive cleanup --safe.
- Call ctfctl interactive status, then prepare-target/next/solve-loop again. Never stop after one problem unless the user stops you, the contest ends, or completion_status is all_solved or all_solved_or_stalled.
"""
    return {"status": "ok", "contest_id": contest_id, "agent": agent, "prompt": text}


def operator_root(contest_id: str) -> Path:
    return get_paths().contests_root / _safe_slug(contest_id) / "operator"


def _ensure_operator_files(
    root: Path,
    contest_id: str,
    *,
    profile: str | Path | None,
    writeup_root: str | Path | None,
    agents: int | None,
) -> dict[str, Any]:
    created: list[str] = []
    preserved: list[str] = []
    paths: dict[str, Path] = {}
    for dirname in ("claims", "memos", "writeups", "toolchain"):
        path = root / dirname
        existed = path.exists()
        path.mkdir(parents=True, exist_ok=True)
        (preserved if existed else created).append(dirname)
        paths[dirname] = path
    config_path = root / "operator.json"
    config = _operator_config(root)
    config.update(
        {
            "contest_id": contest_id,
            "profile_path": _display(Path(profile).expanduser()) if profile else config.get("profile_path", "TODO"),
            "writeup_root": _display(Path(writeup_root).expanduser()) if writeup_root else config.get("writeup_root", _display(root / "writeups")),
            "agents": agents if agents is not None else config.get("agents", "TODO"),
            "updated_at": utc_now(),
        }
    )
    if not config_path.exists():
        config["created_at"] = utc_now()
        created.append("operator.json")
    else:
        preserved.append("operator.json")
    _write_json(config_path, config)
    paths["operator_json"] = config_path
    defaults: dict[str, str] = {
        "BOARD.md": f"# {contest_id} Board\n\nNo challenges synced yet.\n",
        "board.json": json.dumps(_default_board(contest_id), indent=2, sort_keys=True) + "\n",
        "solved.jsonl": "",
        "external_solved.txt": "",
        "stalled.jsonl": "",
        "submissions.jsonl": "",
    }
    for filename, text in defaults.items():
        path = root / filename
        if path.exists():
            preserved.append(filename)
        else:
            path.write_text(text, encoding="utf-8")
            created.append(filename)
        paths[filename] = path
    paths["metrics"] = _ensure_metrics_files(root)
    return {"created": created, "preserved": preserved, "paths": paths}


def _default_board(contest_id: str) -> dict[str, Any]:
    return {"contest_id": contest_id, "updated_at": utc_now(), "challenges": []}


def _read_board(root: Path, contest_id: str) -> dict[str, Any]:
    path = root / "board.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = _default_board(contest_id)
    if not isinstance(data, dict):
        data = _default_board(contest_id)
    data.setdefault("contest_id", contest_id)
    data.setdefault("challenges", [])
    return data


def _write_board(root: Path, board: Mapping[str, Any]) -> None:
    _write_json(root / "board.json", dict(board))


def _write_board_md(root: Path, board: Mapping[str, Any]) -> None:
    lines = [f"# {board.get('contest_id')} Board", "", "| Status | Category | Challenge | Notes |", "| --- | --- | --- | --- |"]
    for item in board.get("challenges", []):
        notes = []
        if not item.get("claimable", True):
            notes.append("not claimable")
        if item.get("is_static_shell"):
            notes.append("static shell")
        if item.get("is_static_alias"):
            notes.append("static alias")
        if item.get("is_artifact_source") or item.get("artifact_source"):
            notes.append("artifact source")
        if item.get("is_alias"):
            notes.append(f"alias of {item.get('canonical_id')}")
        aliases = _list_values(item.get("aliases"))
        if aliases:
            notes.append(f"{len(aliases)} aliases")
        artifact_sources = _list_values(item.get("artifact_sources"))
        if artifact_sources:
            notes.append(f"{len(artifact_sources)} artifact sources")
        if item.get("claimed_by"):
            notes.append(f"claimed by {item.get('claimed_by')}")
        lines.append(
            f"| {redact_text(str(item.get('status') or 'todo'))} | {redact_text(str(item.get('category') or ''))} | "
            f"{redact_text(str(item.get('name') or item.get('challenge_id') or ''))} | {redact_text(', '.join(notes))} |"
        )
    (root / "BOARD.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _operator_config(root: Path) -> dict[str, Any]:
    path = root / "operator.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_toolchain_report(root: Path, report: Mapping[str, Any]) -> dict[str, Path]:
    toolchain_dir = root / "toolchain"
    toolchain_dir.mkdir(parents=True, exist_ok=True)
    json_path = toolchain_dir / "capabilities.json"
    md_path = toolchain_dir / "capabilities.md"
    _write_json(json_path, _redact_object(dict(report)))
    md_path.write_text(_target_safe_text(render_capabilities_markdown(report)), encoding="utf-8")
    return {"json": json_path, "md": md_path}


def _load_toolchain_report(root: Path) -> dict[str, Any] | None:
    path = root / "toolchain" / "capabilities.json"
    if not path.exists():
        return None
    data = _read_json_file(path)
    return data if data else None


def _toolchain_report_for_context(root: Path, contest_id: str, category: str | None) -> dict[str, Any]:
    existing = _load_toolchain_report(root)
    if existing:
        return existing
    report = collect_toolchain_capabilities(category=category, probe_docker=False)
    _save_toolchain_report(root, report)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="toolchain_checked",
        data=_toolchain_metric_payload(report),
    )
    return report


def _toolchain_metric_payload(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "category": str(report.get("category") or ""),
        "categories": list(report.get("categories") or [])[:12],
        "available_tool_count": len(report.get("available_tools") or []),
        "missing_high_priority_tools": list(report.get("missing_high_priority_tools") or [])[:40],
        "recommended_fallback_count": len(report.get("recommended_fallbacks") or []),
        "docker_available": bool((report.get("docker") or {}).get("available")) if isinstance(report.get("docker"), Mapping) else False,
        "no_auto_install": True,
    }


def _challenge_submit_metadata(root: Path, board: Mapping[str, Any], challenge_id: str) -> dict[str, Any]:
    board_metadata: dict[str, Any] = {}
    item = _find_challenge(board, challenge_id)
    if isinstance(item, Mapping):
        raw = item.get("submit_metadata") or item.get("submit")
        if isinstance(raw, Mapping):
            board_metadata.update(dict(raw))
    top_level = board.get("submit_metadata") if isinstance(board.get("submit_metadata"), Mapping) else {}
    if isinstance(top_level, Mapping) and isinstance(top_level.get(challenge_id), Mapping):
        board_metadata.update(dict(top_level[challenge_id]))
    config = _operator_config(root)
    configured = config.get("challenge_submit_metadata") if isinstance(config.get("challenge_submit_metadata"), Mapping) else {}
    operator_metadata = dict(configured.get(challenge_id) or {}) if isinstance(configured.get(challenge_id), Mapping) else {}
    return _normalize_submit_metadata({**board_metadata, **operator_metadata})


def _save_challenge_submit_metadata(root: Path, board: dict[str, Any], challenge_id: str, metadata: Mapping[str, Any]) -> None:
    normalized = _normalize_submit_metadata({**dict(metadata), "challenge_id": challenge_id})
    config_path = root / "operator.json"
    config = _operator_config(root)
    configured = dict(config.get("challenge_submit_metadata") or {}) if isinstance(config.get("challenge_submit_metadata"), Mapping) else {}
    configured[challenge_id] = normalized
    config["challenge_submit_metadata"] = configured
    config["updated_at"] = utc_now()
    _write_json(config_path, config)

    board_submit = dict(board.get("submit_metadata") or {}) if isinstance(board.get("submit_metadata"), Mapping) else {}
    board_submit[challenge_id] = normalized
    board["submit_metadata"] = board_submit
    item = _find_challenge(board, challenge_id)
    if isinstance(item, dict):
        item["submit_metadata"] = normalized
    board["updated_at"] = utc_now()
    _write_board(root, board)
    _write_board_md(root, board)


def _normalize_submit_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("challenge_id", "submit_type", "endpoint", "method", "field_name", "auth_source", "status_url", "status_check"):
        value = metadata.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        result[key] = text
    if result.get("submit_type") == "artifact_upload":
        result.setdefault("method", "multipart")
        result.setdefault("field_name", "file")
        result.setdefault("auth_source", "profile")
        result.setdefault("status_check", "optional")
    if "method" in result:
        result["method"] = str(result["method"]).strip().lower()
    return result


def _validate_submit_metadata_urls(metadata: Mapping[str, Any]) -> dict[str, Any]:
    warnings: list[str] = []
    field_name = str(metadata.get("field_name") or "")
    if field_name and not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", field_name):
        return {"allowed": False, "reason": "upload_field_name_invalid", "warnings": warnings}
    for key in ("endpoint", "status_url"):
        value = str(metadata.get(key) or "").strip()
        if not value:
            continue
        check = _validate_endpoint_url_syntax(value, label=key)
        if not check["allowed"]:
            return check
    return {"allowed": True, "reason": "", "warnings": warnings}


def _artifact_info(path: Path) -> dict[str, Any]:
    exists = path.exists() and path.is_file()
    return {
        "path": _display(path),
        "exists": exists,
        "size": path.stat().st_size if exists else 0,
        "sha256": _sha256_file(path) if exists else "",
    }


def _validate_official_upload_endpoint(root: Path, url: str, *, label: str) -> dict[str, Any]:
    syntax = _validate_endpoint_url_syntax(url, label=label)
    if not syntax["allowed"]:
        return syntax
    config = _operator_config(root)
    profile_path = str(config.get("profile_path") or "").strip()
    if not profile_path or profile_path == "TODO":
        return {"allowed": False, "reason": "profile_missing_for_endpoint_validation", "label": label}
    loaded = load_config_metadata(Path(profile_path).expanduser())
    if not loaded.get("exists"):
        return {"allowed": False, "reason": "profile_missing_for_endpoint_validation", "label": label}
    data = dict(loaded.get("data") or {})
    if not bool((data.get("policy") if isinstance(data.get("policy"), Mapping) else {}).get("allow_submission")):
        return {"allowed": False, "reason": "artifact_upload_not_allowed_by_profile_policy", "label": label}
    base_url = str(data.get("base_url") or data.get("url") or "").strip()
    if not base_url:
        return {"allowed": False, "reason": "profile_base_url_missing_for_endpoint_validation", "label": label}
    base_check = _validate_endpoint_url_syntax(base_url, label="profile_base_url")
    if not base_check["allowed"]:
        return {"allowed": False, "reason": "profile_base_url_invalid_for_endpoint_validation", "label": label}
    if not _same_url_origin(url, base_url):
        return {"allowed": False, "reason": f"{label}_not_official_profile_origin", "label": label, "profile_origin": _url_origin(base_url)}
    return {"allowed": True, "reason": "", "label": label, "profile_origin": _url_origin(base_url)}


def _validate_endpoint_url_syntax(url: str, *, label: str) -> dict[str, Any]:
    try:
        parsed = urllib.parse.urlsplit(str(url).strip())
    except ValueError:
        return {"allowed": False, "reason": f"{label}_invalid_url", "label": label}
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"allowed": False, "reason": f"{label}_requires_http_url", "label": label}
    if parsed.username or parsed.password:
        return {"allowed": False, "reason": f"{label}_must_not_embed_auth_material", "label": label}
    query_keys = {key.lower() for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
    if any(any(marker in key for marker in ("token", "secret", "cookie", "session", "auth", "password", "key")) for key in query_keys):
        return {"allowed": False, "reason": f"{label}_must_not_embed_auth_material", "label": label}
    if parsed.fragment:
        return {"allowed": False, "reason": f"{label}_must_not_use_fragment", "label": label}
    return {"allowed": True, "reason": "", "label": label}


def _same_url_origin(left: str, right: str) -> bool:
    return _url_origin(left) == _url_origin(right)


def _url_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value).strip())
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
    return f"{parsed.scheme}://{host}:{port}" if port else f"{parsed.scheme}://{host}"


def _upload_auth_headers(root: Path, endpoint: str) -> dict[str, str]:
    config = _operator_config(root)
    profile_path = str(config.get("profile_path") or "").strip()
    if not profile_path or profile_path == "TODO":
        raise FileNotFoundError("profile missing")
    loaded = load_config_metadata(Path(profile_path).expanduser())
    if not loaded.get("exists"):
        raise FileNotFoundError("profile missing")
    data = dict(loaded.get("data") or {})
    secret = load_auth_secret(data, live=True)
    headers = {"Accept": "application/json"}
    headers.update(secret.build_headers(base_url=endpoint))
    return headers


def _multipart_upload(endpoint: str, *, artifact_path: Path, field_name: str, headers: Mapping[str, str]) -> dict[str, Any]:
    boundary = f"dding-{hashlib.sha256((artifact_path.name + utc_now()).encode('utf-8')).hexdigest()[:32]}"
    filename = _safe_upload_filename(artifact_path.name)
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    file_bytes = artifact_path.read_bytes()
    body = b"".join(
        [
            f"--{boundary}\r\n".encode("ascii"),
            (
                f'Content-Disposition: form-data; name="{_multipart_quote(field_name)}"; '
                f'filename="{_multipart_quote(filename)}"\r\n'
            ).encode("utf-8"),
            f"Content-Type: {content_type}\r\n\r\n".encode("ascii"),
            file_bytes,
            f"\r\n--{boundary}--\r\n".encode("ascii"),
        ]
    )
    request_headers = dict(headers)
    request_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    request_headers["Content-Length"] = str(len(body))
    request = urllib.request.Request(endpoint, data=body, headers=request_headers, method="POST")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - endpoint is official-profile validated.
        raw_body = response.read(512 * 1024)
        status_code = int(getattr(response, "status", 0) or getattr(response, "code", 0) or 200)
    return _classify_upload_response(status_code, raw_body)


def _status_check(status_url: str, *, headers: Mapping[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(status_url, headers=dict(headers), method="GET")
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - endpoint is official-profile validated.
        raw_body = response.read(512 * 1024)
        status_code = int(getattr(response, "status", 0) or getattr(response, "code", 0) or 200)
    return _classify_upload_response(status_code, raw_body)


def _upload_http_error(exc: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        raw_body = exc.read(512 * 1024)
    except Exception:
        raw_body = b""
    return _classify_upload_response(int(exc.code), raw_body)


def _classify_upload_response(status_code: int, raw_body: bytes) -> dict[str, Any]:
    text = raw_body.decode("utf-8", errors="replace") if raw_body else ""
    payload: Any
    try:
        payload = json.loads(text) if text else {}
    except json.JSONDecodeError:
        payload = {"message": text}
    combined = _response_text(payload).lower()
    active = _response_active(payload)
    if status_code in {401, 403}:
        response_status = "auth_required"
    elif status_code == 429 or "rate limit" in combined or "too many" in combined:
        response_status = "rate_limited"
    elif status_code >= 400:
        response_status = "rejected"
    elif active is False or any(token in combined for token in ("incorrect", "wrong", "rejected", "failed", "inactive", "invalid")):
        response_status = "rejected"
    elif active is True or any(token in combined for token in ("accepted", "correct", "success", "active", "solved")):
        response_status = "accepted"
    else:
        response_status = "unknown"
    active_status = "active" if response_status == "accepted" or active is True else "inactive" if active is False else "unknown"
    return {
        "http_status": status_code,
        "response_status": response_status,
        "active_status": active_status,
        "response_summary": _response_summary(status_code, payload),
    }


def _merge_upload_status(upload: Mapping[str, Any], status_check: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(upload)
    merged["status_check"] = dict(status_check)
    status_response = str(status_check.get("response_status") or "")
    status_active = str(status_check.get("active_status") or "")
    if status_response == "accepted" or status_active == "active":
        merged["response_status"] = "accepted"
        merged["active_status"] = "active"
    elif status_active == "inactive" or status_response in {"rejected", "auth_required", "rate_limited"}:
        merged["response_status"] = status_response or "rejected"
        merged["active_status"] = status_active or "inactive"
    return merged


def _response_text(value: Any) -> str:
    if isinstance(value, Mapping):
        parts: list[str] = []
        for key in ("status", "result", "state", "message", "detail", "error"):
            item = value.get(key)
            if item is not None:
                parts.append(str(item))
        for key in ("data", "response"):
            item = value.get(key)
            if isinstance(item, Mapping):
                parts.append(_response_text(item))
        return " ".join(parts)
    if isinstance(value, list):
        return " ".join(_response_text(item) for item in value[:5])
    return str(value or "")


def _response_active(value: Any) -> bool | None:
    if isinstance(value, Mapping):
        for key in ("active", "is_active", "accepted", "ok", "success", "solved"):
            item = value.get(key)
            if isinstance(item, bool):
                return item
        for key in ("data", "response"):
            item = value.get(key)
            nested = _response_active(item)
            if nested is not None:
                return nested
    return None


def _response_summary(status_code: int, payload: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {"http_status": status_code}
    if isinstance(payload, Mapping):
        source = payload.get("data") if isinstance(payload.get("data"), Mapping) else payload
        for key in ("status", "result", "state", "message", "detail", "error"):
            if key in source:
                summary[key] = redact_text(str(source.get(key) or ""))[:500]
        active = _response_active(payload)
        if active is not None:
            summary["active"] = active
    elif payload:
        summary["message"] = redact_text(str(payload))[:500]
    return summary


def _artifact_terminal_event(status: str) -> str:
    if status == "accepted":
        return "artifact_submit_accepted"
    if status == "blocked":
        return "artifact_submit_blocked"
    if status == "rejected":
        return "artifact_submit_rejected"
    return ""


def _artifact_metric_data(record: Mapping[str, Any]) -> dict[str, Any]:
    data = {
        "status": record.get("status"),
        "reason": record.get("reason"),
        "artifact_sha256": record.get("artifact_sha256"),
        "artifact_size": record.get("artifact_size"),
        "response_status": record.get("response_status"),
        "http_status": record.get("http_status"),
        "active_status": record.get("active_status"),
        "submitted_at": record.get("submitted_at") or record.get("timestamp"),
    }
    return {key: value for key, value in data.items() if value not in (None, "")}


def _safe_upload_filename(value: str) -> str:
    filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(value or "artifact.bin").name).strip("._")
    return filename[:160] or "artifact.bin"


def _multipart_quote(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _canonicalize_challenges(challenges: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    raw = [_challenge_from_source(item) for item in challenges if item]
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in raw:
        key = _normalize(str(item.get("canonical_name") or item.get("name") or item.get("challenge_id") or ""))
        if not key:
            continue
        groups.setdefault(key, []).append(item)

    result: list[dict[str, Any]] = []
    canonical_map: dict[str, str] = {}
    warnings: list[str] = []
    alias_count = 0
    skipped_static_count = 0
    for _key, group in groups.items():
        canonical_source = max(group, key=_canonical_source_score)
        canonical = _canonical_entry(canonical_source)
        aliases: list[str] = []
        artifact_sources: list[str] = []
        source_ids: list[str] = []
        platform_solved = bool(canonical.get("platform_solved"))
        platform_solved_known = bool(canonical.get("platform_solved_known"))
        solved_aliases: list[str] = []
        submit_metadata = canonical.get("platform_submission") if isinstance(canonical.get("platform_submission"), Mapping) else {}

        for source in group:
            source_id = str(source.get("challenge_id") or source.get("name") or "").strip()
            if source_id:
                source_ids.append(source_id)
                canonical_map[source_id] = str(canonical["challenge_id"])
            if source.get("slug"):
                canonical_map[str(source["slug"])] = str(canonical["challenge_id"])
            platform_solved_known = platform_solved_known or bool(source.get("platform_solved_known"))
            platform_solved = platform_solved or bool(source.get("platform_solved"))
            if source.get("platform_solved"):
                solved_aliases.extend(_platform_solved_alias_values(source, canonical))
            if isinstance(source.get("platform_submission"), Mapping):
                submit_metadata = {**dict(submit_metadata), **dict(source["platform_submission"])}

            if source is canonical_source:
                continue
            alias_count += 1
            for alias in _source_alias_values(source):
                aliases.append(alias)
                canonical_map[alias] = str(canonical["challenge_id"])
            if _is_artifact_source(source):
                skipped_static_count += 1
                for alias in _source_alias_values(source):
                    artifact_sources.append(alias)
            warnings.append(f"alias:{source_id}->{canonical['challenge_id']}")

        if canonical_source.get("is_static_shell"):
            skipped_static_count += 1
        canonical["aliases"] = _dedupe_strings(aliases)
        canonical["artifact_sources"] = _dedupe_strings(artifact_sources)
        canonical["source_ids"] = _dedupe_strings(source_ids)
        canonical["platform_solved"] = platform_solved
        canonical["platform_solved_known"] = platform_solved_known
        canonical["solved_aliases"] = _dedupe_strings([*_list_values(canonical.get("solved_aliases")), *solved_aliases])
        if submit_metadata:
            canonical["platform_submission"] = dict(submit_metadata)
        if platform_solved:
            canonical["status"] = "solved"
            canonical["solved_by_platform"] = True
            canonical["solved_source"] = "platform"
        canonical["claimable"] = _claimable_source(canonical)
        result.append(canonical)

    counts = {
        "canonical_count": len(result),
        "alias_count": alias_count,
        "skipped_static_count": skipped_static_count,
        "claimable_count": sum(1 for item in result if _claimable_source(item)),
    }
    return {"challenges": result, "map": canonical_map, "warnings": warnings, "counts": counts}


def _challenge_from_source(item: Mapping[str, Any]) -> dict[str, Any]:
    challenge_id = str(item.get("challenge_id") or item.get("id") or item.get("slug") or item.get("name") or "").strip()
    name = str(item.get("name") or challenge_id).strip()
    metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
    statement = redact_text(str(item.get("statement") or item.get("description") or metadata.get("statement") or "")).strip()
    attachments = _source_attachments(item)
    links = _source_links(item)
    file_count = _source_file_count(item, attachments)
    platform_status = _source_platform_status(item)
    platform_submission = _source_submission_summary(item)
    platform_solved_known = _source_platform_solved_known(item, platform_status=platform_status, platform_submission=platform_submission)
    platform_solved = _source_platform_solved(item, platform_status=platform_status, platform_submission=platform_submission)
    canonical_name = _canonical_name(str(name or challenge_id))
    is_static_shell = _is_static_shell_source(
        {
            "challenge_id": challenge_id,
            "name": name,
            "statement": statement,
            "file_count": file_count,
            "links": links,
        }
    )
    return {
        "challenge_id": challenge_id,
        "name": name,
        "slug": str(item.get("slug") or "").strip(),
        "category": str(item.get("category") or metadata.get("category") or ""),
        "points": item.get("points") or item.get("value"),
        "solves": item.get("solves"),
        "statement": statement,
        "statement_bytes": len(statement.encode("utf-8")),
        "has_files": file_count > 0,
        "file_count": file_count,
        "attachment_count": file_count,
        "link_count": len(links),
        "platform_solved": platform_solved,
        "platform_solved_known": platform_solved_known,
        "platform_status": platform_status,
        "platform_submission": platform_submission,
        "canonical_id": challenge_id,
        "canonical_name": canonical_name,
        "is_static_shell": is_static_shell,
        "is_static_alias": is_static_shell,
        "claimable": not is_static_shell,
        "solved_by_platform": platform_solved,
        "solved_by_external": False,
        "solved_source": "platform" if platform_solved else "",
        "solved_aliases": [],
        "tags": list(item.get("tags") or []),
        "priority": 100,
        "status": "solved" if platform_solved else "skipped" if is_static_shell else "todo",
    }


def _canonical_name(value: str) -> str:
    lowered = value.strip()
    lowered = re.sub(r"[-_\s]*static$", "", lowered, flags=re.IGNORECASE)
    lowered = re.sub(r"[-_\s]*phase[-_\s]*\d+$", "", lowered, flags=re.IGNORECASE)
    known = {
        "birdhouse": "Birdhouse",
        "myfavoriteinstructions": "My Favorite Instructions",
        "favoriteinstructions": "My Favorite Instructions",
        "favorite": "My Favorite Instructions",
        "stork": "Stork",
        "twobirdtwocan": "2bird2can",
        "2bird2can": "2bird2can",
        "waybirdmachine": "Waybird Machine",
        "livectf": "LiveCTF",
        "livectfphase1": "LiveCTF",
    }
    compact = _normalize(lowered)
    if compact in known:
        return known[compact]
    return re.sub(r"[_-]+", " ", lowered).strip().title()


def _canonical_entry(source: Mapping[str, Any]) -> dict[str, Any]:
    canonical = dict(source)
    canonical["canonical_id"] = str(source.get("challenge_id") or source.get("name") or "")
    canonical["canonical_name"] = str(source.get("canonical_name") or source.get("name") or canonical["canonical_id"])
    canonical["is_alias"] = False
    canonical["is_static_alias"] = False
    canonical.setdefault("aliases", [])
    canonical.setdefault("artifact_sources", [])
    canonical.setdefault("source_ids", [canonical["canonical_id"]])
    canonical.setdefault("solved_aliases", [])
    canonical.setdefault("solved_source", "platform" if canonical.get("platform_solved") else "")
    canonical["claimable"] = not bool(canonical.get("is_static_shell"))
    if canonical.get("is_static_shell"):
        canonical["status"] = "skipped"
    return canonical


def _canonical_source_score(item: Mapping[str, Any]) -> tuple[int, int, int, int, str]:
    statement_bytes = int(item.get("statement_bytes") or 0)
    display = str(item.get("name") or item.get("challenge_id") or "")
    ident = str(item.get("challenge_id") or "")
    score = 0
    if item.get("is_static_shell"):
        score -= 1000
    if item.get("has_files") or int(item.get("attachment_count") or 0) > 0:
        score += 300
    score += min(statement_bytes, 1200) // 8
    if _looks_display_name(display, ident):
        score += 120
    if _is_phase_metadata(item):
        score -= 200
    if str(ident).lower().endswith("-static"):
        score -= 200
    if item.get("platform_solved"):
        score += 10
    return (score, len(display), statement_bytes, -len(ident), display)


def _looks_display_name(name: str, challenge_id: str) -> bool:
    text = str(name or "").strip()
    ident = str(challenge_id or "").strip()
    if not text:
        return False
    if text != ident and (" " in text or any(char.isupper() for char in text)):
        return True
    return bool(any(char.isupper() for char in text) and not re.fullmatch(r"[a-z0-9_-]+", text))


def _source_alias_values(source: Mapping[str, Any]) -> list[str]:
    values = [
        str(source.get("challenge_id") or "").strip(),
        str(source.get("name") or "").strip(),
        str(source.get("slug") or "").strip(),
    ]
    return _dedupe_strings(value for value in values if value)


def _platform_solved_alias_values(source: Mapping[str, Any], canonical: Mapping[str, Any]) -> list[str]:
    canonical_keys = {
        _normalize(str(canonical.get("challenge_id") or "")),
        _normalize(str(canonical.get("canonical_id") or "")),
        _normalize(str(canonical.get("canonical_name") or "")),
        _normalize(str(canonical.get("name") or "")),
    }
    aliases: list[str] = []
    for value in _source_alias_values(source):
        if _normalize(value) not in canonical_keys:
            aliases.append(value)
    return _dedupe_strings(aliases)


def _is_artifact_source(source: Mapping[str, Any]) -> bool:
    ident = str(source.get("challenge_id") or source.get("name") or "").lower()
    return bool(source.get("is_static_shell") or ident.endswith("-static"))


def _is_static_shell_source(item: Mapping[str, Any]) -> bool:
    ident = str(item.get("challenge_id") or item.get("name") or "").strip().lower()
    statement = str(item.get("statement") or "").strip()
    statement_lower = statement.lower()
    statement_bytes = len(statement.encode("utf-8"))
    file_count = int(item.get("file_count") or item.get("attachment_count") or 0)
    links = list(item.get("links") or [])
    if ident.endswith("-static"):
        return True
    if file_count > 0:
        return False
    if statement_bytes <= 120 and links and _links_are_only_static_assets(links):
        return True
    generic_titles = {"def con ctf quals 2026", "defcon ctf quals 2026", "def con ctf quals", "defcon ctf quals"}
    if statement_lower in generic_titles and links and _links_are_only_static_assets(links):
        return True
    return False


def _is_phase_metadata(item: Mapping[str, Any]) -> bool:
    text = " ".join(str(item.get(key) or "") for key in ("challenge_id", "name", "slug")).lower()
    return bool(re.search(r"(?:^|[-_\s])phase[-_\s]*\d+$", text))


def _source_attachments(item: Mapping[str, Any]) -> list[str]:
    raw = item.get("attachments")
    if raw is None:
        raw = item.get("_attachments_private")
    if raw is None:
        raw = item.get("files")
    if raw is None:
        return []
    values = raw if isinstance(raw, list) else [raw]
    attachments: list[str] = []
    for value in values:
        if isinstance(value, Mapping):
            text = str(value.get("filename") or value.get("name") or value.get("source") or value.get("url") or value.get("path") or "").strip()
        else:
            text = str(value or "").strip()
        if text:
            attachments.append(redact_text(text)[:200])
    return _dedupe_strings(attachments)


def _source_links(item: Mapping[str, Any]) -> list[str]:
    raw = item.get("links")
    if raw is None:
        raw = item.get("_links_private")
    if raw is None:
        return []
    values = raw if isinstance(raw, list) else [raw]
    links: list[str] = []
    for value in values:
        if isinstance(value, Mapping):
            text = " ".join(
                str(value.get(key) or "").strip()
                for key in ("label", "text", "filename", "name", "rel", "source", "url", "href")
                if value.get(key)
            )
        else:
            text = str(value or "").strip()
        if text:
            links.append(redact_text(text)[:300])
    return _dedupe_strings(links)


def _source_file_count(item: Mapping[str, Any], attachments: list[str]) -> int:
    for key in ("attachment_count", "file_count"):
        value = _int_value(item.get(key))
        if value is not None:
            return max(0, value)
    if attachments:
        return len(attachments)
    return 1 if item.get("has_files") else 0


def _source_platform_status(item: Mapping[str, Any]) -> str:
    for key in ("platform_status", "state", "phase", "result"):
        value = str(item.get(key) or "").strip()
        if value:
            return redact_text(value)[:120]
    value = item.get("status")
    if isinstance(value, str) and value.strip().lower() not in {"todo", "new"}:
        return redact_text(value.strip())[:120]
    return ""


def _source_submission_summary(item: Mapping[str, Any]) -> dict[str, Any]:
    raw = None
    for key in ("submission", "last_submission", "submission_result", "submit_result"):
        if item.get(key) is not None:
            raw = item.get(key)
            break
    status = str(item.get("submission_status") or item.get("submit_status") or "").strip()
    summary: dict[str, Any] = {}
    if isinstance(raw, Mapping):
        for key in ("status", "state", "result", "active_status", "submitted_at", "timestamp"):
            value = raw.get(key)
            if value is None:
                continue
            summary[key] = redact_text(str(value))[:160]
        summary["present"] = True
    elif isinstance(raw, bool):
        summary["present"] = raw
    elif isinstance(raw, str) and raw.strip():
        lowered = raw.strip().lower()
        if lowered in {"accepted", "correct", "solved", "already_solved", "rejected", "incorrect", "wrong", "pending", "queued"}:
            summary["status"] = lowered
        summary["present"] = True
    if status:
        summary["status"] = redact_text(status)[:120]
        summary["present"] = True
    return summary


def _source_platform_solved_known(item: Mapping[str, Any], *, platform_status: str, platform_submission: Mapping[str, Any]) -> bool:
    for key in ("solved", "solved_by_me", "completed", "accepted", "correct"):
        if key in item and item.get(key) is not None:
            return True
    if platform_submission:
        return True
    status_text = " ".join(
        str(value or "")
        for value in (
            platform_status,
            platform_submission.get("status"),
            platform_submission.get("state"),
            platform_submission.get("result"),
        )
    ).lower()
    if not status_text.strip():
        return False
    if any(token in status_text for token in ("unsolved", "not solved", "already_solved", "already solved")):
        return True
    status_words = set(re.sub(r"[^a-z0-9]+", " ", status_text).split())
    return bool(status_words & {"accepted", "correct", "solved", "completed", "incorrect", "wrong", "rejected"})


def _source_platform_solved(item: Mapping[str, Any], *, platform_status: str, platform_submission: Mapping[str, Any]) -> bool:
    solved = item.get("solved")
    if solved is None:
        solved = item.get("solved_by_me", item.get("completed"))
    if solved is None:
        solved = item.get("accepted", item.get("correct"))
    if isinstance(solved, bool):
        return solved
    if solved is not None and str(solved).strip().lower() in {"1", "true", "yes", "solved", "accepted", "correct", "completed"}:
        return True
    status_text = " ".join(
        str(value or "")
        for value in (
            platform_status,
            platform_submission.get("status"),
            platform_submission.get("state"),
            platform_submission.get("result"),
        )
    ).lower()
    if any(token in status_text for token in ("unsolved", "not solved", "incorrect", "wrong", "rejected")):
        return False
    status_words = set(re.sub(r"[^a-z0-9]+", " ", status_text).split())
    return bool(status_words & {"accepted", "correct", "solved", "completed"} or "already_solved" in status_text)


def _empty_solved_status(source: str) -> dict[str, Any]:
    return {"available": False, "source": source, "records": []}


def _discover_solved_status(challenges: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    available = False
    for item in challenges:
        if not isinstance(item, Mapping):
            continue
        record = _platform_solved_record_from_mapping(item, source="discover")
        if not record:
            continue
        available = True
        records.append(record)
    return {"available": available, "source": "discover" if available else "unavailable", "records": records}


def _collect_platform_solved_status(platform: Any, *, live: bool) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    sources: list[str] = []
    attempted = False
    for name in (
        "solved_status",
        "get_solved_status",
        "list_solved",
        "list_solved_challenges",
        "list_submissions",
        "discover_submissions",
        "submission_status",
    ):
        method = getattr(platform, name, None)
        if not callable(method):
            continue
        attempted = True
        payload = _call_platform_solved_method(method, live=live)
        status = str(payload.get("status") or "")
        if status in {"blocked", "planned", "not_implemented", "auth_required", "rate_limited", "network_error", "unexpected_response", "error"}:
            continue
        parsed = _platform_solved_records_from_payload(payload.get("payload"), source=name)
        if parsed["available"]:
            records.extend(parsed["records"])
            sources.append(name)
    if records or sources:
        return {"available": True, "source": "+".join(_dedupe_strings(sources)) or "platform", "records": records}
    return _empty_solved_status("unavailable" if attempted else "unavailable")


def _call_platform_solved_method(method: Any, *, live: bool) -> dict[str, Any]:
    try:
        result = method(live=live)
    except TypeError:
        try:
            result = method()
        except TypeError as exc:
            return {"status": "error", "payload": {"reason": redact_text(str(exc))[:200]}}
    except Exception as exc:  # pragma: no cover - defensive adapter boundary.
        return {"status": "error", "payload": {"reason": redact_text(str(exc))[:200]}}
    if isinstance(result, PlatformAction):
        return {"status": result.status, "payload": action_to_dict(result)}
    if isinstance(result, Mapping):
        return {"status": str(result.get("status") or "ok"), "payload": dict(result)}
    if isinstance(result, list):
        return {"status": "ok", "payload": result}
    return {"status": "unavailable", "payload": {}}


def _combine_solved_status_sources(discovered: Mapping[str, Any], adapter: Mapping[str, Any], *, pull_solved: bool) -> str:
    sources: list[str] = []
    if discovered.get("available"):
        sources.append(str(discovered.get("source") or "discover"))
    if adapter.get("available"):
        sources.append(str(adapter.get("source") or "platform"))
    if sources:
        return "+".join(_dedupe_strings(sources))
    return "unavailable" if pull_solved else "not_requested"


def _platform_solved_records_from_payload(payload: Any, *, source: str) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    available = False

    def add(record: dict[str, Any] | None) -> None:
        nonlocal available
        if not record:
            return
        available = True
        records.append(record)

    def visit(value: Any, *, key_hint: str = "", depth: int = 0) -> None:
        nonlocal available
        if depth > 5:
            return
        if isinstance(value, PlatformAction):
            visit(action_to_dict(value), key_hint=key_hint, depth=depth + 1)
            return
        if isinstance(value, Mapping):
            details = value.get("details")
            if isinstance(details, Mapping):
                visit(details, key_hint=key_hint, depth=depth + 1)
            data = value.get("data")
            if isinstance(data, (Mapping, list)):
                visit(data, key_hint=key_hint or "data", depth=depth + 1)
            if _looks_like_status_map(value):
                for challenge, status_value in value.items():
                    add(_platform_solved_record_from_key_value(str(challenge), status_value, source=source))
                return
            add(_platform_solved_record_from_mapping(value, source=source))
            for key in (
                "solved",
                "solved_challenges",
                "solved_ids",
                "solved_names",
                "team_solved",
                "accepted",
                "submissions",
                "submission",
                "last_submission",
                "statuses",
                "status",
                "challenges",
                "items",
                "results",
            ):
                if key in value:
                    if key in {"solved", "solved_challenges", "solved_ids", "solved_names", "team_solved", "accepted", "submissions", "statuses"}:
                        available = True
                    visit(value.get(key), key_hint=key, depth=depth + 1)
            return
        if isinstance(value, list):
            if key_hint in {"solved", "solved_challenges", "solved_ids", "solved_names", "team_solved", "accepted"}:
                for item in value:
                    if isinstance(item, (str, int)) and not isinstance(item, bool):
                        add(_platform_solved_record_from_key_value(str(item), True, source=source))
                    else:
                        visit(item, key_hint=key_hint, depth=depth + 1)
                return
            for item in value:
                visit(item, key_hint=key_hint, depth=depth + 1)
            return
        if key_hint in {"solved", "solved_challenges", "solved_ids", "solved_names", "team_solved", "accepted"} and isinstance(value, (str, int)) and not isinstance(value, bool):
            add(_platform_solved_record_from_key_value(str(value), True, source=source))

    visit(payload)
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        challenge = str(record.get("challenge") or "").strip()
        if not challenge:
            continue
        key = (_normalize(challenge), str(record.get("source") or source))
        existing = deduped.get(key)
        if existing and existing.get("solved"):
            continue
        deduped[key] = record
    return {"available": available, "records": list(deduped.values())}


def _looks_like_status_map(value: Mapping[str, Any]) -> bool:
    if not value:
        return False
    structural = {
        "action",
        "details",
        "data",
        "status",
        "challenges",
        "items",
        "results",
        "submissions",
        "solved",
        "challenge_id",
        "id",
        "name",
        "slug",
    }
    if any(key in structural for key in value.keys()):
        return False
    scalar_count = 0
    for item in value.values():
        if isinstance(item, (bool, str, int)) or item is None:
            scalar_count += 1
        elif isinstance(item, Mapping):
            scalar_count += 1
        else:
            return False
    return scalar_count > 0


def _platform_solved_record_from_key_value(challenge: str, value: Any, *, source: str) -> dict[str, Any] | None:
    if isinstance(value, Mapping):
        payload = {"challenge_id": challenge, **dict(value)}
        return _platform_solved_record_from_mapping(payload, source=source)
    if isinstance(value, bool):
        solved = value
        known = True
        status = "solved" if value else "unsolved"
    else:
        status = str(value or "").strip()
        status_payload = {"challenge_id": challenge, "status": status}
        known = _source_platform_solved_known(status_payload, platform_status=status, platform_submission={})
        solved = _source_platform_solved(status_payload, platform_status=status, platform_submission={})
    if not challenge or not known:
        return None
    return {"challenge": challenge, "solved": solved, "known": known, "status": redact_text(status)[:120], "source": source}


def _platform_solved_record_from_mapping(item: Mapping[str, Any], *, source: str) -> dict[str, Any] | None:
    nested_challenge = item.get("challenge") or item.get("problem") or item.get("task")
    nested: Mapping[str, Any] = nested_challenge if isinstance(nested_challenge, Mapping) else {}
    challenge = str(
        item.get("challenge_id")
        or item.get("id")
        or item.get("slug")
        or item.get("canonical_id")
        or nested.get("challenge_id")
        or nested.get("id")
        or nested.get("slug")
        or nested.get("name")
        or item.get("name")
        or item.get("title")
        or ""
    ).strip()
    if not challenge:
        return None
    platform_status = _source_platform_status(item)
    platform_submission = _source_submission_summary(item)
    known = _source_platform_solved_known(item, platform_status=platform_status, platform_submission=platform_submission)
    if not known and nested:
        platform_status = platform_status or _source_platform_status(nested)
        platform_submission = platform_submission or _source_submission_summary(nested)
        known = _source_platform_solved_known(nested, platform_status=platform_status, platform_submission=platform_submission)
    if not known:
        return None
    solved = _source_platform_solved(item, platform_status=platform_status, platform_submission=platform_submission)
    if not solved and nested:
        solved = _source_platform_solved(nested, platform_status=platform_status, platform_submission=platform_submission)
    aliases = _dedupe_strings(
        [
            str(item.get("alias") or ""),
            str(item.get("slug") or ""),
            str(item.get("name") or ""),
            str(nested.get("slug") or ""),
            str(nested.get("name") or ""),
        ]
    )
    return {
        "challenge": challenge,
        "solved": solved,
        "known": known,
        "status": redact_text(str(platform_status or platform_submission.get("status") or ""))[:120],
        "source": source,
        "aliases": aliases,
    }


def _apply_platform_solved_records(
    root: Path,
    board: dict[str, Any],
    records: Iterable[Mapping[str, Any]],
    *,
    available: bool,
    source: str,
    synced_at: str,
) -> dict[str, Any]:
    synced_ids: set[str] = set()
    alias_resolved: set[str] = set()
    for record in records:
        challenge = str(record.get("challenge") or "").strip()
        if not challenge:
            continue
        item = _find_challenge(board, challenge)
        if item is None:
            continue
        item["platform_solved_known"] = True
        if not bool(record.get("solved")):
            continue
        item["platform_solved"] = True
        item["solved_by_platform"] = True
        item["solved_synced_at"] = synced_at
        if str(item.get("solved_source") or "") in {"", "platform"}:
            item["solved_source"] = "platform"
        if not item.get("solved_by_external"):
            item["status"] = "solved"
        aliases = _list_values(item.get("solved_aliases"))
        if _record_resolved_alias(item, challenge):
            aliases.append(challenge)
            alias_resolved.add(_sync_key(item) or challenge)
        for alias in _list_values(record.get("aliases")):
            if alias and _record_resolved_alias(item, str(alias)):
                aliases.append(str(alias))
                alias_resolved.add(_sync_key(item) or challenge)
        item["solved_aliases"] = _dedupe_strings(aliases)
        synced_ids.add(_sync_key(item) or _normalize(challenge))
    countable_items = [item for item in board.get("challenges", []) if isinstance(item, Mapping) and _status_countable_item(item)]
    metadata = {
        "available": bool(available),
        "source": source,
        "solved_status_source": source,
        "last_synced_at": synced_at if available or source != "not_requested" else "",
        "solved_synced_count": len(synced_ids),
        "external_solved_count": sum(1 for item in countable_items if item.get("solved_by_external")),
        "solved_by_platform_count": sum(1 for item in countable_items if item.get("solved_by_platform") or item.get("platform_solved")),
        "solved_alias_resolved_count": len(alias_resolved),
    }
    board["solved_sync"] = metadata
    return metadata


def _refresh_solved_sync_counts(board: dict[str, Any], metadata: Mapping[str, Any]) -> dict[str, Any]:
    countable_items = [item for item in board.get("challenges", []) if isinstance(item, Mapping) and _status_countable_item(item)]
    refreshed = dict(metadata)
    refreshed["external_solved_count"] = sum(1 for item in countable_items if item.get("solved_by_external"))
    refreshed["solved_by_platform_count"] = sum(1 for item in countable_items if item.get("solved_by_platform") or item.get("platform_solved"))
    board["solved_sync"] = refreshed
    return refreshed


def _record_resolved_alias(item: Mapping[str, Any], challenge: str) -> bool:
    wanted = _normalize(challenge)
    direct = {
        _normalize(str(item.get("challenge_id") or "")),
        _normalize(str(item.get("canonical_id") or "")),
        _normalize(str(item.get("canonical_name") or "")),
        _normalize(str(item.get("name") or "")),
    }
    return bool(wanted and wanted not in direct and wanted in _challenge_keys(item))


def _links_are_only_static_assets(links: Iterable[Any]) -> bool:
    seen = False
    for link in links:
        text = str(link or "").strip().lower()
        if not text:
            continue
        seen = True
        if not any(token in text for token in ("favicon", ".css", "stylesheet", "style.css", "icon", "manifest")):
            return False
    return seen


def _previous_challenge(previous_by_key: Mapping[str, dict[str, Any]], item: Mapping[str, Any]) -> dict[str, Any]:
    preferred = [
        _normalize(str(item.get("challenge_id") or "")),
        _normalize(str(item.get("canonical_id") or "")),
        _normalize(str(item.get("canonical_name") or "")),
    ]
    preferred.extend(_normalize(str(value)) for value in _list_values(item.get("source_ids")))
    for key in preferred:
        previous = previous_by_key.get(key)
        if previous:
            return previous
    for key in _challenge_keys(item):
        previous = previous_by_key.get(key)
        if previous:
            return previous
    return {}


def _merge_challenge_entry(previous: Mapping[str, Any], item: Mapping[str, Any]) -> dict[str, Any]:
    merged = _normalize_challenge_entry({**dict(previous or {}), **dict(item)})
    for key in ("aliases", "artifact_sources", "source_ids"):
        merged[key] = _dedupe_strings([*_list_values(previous.get(key)), *_list_values(item.get(key))])
    if isinstance(previous.get("submit_metadata"), Mapping) and "submit_metadata" not in item:
        merged["submit_metadata"] = dict(previous["submit_metadata"])
    previous_status = str(previous.get("status") or "")
    item_status = str(item.get("status") or "")
    if item.get("platform_solved"):
        merged["status"] = "solved"
        merged["solved_by_platform"] = True
        if str(previous.get("solved_source") or "") not in {"submit", "external_solved_txt", "manual"}:
            merged["solved_source"] = "platform"
    elif item_status == "external_solved":
        merged["status"] = "external_solved"
        merged["solved_by_external"] = True
        merged.setdefault("solved_source", "external_solved_txt")
    elif previous_status in {"solved", "external_solved", "stalled", "claimed"}:
        merged["status"] = previous_status
        if previous_status == "external_solved":
            merged["solved_by_external"] = True
    for key in ("claimed_by", "claimed_at", "solved_at", "solved_synced_at", "flag_hash", "artifact_sha256", "stalled_reason"):
        if key in previous and key not in item:
            merged[key] = previous[key]
    merged["claimable"] = _claimable_source(merged)
    return merged


def _normalize_challenge_entry(item: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(item)
    challenge_id = str(normalized.get("challenge_id") or normalized.get("canonical_id") or normalized.get("name") or "").strip()
    name = str(normalized.get("name") or normalized.get("canonical_name") or challenge_id).strip()
    normalized["challenge_id"] = challenge_id
    normalized["name"] = name
    normalized["canonical_id"] = str(normalized.get("canonical_id") or challenge_id)
    normalized["canonical_name"] = str(normalized.get("canonical_name") or name)
    normalized["aliases"] = _dedupe_strings(_list_values(normalized.get("aliases")))
    normalized["artifact_sources"] = _dedupe_strings(_list_values(normalized.get("artifact_sources")))
    normalized["source_ids"] = _dedupe_strings(_list_values(normalized.get("source_ids")) or [challenge_id])
    normalized["is_alias"] = bool(normalized.get("is_alias", False))
    normalized["is_static_shell"] = bool(normalized.get("is_static_shell", False))
    normalized["is_static_alias"] = bool(normalized.get("is_static_alias", False))
    normalized["platform_solved"] = bool(normalized.get("platform_solved", False))
    normalized["platform_solved_known"] = bool(normalized.get("platform_solved_known", False))
    normalized["solved_by_platform"] = bool(normalized.get("solved_by_platform", False))
    normalized["solved_by_external"] = bool(normalized.get("solved_by_external", False))
    normalized["solved_aliases"] = _dedupe_strings(_list_values(normalized.get("solved_aliases")))
    normalized["solved_source"] = str(normalized.get("solved_source") or "")
    normalized.setdefault("priority", 100)
    normalized.setdefault("status", "skipped" if normalized.get("is_static_shell") else "todo")
    normalized["claimable"] = _claimable_source(normalized)
    return normalized


def _challenge_text_for_ingest(challenge: Mapping[str, Any]) -> str:
    return redact_text(str(challenge.get("statement") or "").strip())


def _apply_runtime_statuses(root: Path, board: dict[str, Any]) -> None:
    solved_ids = {_normalize(str(row.get("challenge_id"))) for row in _read_jsonl(root / "solved.jsonl") if row.get("challenge_id")}
    external_lines = (root / "external_solved.txt").read_text(encoding="utf-8").splitlines() if (root / "external_solved.txt").exists() else []
    external = {_normalize(line.strip()) for line in external_lines if line.strip()}
    stalled = {_normalize(str(row.get("challenge_id"))) for row in _read_jsonl(root / "stalled.jsonl") if row.get("challenge_id")}
    claimed = {_normalize(value) for value in _claimed_ids(root)}
    for item in board.get("challenges", []):
        cid = str(item.get("challenge_id") or "")
        keys = _challenge_keys(item)
        item["claimable"] = _claimable_source(item)
        if keys & solved_ids:
            item["status"] = "solved"
            item["solved_source"] = "submit"
            item["solved_by_external"] = False
        elif keys & external:
            item["status"] = "external_solved"
            item["solved_by_external"] = True
            item["solved_source"] = "external_solved_txt"
            item["solved_aliases"] = _dedupe_strings(
                [
                    *_list_values(item.get("solved_aliases")),
                    *[line.strip() for line in external_lines if _normalize(line.strip()) in keys],
                ]
            )
        elif item.get("platform_solved") or item.get("solved_by_platform"):
            item["status"] = "solved"
            item["solved_by_platform"] = True
            item["solved_source"] = "platform"
        elif keys & claimed:
            item["status"] = "claimed"
        elif keys & stalled:
            item["status"] = "stalled"
        elif not _claimable_source(item):
            item["status"] = "skipped"
        elif item.get("status") in {"solved", "external_solved", "stalled", "claimed", "skipped"}:
            continue
        else:
            item["status"] = "todo"


def _operator_status_summary(contest_id: str, root: Path, board: Mapping[str, Any]) -> dict[str, Any]:
    buckets: dict[str, list[dict[str, Any]]] = {key: [] for key in ("todo", "claimed", "solved", "external_solved", "stalled", "skipped")}
    items = [item for item in board.get("challenges", []) if isinstance(item, Mapping) and _status_countable_item(item)]
    for item in items:
        state = _completion_item_status(root, item)
        buckets.setdefault(state, []).append(_challenge_public(item))
    canonical_counts = board.get("canonical_counts") if isinstance(board.get("canonical_counts"), Mapping) else {}
    canonical_count = _int_value(canonical_counts.get("canonical_count")) if canonical_counts else None
    if canonical_count is None:
        canonical_count = len(items)
    alias_count = _int_value(canonical_counts.get("alias_count")) if canonical_counts else None
    if alias_count is None:
        alias_count = _computed_alias_count(board)
    artifact_source_count = sum(len(_list_values(item.get("artifact_sources"))) for item in board.get("challenges", []) if isinstance(item, Mapping))
    skipped_static_count = _int_value(canonical_counts.get("skipped_static_count")) if canonical_counts else None
    if skipped_static_count is None:
        skipped_static_count = sum(1 for item in board.get("challenges", []) if isinstance(item, Mapping) and (item.get("is_static_shell") or item.get("is_static_alias"))) + artifact_source_count
    claimable_count = sum(1 for item in items if _claimable(root, item))
    solved_by_platform_count = sum(1 for item in items if item.get("solved_by_platform") or item.get("platform_solved"))
    solved_by_external_count = sum(1 for item in items if item.get("solved_by_external"))
    active_claims, stale_claims = _claim_rows(root, board)
    counts = {
        "todo": len(buckets["todo"]),
        "claimed": len(buckets["claimed"]),
        "solved": len(buckets["solved"]),
        "external_solved": len(buckets["external_solved"]),
        "stalled": len(buckets["stalled"]),
        "skipped": len(buckets["skipped"]),
        "canonical_count": canonical_count,
        "alias_count": alias_count,
        "artifact_sources_count": artifact_source_count,
        "skipped_static_count": skipped_static_count,
        "claimable_count": claimable_count,
        "solved_by_platform_count": solved_by_platform_count,
        "solved_by_external_count": solved_by_external_count,
        "active_claim_count": len(active_claims),
        "stale_claim_count": len(stale_claims),
    }
    completion_status = _completion_status(root, board, counts)
    no_useful_work = completion_status in {"all_solved", "all_solved_or_stalled", "no_claimable"}
    profile_path = str(board.get("profile_path") or _operator_config(root).get("profile_path") or "")
    solved_sync = board.get("solved_sync") if isinstance(board.get("solved_sync"), Mapping) else {}
    solved_sync_available = bool(solved_sync.get("available") or any(item.get("platform_solved_known") for item in items))
    return {
        "status": "ok",
        "contest_id": contest_id,
        "operator_root": _display(root),
        "canonical_count": canonical_count,
        "claimable_count": claimable_count,
        "todo": counts["todo"],
        "claimed": counts["claimed"],
        "solved": counts["solved"],
        "external_solved": counts["external_solved"],
        "solved_by_platform_count": solved_by_platform_count,
        "solved_by_external_count": solved_by_external_count,
        "solved_sync_available": solved_sync_available,
        "stalled": counts["stalled"],
        "skipped": counts["skipped"],
        "alias_count": alias_count,
        "artifact_sources_count": artifact_source_count,
        "artifact_source_count": artifact_source_count,
        "skipped_static_count": skipped_static_count,
        "active_local_claims": active_claims,
        "stale_claims": stale_claims,
        "no_useful_work": no_useful_work,
        "completion_status": completion_status,
        "counts": counts,
        "challenges": buckets,
        "canonical_map": board.get("canonical_map", {}),
        "profile_path": profile_path,
        "last_sync_at": board.get("last_sync_at") or "",
        "solved_sync": solved_sync,
    }


def _completion_status(root: Path, board: Mapping[str, Any], counts: Mapping[str, Any]) -> str:
    work_count = int(counts.get("todo") or 0) + int(counts.get("claimed") or 0) + int(counts.get("solved") or 0) + int(counts.get("external_solved") or 0) + int(counts.get("stalled") or 0)
    if int(counts.get("todo") or 0) > 0 or int(counts.get("claimed") or 0) > 0:
        return "active"
    if int(counts.get("canonical_count") or 0) == 0 and _profile_configured(root, board) and not board.get("last_sync_at"):
        return "needs_sync"
    solved_total = int(counts.get("solved") or 0) + int(counts.get("external_solved") or 0)
    if work_count > 0 and solved_total == work_count:
        return "all_solved"
    if work_count > 0 and solved_total + int(counts.get("stalled") or 0) == work_count:
        return "all_solved_or_stalled"
    if int(counts.get("claimable_count") or 0) == 0:
        return "no_claimable"
    return "active"


def _completion_item_status(root: Path, item: Mapping[str, Any]) -> str:
    if str(item.get("status") or "") == "external_solved" or item.get("solved_by_external"):
        return "external_solved"
    if item.get("solved_by_platform") or item.get("platform_solved"):
        return "solved"
    status = _challenge_status(root, item)
    if status in {"solved", "claimed", "stalled", "skipped"}:
        return status
    if not _claimable_source(item):
        return "skipped"
    return "todo"


def _status_countable_item(item: Mapping[str, Any]) -> bool:
    if item.get("is_alias") or item.get("is_artifact_source") or item.get("artifact_source"):
        return False
    challenge_id = str(item.get("challenge_id") or "")
    canonical_id = str(item.get("canonical_id") or challenge_id)
    if item.get("is_static_alias") and _normalize(canonical_id) not in {"", _normalize(challenge_id)}:
        return False
    return True


def _computed_alias_count(board: Mapping[str, Any]) -> int:
    count = 0
    for item in board.get("challenges", []):
        if not isinstance(item, Mapping):
            continue
        count += len(_list_values(item.get("aliases")))
        challenge_id = str(item.get("challenge_id") or "")
        canonical_id = str(item.get("canonical_id") or challenge_id)
        if item.get("is_alias") or (item.get("is_static_alias") and _normalize(canonical_id) not in {"", _normalize(challenge_id)}):
            count += 1
    return count


def _profile_configured(root: Path, board: Mapping[str, Any]) -> bool:
    profile_path = str(board.get("profile_path") or _operator_config(root).get("profile_path") or "").strip()
    return bool(profile_path and profile_path != "TODO")


def _compact_status_summary(summary: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "canonical_count",
        "claimable_count",
        "todo",
        "claimed",
        "solved",
        "external_solved",
        "solved_by_platform_count",
        "solved_by_external_count",
        "solved_sync_available",
        "stalled",
        "skipped",
        "alias_count",
        "artifact_sources_count",
        "completion_status",
        "no_useful_work",
    )
    return {key: summary.get(key) for key in keys}


def _claim_rows(root: Path, board: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    for path in sorted((root / "claims").glob("*.lock")):
        data = _read_json_file(path)
        item = _find_claimed_item(board, data)
        state = _completion_item_status(root, item) if item else "not_found"
        is_stale = state in {"solved", "external_solved", "stalled", "skipped", "not_found"}
        row = {
            "agent": data.get("agent") or "",
            "challenge_id": data.get("challenge_id") or (item.get("challenge_id") if item else ""),
            "name": data.get("name") or (item.get("name") if item else ""),
            "canonical_id": data.get("canonical_id") or (item.get("canonical_id") if item else ""),
            "category": data.get("category") or (item.get("category") if item else ""),
            "claimed_at": data.get("claimed_at") or "",
            "allow_duplicate": bool(data.get("allow_duplicate")),
            "lock_path": _display(path),
            "challenge_status": state,
            "stale": is_stale,
        }
        (stale if is_stale else active).append(row)
    return active, stale


def _find_claimed_item(board: Mapping[str, Any], data: Mapping[str, Any]) -> dict[str, Any] | None:
    for value in [
        data.get("challenge_id"),
        data.get("canonical_id"),
        data.get("canonical_name"),
        data.get("name"),
        *_list_values(data.get("aliases")),
        *_list_values(data.get("source_ids")),
        *_list_values(data.get("artifact_sources")),
    ]:
        text = str(value or "")
        if not text:
            continue
        item = _find_challenge(board, text)
        if item is not None:
            return item
    return None


def _stale_claims(root: Path, board: Mapping[str, Any]) -> list[dict[str, Any]]:
    return _claim_rows(root, board)[1]


def _claim_metric_rows(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "agent": row.get("agent") or "",
            "challenge_id": row.get("challenge_id") or "",
            "challenge_status": row.get("challenge_status") or "",
            "claimed_at": row.get("claimed_at") or "",
        }
        for row in list(rows)[:50]
    ]


def _record_no_work_metrics(root: Path, contest_id: str, summary: Mapping[str, Any], *, source: str) -> None:
    stale_claims = summary.get("stale_claims") if isinstance(summary.get("stale_claims"), list) else []
    if stale_claims:
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="stale_claims_detected",
            data={"source": source, "stale_count": len(stale_claims), "claims": _claim_metric_rows(stale_claims)},
        )
    if summary.get("no_useful_work"):
        _record_metrics_event(
            root,
            contest_id=contest_id,
            event="no_useful_work",
            data={**_compact_status_summary(summary), "source": source},
        )


def _refresh_operator_once(contest_id: str, root: Path, profile: str | Path | None, *, pull_solved: bool = True) -> dict[str, Any]:
    resolved = _refresh_profile_path(root, profile)
    if not resolved:
        return {"status": "blocked", "contest_id": contest_id, "reason": "profile_required_for_refresh"}
    return sync_operator(contest_id, profile=resolved, live=True, pull_solved=pull_solved)


def _refresh_profile_path(root: Path, profile: str | Path | None) -> str | None:
    if profile:
        return str(Path(profile).expanduser())
    configured = str(_operator_config(root).get("profile_path") or "").strip()
    if not configured or configured == "TODO":
        return None
    return str(_expand_display_path(configured))


def _claimable_source(item: Mapping[str, Any]) -> bool:
    if item.get("is_alias") or item.get("is_static_alias") or item.get("is_static_shell") or item.get("is_artifact_source") or item.get("artifact_source"):
        return False
    return bool(item.get("claimable", True))


def _claimable(root: Path, item: Mapping[str, Any]) -> bool:
    return _challenge_status(root, item) == "todo" and _claimable_source(item)


def _challenge_status(root: Path, item: Mapping[str, Any]) -> str:
    status = str(item.get("status") or "todo")
    if status == "external_solved" or item.get("solved_by_external") or item.get("solved_by_platform") or item.get("platform_solved"):
        return "solved"
    if status in {"solved", "claimed", "stalled", "skipped"}:
        return status
    return "todo"


def _item_solved_by_platform_or_external(item: Mapping[str, Any]) -> bool:
    return bool(item.get("solved_by_external") or item.get("solved_by_platform") or item.get("platform_solved"))


def _is_solved(root: Path, item: Mapping[str, Any]) -> bool:
    return _challenge_status(root, item) == "solved"


def _is_accepted(root: Path, challenge_id: str) -> bool:
    return _accepted_record(root, challenge_id) is not None


def _accepted_record(root: Path, challenge_id: str) -> dict[str, Any] | None:
    for row in _read_jsonl(root / "solved.jsonl"):
        if str(row.get("challenge_id")) == str(challenge_id) and str(row.get("status") or "accepted") == "accepted":
            return row
    return None


def _claimed_ids(root: Path) -> set[str]:
    ids: set[str] = set()
    for path in (root / "claims").glob("*.lock"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("challenge_id"):
                ids.add(str(data["challenge_id"]))
        except (OSError, json.JSONDecodeError):
            continue
    return ids


def _release_locks(root: Path, *, agent: str | None, challenge: str | None) -> int:
    count = 0
    wanted = _normalize(challenge or "")
    for path in (root / "claims").glob("*.lock"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        if agent and str(data.get("agent")) != agent:
            continue
        keys = {
            _normalize(str(data.get("challenge_id") or "")),
            _normalize(str(data.get("name") or "")),
            _normalize(str(data.get("canonical_id") or "")),
            _normalize(str(data.get("canonical_name") or "")),
        }
        keys.update(_normalize(str(value)) for value in _list_values(data.get("aliases")))
        keys.update(_normalize(str(value)) for value in _list_values(data.get("source_ids")))
        keys.update(_normalize(str(value)) for value in _list_values(data.get("artifact_sources")))
        if wanted and wanted not in keys:
            continue
        _unlink(path)
        count += 1
    return count


def _release_locks_for_item(root: Path, *, agent: str | None, item: Mapping[str, Any]) -> int:
    released = 0
    for key in _challenge_release_values(item):
        released += _release_locks(root, agent=agent, challenge=key)
    return released


def _find_challenge(board: Mapping[str, Any], challenge: str) -> dict[str, Any] | None:
    wanted = _normalize(challenge)
    matches: list[dict[str, Any]] = []
    for item in board.get("challenges", []):
        if wanted in _challenge_keys(item):
            matches.append(item)
    if not matches:
        return None
    return max(matches, key=lambda item: _challenge_resolution_score(item, wanted))


def _challenge_resolution_score(item: Mapping[str, Any], wanted: str) -> tuple[int, int, int, str]:
    score = 0
    if _claimable_source(item):
        score += 1000
    if not item.get("is_alias") and not item.get("is_static_alias") and not item.get("is_static_shell"):
        score += 200
    if _normalize(str(item.get("challenge_id") or "")) == wanted:
        score += 40
    if _normalize(str(item.get("canonical_id") or "")) == wanted:
        score += 35
    if _normalize(str(item.get("canonical_name") or "")) == wanted:
        score += 25
    if _normalize(str(item.get("name") or "")) == wanted:
        score += 20
    if wanted in {_normalize(str(value)) for value in _list_values(item.get("aliases"))}:
        score += 15
    if wanted in {_normalize(str(value)) for value in _list_values(item.get("artifact_sources"))}:
        score += 10
    return (score, int(not item.get("is_alias")), int(not item.get("is_static_shell")), str(item.get("name") or ""))


def _challenge_keys(item: Mapping[str, Any]) -> set[str]:
    keys = {
        _normalize(str(item.get("challenge_id") or "")),
        _normalize(str(item.get("name") or "")),
        _normalize(str(item.get("canonical_id") or "")),
        _normalize(str(item.get("canonical_name") or "")),
    }
    keys.update(_normalize(str(alias)) for alias in _list_values(item.get("aliases")))
    keys.update(_normalize(str(alias)) for alias in _list_values(item.get("artifact_sources")))
    keys.update(_normalize(str(alias)) for alias in _list_values(item.get("source_ids")))
    return {key for key in keys if key}


def _challenge_release_values(item: Mapping[str, Any]) -> list[str]:
    values = [
        str(item.get("challenge_id") or ""),
        str(item.get("name") or ""),
        str(item.get("canonical_id") or ""),
        str(item.get("canonical_name") or ""),
    ]
    values.extend(str(value) for value in _list_values(item.get("aliases")))
    values.extend(str(value) for value in _list_values(item.get("artifact_sources")))
    values.extend(str(value) for value in _list_values(item.get("source_ids")))
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _sync_signatures(root: Path, items: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    signatures: dict[str, str] = {}
    for item in items:
        if not _status_countable_item(item):
            continue
        key = _sync_key(item)
        if not key:
            continue
        payload = {
            "challenge_id": item.get("challenge_id") or "",
            "canonical_id": item.get("canonical_id") or "",
            "canonical_name": item.get("canonical_name") or "",
            "name": item.get("name") or "",
            "category": item.get("category") or "",
            "points": item.get("points"),
            "solves": item.get("solves"),
            "statement": item.get("statement") or "",
            "has_files": bool(item.get("has_files")),
            "file_count": _int_value(item.get("file_count")) or 0,
            "attachment_count": _int_value(item.get("attachment_count")) or 0,
            "link_count": _int_value(item.get("link_count")) or 0,
            "aliases": sorted(str(value) for value in _list_values(item.get("aliases"))),
            "artifact_sources": sorted(str(value) for value in _list_values(item.get("artifact_sources"))),
            "source_ids": sorted(str(value) for value in _list_values(item.get("source_ids"))),
            "platform_solved": bool(item.get("platform_solved")),
            "solved_by_platform": bool(item.get("solved_by_platform")),
            "solved_by_external": bool(item.get("solved_by_external")),
            "solved_source": str(item.get("solved_source") or ""),
            "solved_aliases": sorted(str(value) for value in _list_values(item.get("solved_aliases"))),
            "status": _completion_item_status(root, item),
            "claimable": bool(item.get("claimable", True)),
        }
        signatures[key] = json.dumps(payload, sort_keys=True, default=str)
    return signatures


def _sync_statuses(root: Path, items: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for item in items:
        if not _status_countable_item(item):
            continue
        key = _sync_key(item)
        if key:
            statuses[key] = _completion_item_status(root, item)
    return statuses


def _sync_public_ids(items: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        if not _status_countable_item(item):
            continue
        key = _sync_key(item)
        if key:
            result[key] = str(item.get("challenge_id") or item.get("canonical_id") or item.get("name") or key)
    return result


def _sync_key(item: Mapping[str, Any]) -> str:
    for value in (item.get("canonical_id"), item.get("challenge_id"), item.get("canonical_name"), item.get("name")):
        key = _normalize(str(value or ""))
        if key:
            return key
    return ""


def _external_solved_lines(item: Mapping[str, Any], challenge: str) -> list[str]:
    seen: set[str] = set()
    lines: list[str] = []
    for value in [challenge, *_challenge_release_values(item)]:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        lines.append(text)
    return lines


def _challenge_path(contest_id: str, item: Mapping[str, Any]) -> Path:
    category = _safe_slug(str(item.get("category") or "misc"))
    name = _safe_slug(str(item.get("name") or item.get("challenge_id") or "challenge"))
    return get_paths().contests_root / _safe_slug(contest_id) / category / name


def _rank_next_targets(
    root: Path,
    contest_id: str,
    board: Mapping[str, Any],
    *,
    category: str | None,
    allow_duplicate: bool,
) -> list[dict[str, Any]]:
    fresh: list[tuple[dict[str, Any], str]] = []
    duplicate_claimed: list[tuple[dict[str, Any], str]] = []
    for raw_item in board.get("challenges", []):
        if not isinstance(raw_item, dict):
            continue
        item = raw_item
        if not _claimable_source(item):
            continue
        if category and not _target_category_matches(contest_id, root, item, category):
            continue
        status = _challenge_status(root, item)
        if status == "todo":
            fresh.append((item, status))
        elif status == "claimed" and allow_duplicate:
            duplicate_claimed.append((item, status))

    selected_pool = fresh or duplicate_claimed
    ranked: list[dict[str, Any]] = []
    for item, status in selected_pool:
        score, reasons = _target_score(root, contest_id, item, status=status)
        ranked.append({"item": item, "status": status, "score": score, "reasons": reasons})
    return sorted(
        ranked,
        key=lambda row: (
            -int(row["score"]),
            int(row["item"].get("priority") or 100),
            str(row["item"].get("name") or row["item"].get("challenge_id") or ""),
        ),
    )


def _target_category_matches(contest_id: str, root: Path, item: Mapping[str, Any], wanted: str) -> bool:
    wanted_norm = _normalize(wanted)
    if not wanted_norm:
        return True
    declared = str(item.get("category") or "")
    values = {
        _normalize(declared),
        _normalize(_playbook_category(declared, has_remote=False)),
    }
    guess = _category_guess(item, _candidate_challenge_dirs(contest_id, item))
    values.add(_normalize(str(guess.get("category") or "")))
    values.add(_normalize(str(guess.get("declared") or "")))
    return wanted_norm in values


def _target_score(root: Path, contest_id: str, item: Mapping[str, Any], *, status: str) -> tuple[int, list[str]]:
    context = _target_context(contest_id, root, item)
    score = 0
    reasons: list[str] = []
    priority = _int_value(item.get("priority"))
    if priority is not None:
        priority_bonus = max(0, 150 - min(priority, 150)) // 5
        if priority_bonus:
            score += priority_bonus
            reasons.append(f"priority_bonus={priority_bonus}")

    if _target_has_files(item, context):
        score += 40
        reasons.append("has_files_or_artifacts")
    if context["remote_endpoints"]:
        score += 25
        reasons.append("remote_endpoint")
    if (context.get("web_metadata") or {}).get("base_url"):
        score += 25
        reasons.append("web_base_url")

    category_guess = context["category_guess"]
    confidence = int(category_guess.get("confidence") or 0)
    if confidence >= 75:
        score += 15
        reasons.append("high_category_confidence")
    elif category_guess.get("category"):
        score += 8
        reasons.append("category_known")

    progress_kinds = _memo_progress_kinds(context["memo_summaries"])
    if progress_kinds:
        score += 18
        reasons.append("previous_progress=" + ",".join(progress_kinds[:4]))
    if context["memo_summaries"].get("next_steps", {}).get("has_content"):
        score += 14
        reasons.append("clear_next_steps")

    if status == "stalled":
        score += 10
        reasons.append("stalled_retryable")
    elif status == "claimed":
        score -= 20
        reasons.append("duplicate_claim")

    if item.get("is_static_shell") or item.get("is_static_alias") or item.get("is_alias"):
        score -= 1000
        reasons.append("static_or_alias_penalty")
    if _generic_low_information_target(item, context):
        score -= 25
        reasons.append("low_information_no_files")
    if _challenge_status(root, item) == "solved":
        score -= 1000
        reasons.append("already_solved")
    return score, reasons


def _target_context(contest_id: str, root: Path, item: Mapping[str, Any]) -> dict[str, Any]:
    challenge_dir = _challenge_workdir(contest_id, item)
    _ensure_challenge_memos(challenge_dir)
    candidate_dirs = _candidate_challenge_dirs(contest_id, item, challenge_dir=challenge_dir)
    brief_path = _locate_brief_path(item, candidate_dirs)
    raw_dirs = _existing_named_dirs(candidate_dirs, ("raw", "handout"))
    extracted_dirs = _existing_named_dirs(candidate_dirs, ("extracted",))
    manifest_paths = _existing_named_files(candidate_dirs, ("manifest/manifest.json",))
    scan_paths = _existing_named_files(candidate_dirs, ("manifest/scan.json",))
    memo_summaries = _memo_summaries(challenge_dir)
    remote_endpoints = _remote_endpoints(item, brief_path=brief_path)
    service_metadata = _service_metadata_for_item(root, {"challenges": [item]}, item, str(item.get("challenge_id") or ""))
    web_metadata = _web_metadata_for_item(root, {"challenges": [item]}, item, str(item.get("challenge_id") or ""))
    if not service_metadata:
        service_endpoint = None
        for endpoint_text in remote_endpoints:
            service_endpoint = _parse_service_endpoint(str(endpoint_text))
            if service_endpoint:
                break
        if service_endpoint:
            service_metadata = _build_service_metadata(
                str(item.get("challenge_id") or ""),
                endpoint=service_endpoint,
                endpoint_source="challenge_metadata",
                token_source={"type": "none"},
                pow_helper=None,
            )
    if not web_metadata:
        web_base_url = _web_base_url_from_endpoints(remote_endpoints)
        if web_base_url:
            web_metadata = _build_web_metadata(
                str(item.get("challenge_id") or ""),
                base_url=web_base_url,
                base_url_source="challenge_metadata",
                auth_source={"status": "ok", "type": "none"},
            )
    category_guess = _category_guess(item, candidate_dirs, scan_paths=scan_paths, has_remote=bool(remote_endpoints))
    top_files = _top_interesting_files(candidate_dirs, manifest_paths=manifest_paths, scan_paths=scan_paths)
    return {
        "contest_id": contest_id,
        "operator_root": root,
        "challenge_dir": challenge_dir,
        "candidate_dirs": candidate_dirs,
        "brief_path": brief_path,
        "raw_dirs": raw_dirs,
        "extracted_dirs": extracted_dirs,
        "manifest_paths": manifest_paths,
        "scan_paths": scan_paths,
        "memo_summaries": memo_summaries,
        "remote_endpoints": remote_endpoints,
        "service_metadata": service_metadata,
        "web_metadata": web_metadata,
        "category_guess": category_guess,
        "top_files": top_files,
    }


def _attach_toolchain_context(root: Path, contest_id: str, context: dict[str, Any], *, category: str | None = None) -> None:
    effective = category or str((context.get("category_guess") or {}).get("category") or "")
    report = _toolchain_report_for_context(root, contest_id, effective)
    summary = summarize_capabilities_for_category(report, effective)
    context["toolchain_report"] = report
    context["toolchain_summary"] = summary


def _challenge_workdir(contest_id: str, item: Mapping[str, Any]) -> Path:
    raw_path = str(item.get("path") or "").strip()
    if raw_path:
        return _expand_display_path(raw_path)
    return _challenge_path(contest_id, item)


def _candidate_challenge_dirs(contest_id: str, item: Mapping[str, Any], *, challenge_dir: Path | None = None) -> list[Path]:
    contest_root = get_paths().contests_root / _safe_slug(contest_id)
    raw_values = [
        challenge_dir or _challenge_workdir(contest_id, item),
        _challenge_path(contest_id, item),
        contest_root / _safe_slug(str(item.get("challenge_id") or "")),
        contest_root / _safe_slug(str(item.get("canonical_id") or "")),
        contest_root / _safe_slug(str(item.get("canonical_name") or "")),
    ]
    result: list[Path] = []
    seen: set[str] = set()
    for value in raw_values:
        path = Path(value).expanduser()
        key = path.resolve().as_posix() if path.exists() else path.as_posix()
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def _locate_brief_path(item: Mapping[str, Any], candidate_dirs: Iterable[Path]) -> Path | None:
    raw = str(item.get("brief_path") or "").strip()
    if raw:
        path = _expand_display_path(raw)
        if path.exists() and path.is_file():
            return path
    for base in candidate_dirs:
        path = base / "brief.md"
        if path.exists() and path.is_file():
            return path
    return None


def _existing_named_dirs(candidate_dirs: Iterable[Path], names: tuple[str, ...]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for base in candidate_dirs:
        for name in names:
            path = base / name
            if not path.exists() or not path.is_dir():
                continue
            key = path.resolve().as_posix()
            if key in seen:
                continue
            seen.add(key)
            result.append(path)
    return result


def _existing_named_files(candidate_dirs: Iterable[Path], names: tuple[str, ...]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for base in candidate_dirs:
        for name in names:
            path = base / name
            if not path.exists() or not path.is_file():
                continue
            key = path.resolve().as_posix()
            if key in seen:
                continue
            seen.add(key)
            result.append(path)
    return result


def _memo_summaries(challenge_dir: Path) -> dict[str, dict[str, Any]]:
    summaries: dict[str, dict[str, Any]] = {}
    for kind in MEMO_KINDS:
        path = challenge_dir / f"{kind}.md"
        text = _read_target_text(path, 5000)
        content = _memo_content(text, kind)
        summaries[kind] = {
            "path": _display(path),
            "has_content": bool(content),
            "summary": _target_summary(content, 700),
        }
    return summaries


def _memo_content(text: str, kind: str) -> str:
    title = kind.replace("_", " ").title()
    lines = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped == f"# {title}":
            continue
        lines.append(stripped)
    return "\n".join(lines).strip()


def _memo_progress_kinds(memos: Mapping[str, Mapping[str, Any]]) -> list[str]:
    result: list[str] = []
    for kind in ("memory", "evidence", "attempts", "operator_notes", "next_steps"):
        if memos.get(kind, {}).get("has_content"):
            result.append(kind)
    return result


def _stalled_has_clear_next_step(contest_id: str, item: Mapping[str, Any]) -> bool:
    challenge_dir = _challenge_workdir(contest_id, item)
    next_steps = _memo_content(_read_target_text(challenge_dir / "next_steps.md", 4000), "next_steps")
    if next_steps and len(next_steps.split()) >= 3:
        return True
    reason = str(item.get("stalled_reason") or "").strip().lower()
    return bool(reason and any(token in reason for token in ("next", "try", "todo", "need", "check", "inspect", "test")))


def _target_has_files(item: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    if bool(item.get("has_files")) or int(item.get("attachment_count") or item.get("file_count") or 0) > 0:
        return True
    for key in ("raw_dirs", "extracted_dirs"):
        for path in context.get(key) or []:
            if _dir_has_files(Path(path)):
                return True
    return bool(context.get("top_files"))


def _generic_low_information_target(item: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    if _target_has_files(item, context) or context.get("remote_endpoints"):
        return False
    statement = re.sub(r"\s+", " ", str(item.get("statement") or "")).strip().lower()
    if not statement:
        return True
    generic_titles = {"def con ctf quals 2026", "defcon ctf quals 2026", "def con ctf quals", "defcon ctf quals"}
    return statement in generic_titles or len(statement) < 80


def _remote_endpoints(item: Mapping[str, Any], *, brief_path: Path | None) -> list[str]:
    texts: list[str] = []
    for key in ("statement", "connection_info", "remote", "url"):
        value = item.get(key)
        if value:
            texts.append(str(value))
    for value in _list_values(item.get("links")):
        texts.append(str(value))
    for key in ("submit_metadata", "platform_submission", "platform_submit", "submit"):
        raw = item.get(key)
        if isinstance(raw, Mapping):
            for subkey in ("endpoint", "status_url", "connection_info", "remote", "url"):
                if raw.get(subkey):
                    texts.append(str(raw[subkey]))
    if brief_path:
        texts.append(_read_target_text(brief_path, 8000))

    endpoints: list[str] = []
    for text in texts:
        safe = _target_safe_text(text)
        endpoints.extend(match.group(0).rstrip(").,]") for match in re.finditer(r"https?://[^\s'\"<>]+", safe))
        for match in re.finditer(r"(?i)\b(?:nc|ncat|netcat)\s+((?:--ssl|-ssl|--tls|-tls)\s+)?([A-Za-z0-9_.-]+)\s+([0-9]{2,5})", safe):
            endpoints.append(f"ncat {'--ssl ' if match.group(1) else ''}{match.group(2)} {match.group(3)}")
        for match in re.finditer(r"\b((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|localhost|127(?:\.\d{1,3}){3}):([0-9]{2,5})\b", safe):
            endpoints.append(f"{match.group(1)}:{match.group(2)}")
    return _dedupe_strings(endpoints)[:12]


def _category_guess(
    item: Mapping[str, Any],
    candidate_dirs: Iterable[Path],
    *,
    scan_paths: Iterable[Path] | None = None,
    has_remote: bool = False,
) -> dict[str, Any]:
    declared = str(item.get("category") or "").strip()
    category = _playbook_category(declared, has_remote=has_remote)
    confidence = 75 if declared else 0
    sources = [f"declared:{declared}"] if declared else []
    paths = list(scan_paths or _existing_named_files(candidate_dirs, ("manifest/scan.json",)))
    for path in paths:
        scan = _read_json_file(path)
        likely = scan.get("likely_categories") if isinstance(scan.get("likely_categories"), list) else []
        if not likely:
            continue
        top = likely[0]
        inferred_raw = str(top.get("category") or "")
        inferred = _playbook_category(inferred_raw, has_remote=has_remote)
        inferred_score = int(top.get("score") or 0)
        sources.append(f"inferred:{inferred_raw}:{inferred_score}")
        inferred_confidence = min(95, 50 + inferred_score * 5)
        if not category:
            category = inferred
            confidence = max(confidence, inferred_confidence)
        elif inferred == category:
            confidence = max(confidence, min(95, confidence + 15, inferred_confidence + 10))
        else:
            confidence = max(confidence, 65 if declared else inferred_confidence)
    if not category:
        category = "forensics/misc"
        confidence = 35
        sources.append("fallback:forensics/misc")
    return {"category": category, "declared": declared, "confidence": confidence, "sources": sources}


def _playbook_category(value: str, *, has_remote: bool) -> str:
    raw = str(value or "").strip().lower()
    compact = _normalize(raw)
    if compact in {"web", "http", "browser", "xss"}:
        return "web"
    if compact in {"pwn", "pwnable", "binaryexploitation", "exploit"}:
        return "pwn"
    if compact in {"rev", "reverse", "reversing", "reverseengineering"}:
        return "rev"
    if compact in {"pwnrev"}:
        return "pwn" if has_remote else "rev"
    if compact in {"crypto", "cryptography"}:
        return "crypto"
    if compact in {"forensics", "forensic", "misc", "stego", "steganography", "hardware", "network"}:
        return "forensics/misc"
    if compact in {"osint", "opensourceintelligence", "geoint"}:
        return "osint"
    if compact in {"ai", "ml", "aiml", "machinelearning", "llm"}:
        return "ai/ml"
    return raw if raw in PLAYBOOK_CATEGORIES else ""


def _top_interesting_files(
    candidate_dirs: Iterable[Path],
    *,
    manifest_paths: Iterable[Path],
    scan_paths: Iterable[Path],
) -> list[dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    manifest_roots: dict[str, Path] = {}
    for manifest_path in manifest_paths:
        manifest = _read_json_file(manifest_path)
        root = _manifest_root(manifest, manifest_path.parent.parent)
        manifest_roots[manifest_path.as_posix()] = root
        entries = [entry for entry in manifest.get("files") or [] if isinstance(entry, Mapping)]
        entries.sort(key=lambda entry: (-int(entry.get("interesting_score") or 0), str(entry.get("path") or "")))
        for entry in entries[:30]:
            rel = str(entry.get("path") or "")
            if not rel or is_sensitive_path(rel):
                continue
            key = (root / rel).as_posix()
            files.setdefault(
                key,
                {
                    "path": rel,
                    "root": _display(root),
                    "category": entry.get("category", "unknown"),
                    "score": int(entry.get("interesting_score") or 0),
                    "reasons": _list_values(entry.get("reasons"))[:4],
                },
            )
    for scan_path in scan_paths:
        scan = _read_json_file(scan_path)
        root = manifest_roots.get((scan_path.parent / "manifest.json").as_posix(), scan_path.parent.parent)
        for entry in (scan.get("interesting_files") or [])[:30]:
            if not isinstance(entry, Mapping):
                continue
            rel = str(entry.get("path") or "")
            if not rel or is_sensitive_path(rel):
                continue
            key = (root / rel).as_posix()
            current = files.setdefault(
                key,
                {"path": rel, "root": _display(root), "category": entry.get("category", "unknown"), "score": 0, "reasons": []},
            )
            current["score"] = max(int(current.get("score") or 0), int(entry.get("score") or 0))
            current["reasons"] = _dedupe_strings([*_list_values(current.get("reasons")), *_list_values(entry.get("reasons"))])[:4]
    if not files:
        for base in candidate_dirs:
            for subdir in ("raw", "handout", "extracted"):
                path = base / subdir
                if not path.exists() or not path.is_dir():
                    continue
                for child in sorted(path.rglob("*"))[:50]:
                    if not child.is_file():
                        continue
                    try:
                        rel = child.relative_to(base).as_posix()
                    except ValueError:
                        rel = child.name
                    if is_sensitive_path(rel):
                        continue
                    files.setdefault(
                        child.as_posix(),
                        {"path": rel, "root": _display(base), "category": "unknown", "score": 1, "reasons": ["artifact file"]},
                    )
                    if len(files) >= 18:
                        break
    return sorted(files.values(), key=lambda entry: (-int(entry.get("score") or 0), str(entry.get("path") or "")))[:18]


def _manifest_root(manifest: Mapping[str, Any], fallback: Path) -> Path:
    raw = str(manifest.get("root_dir") or "").strip()
    if raw:
        return _expand_display_path(raw)
    return fallback


def _effective_triage_category(category: str | None, context: Mapping[str, Any]) -> str:
    if category:
        normalized = _playbook_category(category, has_remote=bool(context.get("remote_endpoints")))
        return normalized if normalized in PLAYBOOK_CATEGORIES else "forensics/misc"
    guess = context.get("category_guess") if isinstance(context.get("category_guess"), Mapping) else {}
    normalized = _playbook_category(str(guess.get("category") or ""), has_remote=bool(context.get("remote_endpoints")))
    return normalized if normalized in PLAYBOOK_CATEGORIES else "forensics/misc"


def _triage_file_inventory(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    challenge_dir = Path(context["challenge_dir"]).expanduser()

    def add(path: Path, *, role: str, root: Path | None = None, score: int = 0, reasons: Iterable[str] = ()) -> None:
        expanded = path.expanduser()
        if not expanded.exists() or not expanded.is_file():
            return
        try:
            key = expanded.resolve().as_posix()
        except OSError:
            key = expanded.as_posix()
        if key in seen:
            return
        seen.add(key)
        base = root.expanduser() if root else challenge_dir
        try:
            rel = expanded.relative_to(base).as_posix()
        except ValueError:
            rel = expanded.name
        if is_sensitive_path(rel) or is_sensitive_path(expanded.name):
            return
        try:
            stat = expanded.stat()
        except OSError:
            return
        kind, signature = _triage_file_signature(expanded)
        rows.append(
            {
                "path": rel,
                "abs_path": str(expanded),
                "display_path": _display(expanded),
                "root": _display(base),
                "role": role,
                "size": stat.st_size,
                "suffix": expanded.suffix.lower(),
                "kind": kind,
                "signature": signature,
                "score": score,
                "reasons": _dedupe_strings(str(reason) for reason in reasons)[:5],
            }
        )

    if context.get("brief_path"):
        add(Path(context["brief_path"]), role="brief", root=challenge_dir, score=60, reasons=["brief"])
    for path in context.get("manifest_paths") or []:
        add(Path(path), role="manifest", root=Path(path).parent.parent, score=45, reasons=["manifest"])
    for path in context.get("scan_paths") or []:
        add(Path(path), role="manifest", root=Path(path).parent.parent, score=45, reasons=["scan"])
    for kind in MEMO_KINDS:
        add(challenge_dir / f"{kind}.md", role=f"memo:{kind}", root=challenge_dir, score=20, reasons=["memo"])

    for entry in context.get("top_files") or []:
        if not isinstance(entry, Mapping):
            continue
        root = _expand_display_path(str(entry.get("root") or ""))
        rel = str(entry.get("path") or "")
        if rel:
            add(root / rel, role="top_file", root=root, score=int(entry.get("score") or 0), reasons=_list_values(entry.get("reasons")))

    for base in context.get("candidate_dirs") or [challenge_dir]:
        base_path = Path(base).expanduser()
        for dirname in ("raw", "handout", "extracted"):
            artifact_root = base_path / dirname
            if not artifact_root.exists() or not artifact_root.is_dir():
                continue
            count = 0
            for child in sorted(artifact_root.rglob("*")):
                if child.is_file():
                    add(child, role=dirname, root=base_path, score=5, reasons=["local artifact"])
                    count += 1
                if count >= 250:
                    break
    return sorted(rows, key=lambda row: (-int(row.get("score") or 0), str(row.get("role") or ""), str(row.get("path") or "")))[:400]


def _triage_file_signature(path: Path) -> tuple[str, str]:
    data = _read_file_prefix(path, 4096)
    suffix = path.suffix.lower()
    if data.startswith(b"\x7fELF"):
        return "elf", "ELF"
    if data.startswith(b"MZ"):
        return "pe", "MZ"
    if data.startswith(b"\xca\xfe\xba\xbe") or data.startswith(b"\xfe\xed\xfa") or data.startswith(b"\xcf\xfa\xed\xfe"):
        return "mach-o", "Mach-O"
    if data.startswith(b"\x00asm"):
        return "wasm", "WASM"
    if data.startswith(b"PK\x03\x04"):
        if suffix == ".apk":
            return "apk", "ZIP/APK"
        if suffix in {".jar", ".war"}:
            return "jar", "ZIP/JAR"
        return "zip", "ZIP"
    if data.startswith(b"%PDF"):
        return "pdf", "PDF"
    if data.startswith(b"\x89PNG"):
        return "image", "PNG"
    if data.startswith(b"\xff\xd8\xff"):
        return "image", "JPEG"
    if data.startswith(b"SQLite format 3"):
        return "sqlite", "SQLite"
    if data.startswith(b"\xd4\xc3\xb2\xa1") or data.startswith(b"\xa1\xb2\xc3\xd4") or data.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcap", "PCAP"
    if suffix in {".py", ".js", ".ts", ".php", ".rb", ".go", ".rs", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".html", ".css", ".sql", ".sh"}:
        return "source", suffix.lstrip(".")
    if suffix in {".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".log", ".csv"}:
        return "text", suffix.lstrip(".")
    if suffix in {".pt", ".pth", ".onnx", ".pkl", ".pickle", ".safetensors", ".h5", ".joblib"}:
        return "model", suffix.lstrip(".")
    if data and b"\x00" not in data[:2048]:
        return "text", "text"
    return "binary" if data else "unknown", "binary" if data else "empty"


def _read_file_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def _triage_file_path(row: Mapping[str, Any]) -> Path:
    return Path(str(row.get("abs_path") or row.get("display_path") or row.get("path") or "")).expanduser()


def _run_category_triage_commands(category: str, context: Mapping[str, Any], files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cwd = Path(context["challenge_dir"]).expanduser()
    primary = _primary_triage_files(category, files)
    rows: list[dict[str, Any]] = []
    rows.append(_run_triage_command_planned(["find", ".", "-maxdepth", "4", "-type", "f"], context=context, cwd=cwd, timeout=5))
    if primary:
        rows.append(_run_triage_command_planned(["file", *[str(path) for path in primary[:12]]], context=context, cwd=cwd, timeout=8))

    if category == "web":
        rows.extend(
            [
                _run_triage_command_planned(["rg", "-n", r"route|app\.|router\.|urlpatterns|FastAPI|express|fetch|axios|XMLHttpRequest|<form", "."], context=context, cwd=cwd, timeout=8),
                _run_triage_command_planned(["rg", "-n", r"auth|login|session|jwt|cookie|upload|render|template|sql|sqlite|eval|exec|ssrf|open\(|path", "."], context=context, cwd=cwd, timeout=8),
            ]
        )
    elif category == "pwn":
        target = primary[0] if primary else None
        if target:
            rows.extend(
                [
                    _run_triage_command_planned(["checksec", f"--file={target}"], context=context, cwd=cwd, timeout=8),
                    _run_triage_command_planned(["readelf", "-h", str(target)], context=context, cwd=cwd, timeout=8),
                    _run_triage_command_planned(["readelf", "-s", str(target)], context=context, cwd=cwd, timeout=8),
                    _run_triage_command_planned(["strings", "-a", "-n", "4", str(target)], context=context, cwd=cwd, timeout=8),
                ]
            )
    elif category == "rev":
        target = primary[0] if primary else None
        if target:
            rows.extend(
                [
                    _run_triage_command_planned(["readelf", "-h", str(target)], context=context, cwd=cwd, timeout=8),
                    _run_triage_command_planned(["objdump", "-f", str(target)], context=context, cwd=cwd, timeout=8),
                    _run_triage_command_planned(["strings", "-a", "-n", "4", str(target)], context=context, cwd=cwd, timeout=8),
                ]
            )
        rows.append(_run_triage_command_planned(["rg", "-n", r"check|verify|flag|key|decrypt|xor|base64|password|serial", "."], context=context, cwd=cwd, timeout=8))
    elif category == "crypto":
        rows.append(_run_triage_command_planned(["rg", "-n", r"RSA|ECC|ECDSA|AES|CBC|CTR|GCM|modulus|cipher|decrypt|encrypt|random|seed|nonce|curve|sage|Crypto", "."], context=context, cwd=cwd, timeout=8))
    elif category == "forensics/misc":
        target = primary[0] if primary else None
        if target:
            rows.extend(
                [
                    _run_triage_command_planned(["exiftool", str(target)], context=context, cwd=cwd, timeout=8),
                    _run_triage_command_planned(["binwalk", str(target)], context=context, cwd=cwd, timeout=12),
                    _run_triage_command_planned(["xxd", "-l", "256", str(target)], context=context, cwd=cwd, timeout=8),
                    _run_triage_command_planned(["strings", "-a", "-n", "5", str(target)], context=context, cwd=cwd, timeout=8),
                ]
            )
    elif category == "osint":
        rows.append(_run_triage_command_planned(["rg", "-n", r"https?://|domain|username|handle|coord|latitude|longitude|image|photo|email|@", "."], context=context, cwd=cwd, timeout=8))
    elif category == "ai/ml":
        rows.extend(
            [
                _run_triage_command_planned(["find", ".", "-maxdepth", "5", "-type", "f", "(", "-name", "*.pt", "-o", "-name", "*.pth", "-o", "-name", "*.onnx", "-o", "-name", "*.pkl", "-o", "-name", "*.safetensors", "-o", "-name", "*.json", ")"], context=context, cwd=cwd, timeout=8),
                _run_triage_command_planned(["rg", "-n", r"torch|tensorflow|sklearn|transformers|onnx|pickle|prompt|system|model|dataset|label", "."], context=context, cwd=cwd, timeout=8),
            ]
        )
    return rows


def _primary_triage_files(category: str, files: list[dict[str, Any]]) -> list[Path]:
    preferred_kinds = {
        "pwn": {"elf", "binary"},
        "rev": {"elf", "pe", "mach-o", "wasm", "apk", "jar", "binary"},
        "forensics/misc": {"image", "pdf", "pcap", "zip", "binary", "sqlite", "text"},
        "ai/ml": {"model", "source", "text"},
    }.get(category, {"source", "text", "binary", "elf", "pe", "wasm", "zip"})
    result: list[Path] = []
    for row in files:
        if str(row.get("role") or "").startswith("memo:"):
            continue
        if str(row.get("kind") or "") not in preferred_kinds:
            continue
        path = _triage_file_path(row)
        if path.exists() and path.is_file():
            result.append(path)
        if len(result) >= 16:
            break
    return result


def _run_triage_command(command: list[str], *, cwd: Path, timeout: int) -> dict[str, Any]:
    display = " ".join(shlex.quote(part) for part in command)
    if not command or not shutil.which(command[0]):
        return {"command": display, "status": "skipped", "reason": "tool_missing", "returncode": None, "stdout": "", "stderr": ""}
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        status = "ok" if completed.returncode == 0 else "nonzero"
        return {
            "command": display,
            "status": status,
            "returncode": completed.returncode,
            "stdout": _target_summary(completed.stdout, 6000),
            "stderr": _target_summary(completed.stderr, 3000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": display,
            "status": "timeout",
            "returncode": None,
            "stdout": _target_summary(str(exc.stdout or ""), 2000),
            "stderr": _target_summary(str(exc.stderr or ""), 2000),
        }
    except OSError as exc:
        return {"command": display, "status": "error", "reason": redact_text(str(exc)), "returncode": None, "stdout": "", "stderr": ""}


def _run_triage_command_planned(command: list[str], *, context: Mapping[str, Any], cwd: Path, timeout: int) -> dict[str, Any]:
    report = context.get("toolchain_report") if isinstance(context.get("toolchain_report"), Mapping) else {}
    planned, fallback = choose_command_or_fallback(command, report)
    if planned is None:
        row = _run_triage_command(command, cwd=cwd, timeout=timeout)
        if fallback:
            row["missing_tool"] = fallback.get("tool")
            row["fallbacks"] = fallback.get("fallbacks") or []
        return row
    row = _run_triage_command(planned, cwd=cwd, timeout=timeout)
    if fallback:
        row["fallback_for"] = fallback.get("tool")
        row["fallback_id"] = fallback.get("fallback_id")
        row["fallback_reason"] = fallback.get("reason")
    return row


def _selected_fallback_rows(command_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in command_rows:
        tool = str(row.get("fallback_for") or "")
        fallback_id = str(row.get("fallback_id") or "")
        if not tool or not fallback_id:
            continue
        key = (tool, fallback_id)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"tool": tool, "fallback_id": fallback_id, "reason": str(row.get("fallback_reason") or "tool_missing")})
    return rows


def _skipped_tool_rows(command_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in command_rows:
        if row.get("status") != "skipped" and not row.get("missing_tool"):
            continue
        rows.append(
            {
                "tool": str(row.get("missing_tool") or str(row.get("command") or "").split(" ", 1)[0]),
                "reason": str(row.get("reason") or "tool_missing"),
                "fallback_count": len(row.get("fallbacks") or []),
            }
        )
    return rows[:20]


def _category_triage_findings(
    category: str,
    item: Mapping[str, Any],
    context: Mapping[str, Any],
    files: list[dict[str, Any]],
    command_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = [
        _finding("category", "Category guess", f"{category} from declared/manifest/local evidence"),
        _finding("files", "Local file inventory", f"{len(files)} local context/artifact files indexed"),
    ]
    top = [str(row.get("display_path") or row.get("path") or "") for row in files if not str(row.get("role") or "").startswith("memo:")][:6]
    if top:
        findings.append(_finding("files", "Top local files", "; ".join(top)))
    if context.get("service_metadata"):
        service = _service_public_metadata(context["service_metadata"])
        endpoint = service.get("endpoint") if isinstance(service.get("endpoint"), Mapping) else {}
        findings.append(
            _finding(
                "remote_service",
                "Remote service metadata",
                f"{endpoint.get('host')}:{endpoint.get('port')} transport={endpoint.get('transport')} command={service.get('recommended_connect_command')}",
            )
        )
    elif context.get("remote_endpoints"):
        findings.append(_finding("remote", "Remote endpoints in local metadata", "; ".join(str(value) for value in context["remote_endpoints"][:6])))
    if context.get("web_metadata"):
        web = _web_public_metadata(context["web_metadata"])
        findings.append(
            _finding(
                "web_metadata",
                "Web metadata",
                f"base_url={web.get('base_url')} auth_source={(web.get('auth_source') or {}).get('type') or 'none'}",
            )
        )
    if context.get("web_probe_result"):
        probe = context["web_probe_result"] if isinstance(context["web_probe_result"], Mapping) else {}
        findings.append(
            _finding(
                "web_probe",
                "Web probe",
                f"status={probe.get('status')} http={probe.get('http_status')} title={probe.get('title')} forms={len(probe.get('forms') or [])} endpoints={len(probe.get('endpoint_candidates') or [])}",
            )
        )

    if category == "web":
        findings.extend(_web_triage_findings(files))
    elif category == "pwn":
        findings.extend(_pwn_triage_findings(files, context, command_rows))
    elif category == "rev":
        findings.extend(_rev_triage_findings(files, command_rows))
    elif category == "crypto":
        findings.extend(_crypto_triage_findings(files))
    elif category == "forensics/misc":
        findings.extend(_forensics_triage_findings(files, command_rows))
    elif category == "osint":
        findings.extend(_osint_triage_findings(files))
    elif category == "ai/ml":
        findings.extend(_aiml_triage_findings(files))
    if len(findings) == 2:
        findings.append(_finding("triage", "No category-specific signal found", "Inspect brief and top files manually, then update next_steps."))
    return findings[:80]


def _finding(kind: str, title: str, detail: str, *, path: str = "", evidence: str = "") -> dict[str, Any]:
    row = {"type": kind, "title": title, "detail": _target_summary(detail, 800)}
    if path:
        row["path"] = path
    if evidence:
        row["evidence"] = _target_summary(evidence, 1200)
    return row


def _web_triage_findings(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    source = [row for row in files if str(row.get("suffix") or "") in {".py", ".js", ".ts", ".php", ".rb", ".go", ".java", ".html", ".jsx", ".tsx"}]
    if source:
        findings.append(_finding("web_source", "Web/source files", "; ".join(str(row.get("path") or "") for row in source[:12])))
    route_matches = _scan_text_matches(files, [("route", r"@.*route|app\.(?:get|post|put|delete|route)|router\.(?:get|post|put|delete)|urlpatterns|FastAPI|express")], max_matches=20)
    form_matches = _scan_text_matches(files, [("form", r"<form\b|method=[\"']?(?:post|get)|action=[\"']?")], max_matches=20)
    sink_matches = _scan_text_matches(files, [("sink", r"auth|login|session|jwt|cookie|upload|render_template|template|sql|sqlite|eval\(|exec\(|requests\.(?:get|post)|open\(|send_file|path")], max_matches=30)
    api_matches = _scan_text_matches(files, [("api", r"/api/|fetch\(|axios\.|XMLHttpRequest|graphql|REST")], max_matches=20)
    for label, matches in (("Routes", route_matches), ("Forms", form_matches), ("API/client endpoints", api_matches), ("Likely bug sinks", sink_matches)):
        if matches:
            findings.append(_finding("web", label, _match_summary(matches), path=str(matches[0].get("path") or ""), evidence=str(matches[0].get("line_text") or "")))
    js_bundles = [row for row in files if str(row.get("suffix") or "") == ".js" and re.search(r"bundle|chunk|main|static|assets", str(row.get("path") or ""), re.IGNORECASE)]
    if js_bundles:
        findings.append(_finding("web_js", "JS bundles", "; ".join(str(row.get("path") or "") for row in js_bundles[:10])))
    return findings


def _pwn_triage_findings(files: list[dict[str, Any]], context: Mapping[str, Any], command_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    binaries = [row for row in files if str(row.get("kind") or "") in {"elf", "binary"}]
    if binaries:
        findings.append(_finding("pwn_binary", "Primary binary candidates", "; ".join(str(row.get("display_path") or "") for row in binaries[:8])))
    docker_hints = [row for row in files if Path(str(row.get("path") or "")).name.lower() in {"dockerfile", "docker-compose.yml", "docker-compose.yaml"}]
    libc_hints = [row for row in files if re.search(r"libc|ld-linux|ld-musl", str(row.get("path") or ""), re.IGNORECASE)]
    if docker_hints or libc_hints:
        findings.append(_finding("pwn_env", "Docker/libc hints", "; ".join(str(row.get("path") or "") for row in [*docker_hints, *libc_hints][:12])))
    checksec = _command_output(command_rows, "checksec")
    if checksec:
        findings.append(_finding("pwn_checksec", "checksec output", checksec[:900]))
    readelf = _command_output(command_rows, "readelf -h")
    if readelf:
        findings.append(_finding("pwn_readelf", "ELF header", readelf[:900]))
    if context.get("remote_endpoints"):
        findings.append(_finding("pwn_remote", "Remote service hint", "; ".join(str(value) for value in context["remote_endpoints"][:4])))
    return findings


def _rev_triage_findings(files: list[dict[str, Any]], command_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    artifacts = [row for row in files if str(row.get("kind") or "") in {"elf", "pe", "mach-o", "wasm", "apk", "jar", "binary"}]
    if artifacts:
        formats = _dedupe_strings(str(row.get("kind") or "") for row in artifacts)
        findings.append(_finding("rev_artifact", "Reversing artifact format", f"formats={', '.join(formats)} files={'; '.join(str(row.get('display_path') or '') for row in artifacts[:8])}"))
    string_hits = _scan_text_matches(files, [("rev_marker", r"check|verify|flag|key|decrypt|xor|base64|password|serial")], max_matches=30)
    strings_output = _command_output(command_rows, "strings")
    if string_hits:
        findings.append(_finding("rev_strings", "Interesting source/text markers", _match_summary(string_hits), path=str(string_hits[0].get("path") or ""), evidence=str(string_hits[0].get("line_text") or "")))
    elif strings_output:
        findings.append(_finding("rev_strings", "strings output sample", strings_output[:1200]))
    readelf = _command_output(command_rows, "readelf -h")
    if readelf:
        findings.append(_finding("rev_readelf", "Binary header", readelf[:900]))
    return findings


def _crypto_triage_findings(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    param_matches = _scan_text_matches(
        files,
        [
            ("rsa_param", r"\b(?:n|e|c|p|q|phi|modulus|ciphertext|ct)\s*[:=]\s*(?:0x[0-9a-fA-F]+|\d{6,}|[A-Za-z0-9+/=]{16,})"),
            ("crypto_primitive", r"RSA|ECC|ECDSA|AES|CBC|CTR|GCM|nonce|seed|random|curve|sage|Crypto|openssl"),
        ],
        max_matches=50,
    )
    if param_matches:
        findings.append(_finding("crypto_params", "Crypto parameters/primitives", _match_summary(param_matches), path=str(param_matches[0].get("path") or ""), evidence=str(param_matches[0].get("line_text") or "")))
    data_files = [row for row in files if str(row.get("suffix") or "") in {".txt", ".json", ".sage", ".py", ".pem", ".pub"}]
    if data_files:
        findings.append(_finding("crypto_files", "Likely crypto data/source files", "; ".join(str(row.get("display_path") or "") for row in data_files[:10])))
    return findings


def _forensics_triage_findings(files: list[dict[str, Any]], command_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    formats = _dedupe_strings(str(row.get("kind") or "") for row in files if not str(row.get("role") or "").startswith("memo:"))
    if formats:
        findings.append(_finding("forensics_format", "File format spread", ", ".join(formats[:12])))
    for tool in ("exiftool", "binwalk", "xxd", "strings"):
        output = _command_output(command_rows, tool)
        if output:
            findings.append(_finding("forensics_tool", f"{tool} output", output[:1000]))
    suspicious = [row for row in files if str(row.get("kind") or "") in {"zip", "pcap", "sqlite", "image", "pdf"}]
    if suspicious:
        findings.append(_finding("forensics_artifacts", "Carving/metadata candidates", "; ".join(str(row.get("display_path") or "") for row in suspicious[:10])))
    return findings


def _osint_triage_findings(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches = _scan_text_matches(
        files,
        [("local_identifier", r"https?://[^\s)>'\"]+|@[A-Za-z0-9_.-]{3,}|\b(?:lat|lon|latitude|longitude|coord)\b|[A-Za-z0-9.-]+\.[A-Za-z]{2,}")],
        max_matches=40,
    )
    if not matches:
        return []
    return [_finding("osint_local", "Local-only OSINT identifiers", _match_summary(matches), path=str(matches[0].get("path") or ""), evidence=str(matches[0].get("line_text") or ""))]


def _aiml_triage_findings(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    models = [row for row in files if str(row.get("kind") or "") == "model"]
    if models:
        findings.append(_finding("aiml_model", "Model artifacts", "; ".join(str(row.get("display_path") or "") for row in models[:12])))
    matches = _scan_text_matches(files, [("aiml_code", r"torch|tensorflow|sklearn|transformers|onnx|pickle|prompt|system|dataset|label|logits|softmax")], max_matches=40)
    if matches:
        findings.append(_finding("aiml_code", "ML/inference code hints", _match_summary(matches), path=str(matches[0].get("path") or ""), evidence=str(matches[0].get("line_text") or "")))
    return findings


def _scan_text_matches(files: list[dict[str, Any]], patterns: list[tuple[str, str]], *, max_matches: int) -> list[dict[str, Any]]:
    compiled = [(label, re.compile(pattern, re.IGNORECASE)) for label, pattern in patterns]
    matches: list[dict[str, Any]] = []
    for row in files:
        path = _triage_file_path(row)
        if str(row.get("role") or "").startswith("memo:"):
            continue
        text = _read_small_text_file(path)
        if not text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            for label, regex in compiled:
                if not regex.search(stripped):
                    continue
                matches.append(
                    {
                        "pattern": label,
                        "path": str(row.get("display_path") or row.get("path") or ""),
                        "line": line_no,
                        "line_text": _target_summary(stripped, 300),
                    }
                )
                break
            if len(matches) >= max_matches:
                return matches
    return matches


def _read_small_text_file(path: Path) -> str:
    try:
        if path.stat().st_size > 1024 * 1024:
            return ""
        data = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in data[:4096]:
        return ""
    return _target_safe_text(data.decode("utf-8", errors="replace"))


def _match_summary(matches: list[dict[str, Any]]) -> str:
    parts = []
    for match in matches[:8]:
        parts.append(f"{match.get('path')}:{match.get('line')} {match.get('pattern')} {match.get('line_text')}")
    suffix = f"; +{len(matches) - 8} more" if len(matches) > 8 else ""
    return "; ".join(parts) + suffix


def _command_output(command_rows: list[dict[str, Any]], marker: str) -> str:
    for row in command_rows:
        if marker in str(row.get("command") or "") and row.get("stdout"):
            return str(row.get("stdout") or "")
    return ""


def _triage_next_steps(category: str, findings: list[dict[str, Any]], context: Mapping[str, Any]) -> list[str]:
    steps = {
        "web": [
            "Map routes, auth/session state, forms, and API inputs from the files called out in triage.",
            "Run the app locally if possible, then test only the highest-signal sinks first.",
            "Fill solve_web.py with a reproducible requests.Session proof path.",
        ],
        "pwn": [
            "Confirm protections and architecture, then reproduce a local crash with the primary binary.",
            "Derive offset/primitive and identify matching libc/ld or Docker runtime before remote attempts.",
            "Fill exploit.py with local/remote switches and save verification output locally.",
        ],
        "rev": [
            "Open the primary artifact in a disassembler or objdump and locate the validation routine.",
            "Extract constants/transform logic into solve_rev.py and verify candidate generation locally.",
            "Use z3 only after the constraints are explicit enough to model.",
        ],
        "crypto": [
            "Normalize all parameters/ciphertexts into solve_crypto.py.",
            "Identify the primitive and weakness before brute force; bound any search space explicitly.",
            "Verify decrypt/forge output locally before submission.",
        ],
        "forensics/misc": [
            "Run focused metadata/carving commands on the primary artifact and save extracted files locally.",
            "Try format-specific tools only after file/strings/binwalk/exif evidence points there.",
            "Record decoded candidate derivation in evidence.md before submit.",
        ],
        "osint": [
            "Work only from local identifiers and official sources; do not search current-event writeups.",
            "Record each query path and why it follows from local evidence.",
            "Stop if the remaining path requires guesswork or account-gated external browsing.",
        ],
        "ai/ml": [
            "Identify model format, inference entrypoint, and dataset/label mapping.",
            "Build a minimal local inference or inspection harness before adversarial attempts.",
            "Avoid long training unless a small bounded experiment is justified by local evidence.",
        ],
    }.get(category, [])
    if not findings or any("No category-specific signal" in str(row.get("title") or "") for row in findings):
        steps.insert(0, "Inspect brief.md and the top local files manually; add any concrete signal to evidence.md.")
    if context.get("service_metadata") or context.get("remote_endpoints"):
        contest_id = str(context.get("contest_id") or "<contest>")
        challenge_id = str((context.get("service_metadata") or {}).get("challenge_id") or "<challenge>")
        steps.append(f"Probe the remote service with ctfctl interactive service-probe --contest-id {contest_id} --challenge-id {challenge_id} --json before manual payload work.")
    if category == "web" and context.get("web_metadata"):
        contest_id = str(context.get("contest_id") or "<contest>")
        challenge_id = str((context.get("web_metadata") or {}).get("challenge_id") or "<challenge>")
        steps.append(f"Run ctfctl interactive web-probe --contest-id {contest_id} --challenge-id {challenge_id} --json, then use web-attempt for reproducible requests.Session experiments.")
    elif not context.get("remote_endpoints") and category in {"web", "pwn"}:
        steps.append("Find or record service connection info before remote testing.")
    toolchain = context.get("toolchain_summary") if isinstance(context.get("toolchain_summary"), Mapping) else {}
    for row in list(toolchain.get("recommended_fallbacks") or [])[:3]:
        if not isinstance(row, Mapping):
            continue
        suggestions = row.get("suggestions") if isinstance(row.get("suggestions"), list) else []
        ids = [str(item.get("id") or "") for item in suggestions if isinstance(item, Mapping) and item.get("id")]
        if ids:
            steps.append(f"Tool missing: {row.get('tool')}; prefer fallback {ids[0]} before installing anything.")
        else:
            steps.append(f"Tool missing: {row.get('tool')}; record blocker and use Docker/alternate target before installing anything.")
    return _dedupe_strings(steps)[:5]


def _render_triage_summary(
    contest_id: str,
    item: Mapping[str, Any],
    context: Mapping[str, Any],
    category: str,
    files: list[dict[str, Any]],
    command_rows: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    next_steps: list[str],
    *,
    target_pack_path: str,
    started_at: str,
) -> str:
    lines = [
        f"# Auto Triage: {_md(str(item.get('canonical_name') or item.get('name') or item.get('challenge_id') or 'challenge'))}",
        "",
        f"- generated_at: {utc_now()}",
        f"- started_at: {_md(started_at)}",
        f"- contest_id: {_md(contest_id)}",
        f"- challenge_id: {_md(str(item.get('challenge_id') or ''))}",
        f"- category: {_md(category)}",
        f"- challenge_path: {_md(_display(Path(context['challenge_dir'])))}",
        f"- target_pack_path: {_md(target_pack_path or 'missing')}",
        f"- brief_path: {_md(_display(context['brief_path']) if context.get('brief_path') else 'missing')}",
        "",
        "## Toolchain",
        f"- available_tools: {_md(', '.join((context.get('toolchain_summary') or {}).get('available_tools') or []) or 'none')}",
        f"- missing_critical_tools: {_md(', '.join((context.get('toolchain_summary') or {}).get('missing_critical_tools') or []) or 'none')}",
        f"- recommended_fallbacks: {_md(_fallbacks_inline((context.get('toolchain_summary') or {}).get('recommended_fallbacks') or []))}",
        "",
        "## Top Files",
    ]
    artifacts = [row for row in files if not str(row.get("role") or "").startswith("memo:")]
    if artifacts:
        for row in artifacts[:12]:
            lines.append(f"- {_md(str(row.get('display_path') or row.get('path') or ''))} [{_md(str(row.get('kind') or 'unknown'))}] size={int(row.get('size') or 0)}")
    else:
        lines.append("- none detected")
    lines.extend(["", "## Commands"])
    for row in command_rows[:20]:
        status = str(row.get("status") or "")
        reason = f" reason={_md(str(row.get('reason') or ''))}" if row.get("reason") else ""
        fallback = f" fallback_for={_md(str(row.get('fallback_for')))} fallback_id={_md(str(row.get('fallback_id')))}" if row.get("fallback_for") else ""
        missing = f" missing_tool={_md(str(row.get('missing_tool')))}" if row.get("missing_tool") else ""
        lines.append(f"- `{row.get('command')}` status={_md(status)}{reason}{fallback}{missing}")
    lines.extend(["", "## Findings"])
    for row in findings[:30]:
        detail = str(row.get("detail") or "")
        path = f" ({_md(str(row.get('path') or ''))})" if row.get("path") else ""
        lines.append(f"- {_md(str(row.get('title') or row.get('type') or 'finding'))}{path}: {_md(detail)}")
    lines.extend(["", "## Next Steps"])
    lines.extend(f"- {_md(step)}" for step in next_steps)
    return "\n".join(lines) + "\n"


def _append_triage_memos(
    challenge_dir: Path,
    *,
    category: str,
    summary_path: Path,
    files_path: Path,
    commands_path: Path,
    findings_path: Path,
    findings: list[dict[str, Any]],
    next_steps: list[str],
) -> None:
    timestamp = utc_now()
    _ensure_challenge_memos(challenge_dir)
    _append_text(challenge_dir / "memory.md", f"\n- auto_triage: category={category} findings={len(findings)} summary={_display(summary_path)} ({timestamp})\n")
    _append_text(
        challenge_dir / "evidence.md",
        "\n".join(
            [
                f"\n## Auto Triage {timestamp}",
                f"- category: {category}",
                f"- summary: {_display(summary_path)}",
                f"- files: {_display(files_path)}",
                f"- commands: {_display(commands_path)}",
                f"- findings: {_display(findings_path)}",
                *[f"- {row.get('title')}: {row.get('detail')}" for row in findings[:6]],
                "",
            ]
        ),
    )
    _append_text(challenge_dir / "attempts.md", f"\n- auto_triage: ran local category triage for {category}; command log at {_display(commands_path)} ({timestamp})\n")
    _append_text(challenge_dir / "next_steps.md", "\n".join(["", f"## Auto Triage Next Steps {timestamp}", *[f"- {step}" for step in next_steps], ""]))
    _append_text(challenge_dir / "operator_notes.md", f"\n- auto_triage_complete: {_display(summary_path)} ({timestamp}); local artifacts only, no external CTF access.\n")


def _append_starter_memos(challenge_dir: Path, *, starter_path: Path, category: str, created: bool) -> None:
    timestamp = utc_now()
    verb = "created" if created else "preserved"
    _ensure_challenge_memos(challenge_dir)
    _append_text(challenge_dir / "memory.md", f"\n- starter_{verb}: {category} starter at {_display(starter_path)} ({timestamp})\n")
    _append_text(challenge_dir / "next_steps.md", f"\n- Open {_display(starter_path)} and replace TODO hooks with the verified solve path.\n")
    _append_text(challenge_dir / "operator_notes.md", f"\n- starter_{verb}: {_display(starter_path)} ({category}, {timestamp})\n")


def _append_missing_tool_notes(challenge_dir: Path, missing_tool: Mapping[str, Any], attempt_path: Path) -> None:
    timestamp = utc_now()
    tool = str(missing_tool.get("tool") or "unknown")
    fallback = missing_tool.get("fallback") if isinstance(missing_tool.get("fallback"), Mapping) else {}
    suggestions = fallback.get("suggestions") if isinstance(fallback.get("suggestions"), list) else []
    suggestion_ids = [str(item.get("id") or "") for item in suggestions if isinstance(item, Mapping) and item.get("id")]
    hint = f"; fallback={suggestion_ids[0]}" if suggestion_ids else "; fallback=record blocker or switch target"
    install_hints = fallback.get("install_hints") if isinstance(fallback.get("install_hints"), Mapping) else {}
    planned = "; planned_install_hint=" + next(iter(install_hints.values())) if install_hints else ""
    _append_text(
        challenge_dir / "attempts.md",
        f"\n- missing_tool: {tool} blocked attempt {_display(attempt_path)} at {timestamp}{hint}{planned}\n",
    )
    _append_text(
        challenge_dir / "next_steps.md",
        f"\n- Missing tool `{tool}` blocked the latest attempt. Use fallback {', '.join(suggestion_ids[:3]) or 'from ctfctl interactive fallback'} or switch targets; do not auto-install during solve-loop.\n",
    )


def _missing_tool_metric_payload(missing_tool: Mapping[str, Any]) -> dict[str, Any]:
    fallback = missing_tool.get("fallback") if isinstance(missing_tool.get("fallback"), Mapping) else {}
    suggestions = fallback.get("suggestions") if isinstance(fallback.get("suggestions"), list) else []
    return {
        "tool": str(missing_tool.get("tool") or ""),
        "fallback_ids": [str(item.get("id") or "") for item in suggestions if isinstance(item, Mapping) and item.get("id")][:5],
        "no_auto_install": True,
    }


def _resolve_attempt_invocation(
    root: Path,
    board: Mapping[str, Any],
    item: Mapping[str, Any],
    challenge_id: str,
    challenge_dir: Path,
    *,
    command: str | None,
    script: str | Path | None,
) -> dict[str, Any]:
    if command and script:
        return {"status": "blocked", "reason": "command_and_script_are_mutually_exclusive"}
    if command:
        return {"status": "ok", "argv": str(command), "shell": True, "command_display": str(command), "script_path": None}
    script_path = _resolve_attempt_script(root, board, item, challenge_id, challenge_dir, script)
    if script_path is None:
        return {"status": "blocked", "reason": "command_or_script_required"}
    if not script_path.exists():
        return {"status": "blocked", "reason": "script_not_found"}
    argv = _script_argv(script_path)
    return {
        "status": "ok",
        "argv": argv,
        "shell": False,
        "command_display": " ".join(shlex.quote(part) for part in argv),
        "script_path": script_path,
    }


def _resolve_attempt_script(
    root: Path,
    board: Mapping[str, Any],
    item: Mapping[str, Any],
    challenge_id: str,
    challenge_dir: Path,
    script: str | Path | None,
) -> Path | None:
    if script:
        path = Path(script).expanduser()
        return path if path.is_absolute() else challenge_dir / path
    metadata_sources = [
        _operator_config(root).get("challenge_solver_metadata", {}),
        board.get("solver_metadata", {}),
    ]
    keys = _challenge_keys(item) | {_normalize(challenge_id)}
    for source in metadata_sources:
        if not isinstance(source, Mapping):
            continue
        for key, metadata in source.items():
            if _normalize(str(key)) not in keys or not isinstance(metadata, Mapping):
                continue
            raw = str(metadata.get("starter_path") or "")
            if not raw:
                continue
            path = _undisplay_path(raw)
            if path.exists():
                return path
    for name in ("solve.py", "solver.py", "exploit.py", "solve_web.py", "solve_rev.py", "solve_crypto.py", "solve_misc.py", "solve_ai_ml.py"):
        path = challenge_dir / name
        if path.exists():
            return path
    return None


def _script_argv(path: Path) -> list[str]:
    if path.suffix == ".py":
        return [sys.executable, str(path)]
    if path.suffix in {".sh", ".bash"}:
        return ["bash", str(path)]
    return [str(path)]


def _process_output_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _timestamp_filename(value: str) -> str:
    safe = re.sub(r"[^0-9A-Za-z_.-]+", "-", value.replace("+00:00", "Z"))
    return safe.strip("-") or hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]


def _detect_attempt_candidates(
    contest_id: str,
    challenge_id: str,
    *,
    stdout: str,
    stderr: str,
    command: str,
    attempt_path: Path,
    timestamp: str,
    policy: Mapping[str, Any],
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for stream, text in (("stdout", stdout), ("stderr", stderr)):
        for candidate in detect_flag_candidates(text, flag_regex=str(policy.get("flag_regex") or "") or None):
            if candidate in seen:
                continue
            seen.add(candidate)
            context = {
                "source": "solver_output",
                "evidence_source": _display(attempt_path),
                "derivation": "detected by interactive run-attempt",
                "local_verified": True,
            }
            classification = classify_flag_confidence(candidate, context=context, policy=policy)
            rows.append(
                {
                    "schema": "interactive_candidate_v1",
                    "contest_id": contest_id,
                    "challenge_id": challenge_id,
                    "value": candidate,
                    "flag_hash": str(classification.get("flag_hash") or hash_flag(candidate)),
                    "length": len(candidate),
                    "source": f"attempt_{stream}",
                    "evidence_source": _display(attempt_path),
                    "evidence_stream": stream,
                    "command": command,
                    "timestamp": timestamp,
                    "status": "detected",
                    "confidence": classification.get("confidence"),
                    "fake_likely": bool(classification.get("fake_likely")),
                    "matches_flag_regex": bool(classification.get("matches_flag_regex")),
                }
            )
    return rows


def _append_detected_candidates(challenge_dir: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    path = _candidate_store_path(challenge_dir)
    existing_hashes = {str(row.get("flag_hash") or "") for row in _read_jsonl(path)}
    stored: list[dict[str, Any]] = []
    for row in rows:
        digest = str(row.get("flag_hash") or "")
        if digest and digest in existing_hashes:
            continue
        _append_jsonl_raw(path, row)
        existing_hashes.add(digest)
        stored.append(row)
    return stored


def _candidate_store_path(challenge_dir: Path) -> Path:
    return challenge_dir / "candidates.jsonl"


def _coalesced_candidates(challenge_dir: Path) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in _read_jsonl(_candidate_store_path(challenge_dir)):
        digest = str(row.get("flag_hash") or "")
        if not digest:
            value = str(row.get("value") or "")
            digest = hash_flag(value) if value else hashlib.sha1(json.dumps(row, sort_keys=True).encode("utf-8")).hexdigest()
        if digest not in latest:
            order.append(digest)
        latest[digest] = row
    return [latest[digest] for digest in order]


def _candidate_local_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "value": row.get("value", ""),
        "flag_hash": row.get("flag_hash", ""),
        "length": row.get("length", len(str(row.get("value") or ""))),
        "source": row.get("source", ""),
        "evidence_source": row.get("evidence_source", ""),
        "command": row.get("command", ""),
        "timestamp": row.get("timestamp", ""),
        "status": row.get("status", ""),
        "confidence": row.get("confidence", ""),
        "fake_likely": bool(row.get("fake_likely")),
        "duplicate": bool(row.get("duplicate")),
    }


def _candidate_public_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "challenge_id": str(row.get("challenge_id") or ""),
        "flag_hash": str(row.get("flag_hash") or ""),
        "length": _int_value(row.get("length")) or len(str(row.get("value") or "")),
        "source": _safe_public_note(str(row.get("source") or ""), limit=80),
        "status": _safe_public_note(str(row.get("status") or ""), limit=80),
        "confidence": _safe_public_note(str(row.get("confidence") or ""), limit=40),
        "timestamp": str(row.get("timestamp") or ""),
    }


def _select_candidate_for_verification(
    challenge_dir: Path,
    *,
    candidate: str | None,
    candidate_file: str | Path | None,
) -> dict[str, Any]:
    if candidate is not None:
        value = str(candidate).strip()
        digest = hash_flag(value) if value else ""
        for row in _coalesced_candidates(challenge_dir):
            if str(row.get("flag_hash") or "") == digest:
                return dict(row)
        return {"value": value, "source": "manual_candidate"}
    if candidate_file:
        path = Path(candidate_file).expanduser()
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return {}
        detected = detect_flag_candidates(text)
        return {
            "value": detected[0] if detected else text,
            "source": "candidate_file",
            "evidence_source": _display(path),
            "derivation": "read from candidate file",
            "local_verified": True,
        }
    rows = _coalesced_candidates(challenge_dir)
    if not rows:
        return {}
    return dict(rows[-1])


def _verification_context(selected: Mapping[str, Any]) -> dict[str, Any]:
    source = str(selected.get("source") or "manual_candidate")
    if source.startswith("attempt_"):
        context_source = "solver_output"
    elif source == "candidate_file":
        context_source = "known_flag_source"
    else:
        context_source = source
    return {
        "source": context_source,
        "evidence_source": selected.get("evidence_source") or selected.get("path") or "",
        "derivation": selected.get("derivation") or ("detected by interactive run-attempt" if source.startswith("attempt_") else ""),
        "local_verified": bool(selected.get("local_verified") or source.startswith("attempt_") or source == "candidate_file"),
        "confidence": selected.get("confidence") or "",
    }


def _verification_status(
    confidence: str,
    decision: Mapping[str, Any],
    classification: Mapping[str, Any],
    duplicate: bool,
) -> str:
    if duplicate:
        return "duplicate"
    if bool(classification.get("fake_likely")):
        return "fake_like"
    if not bool(classification.get("matches_flag_regex")):
        return "invalid_format"
    if decision.get("allowed"):
        return f"verified_{confidence or 'unknown'}"
    return f"blocked_{decision.get('reason') or confidence or 'unknown'}"


def _append_attempt_markdown(challenge_dir: Path, attempt: Mapping[str, Any], attempt_path: Path, candidates: list[dict[str, Any]]) -> None:
    safe_command = redact_text(str(attempt.get("command") or "")).replace("`", "")
    lines = [
        f"\n## Attempt {attempt.get('completed_at') or utc_now()}",
        "",
        f"- command: `{safe_command}`",
        f"- agent: {redact_text(str(attempt.get('agent') or ''))}",
        f"- returncode: {attempt.get('returncode')}",
        f"- timed_out: {bool(attempt.get('timed_out'))}",
        f"- runtime_sec: {attempt.get('runtime_sec')}",
        f"- stdout_len: {attempt.get('stdout_len')}",
        f"- stderr_len: {attempt.get('stderr_len')}",
        f"- record: {_display(attempt_path)}",
    ]
    if candidates:
        lines.append("- candidates:")
        for row in candidates:
            lines.append(f"  - hash={row.get('flag_hash')} length={row.get('length')} source={row.get('source')} confidence={row.get('confidence')}")
    else:
        lines.append("- candidates: none")
    _append_text(challenge_dir / "attempts.md", "\n".join(lines) + "\n")


def _append_attempt_evidence(challenge_dir: Path, attempt: Mapping[str, Any], attempt_path: Path, candidates: list[dict[str, Any]]) -> None:
    if candidates:
        lines = [f"\n## Candidate Detection {attempt.get('completed_at') or utc_now()}", "", f"- attempt: {_display(attempt_path)}"]
        for row in candidates:
            lines.append(f"- candidate_sha256: {row.get('flag_hash')} length={row.get('length')} source={row.get('source')} confidence={row.get('confidence')}")
        _append_text(challenge_dir / "evidence.md", "\n".join(lines) + "\n")
    else:
        _append_text(challenge_dir / "evidence.md", f"\n- attempt {attempt.get('completed_at') or utc_now()}: no flag-like candidate detected ({_display(attempt_path)})\n")


def _append_candidate_verification_evidence(challenge_dir: Path, record: Mapping[str, Any]) -> None:
    _append_text(
        challenge_dir / "evidence.md",
        (
            f"\n## Candidate Verification {record.get('timestamp') or utc_now()}\n\n"
            f"- candidate_sha256: {record.get('flag_hash')}\n"
            f"- length: {record.get('length')}\n"
            f"- confidence: {record.get('confidence')}\n"
            f"- status: {record.get('status')}\n"
            f"- source: {record.get('source')}\n"
        ),
    )


def _solve_loop_submit_plan(contest_id: str, challenge_id: str, verification: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "ready",
        "contest_id": contest_id,
        "challenge_id": challenge_id,
        "candidate_hash": verification.get("candidate_hash"),
        "confidence": verification.get("confidence"),
        "command": "ctfctl interactive submit --contest-id <contest> --challenge-id <challenge> --flag-file <local-file> --confirm --json",
        "confirm_required": True,
    }


def _submit_candidate_value(contest_id: str, challenge_id: str, candidate: str, *, challenge_dir: Path) -> dict[str, Any]:
    attempt_dir = challenge_dir / "attempts"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    flag_path = attempt_dir / f"submit-candidate-{hash_flag(candidate)[:12]}.txt"
    flag_path.write_text(candidate, encoding="utf-8")
    try:
        return submit_flag_file(contest_id, challenge_id=challenge_id, flag_file=flag_path, confirm=True)
    finally:
        flag_path.unlink(missing_ok=True)


def _write_solve_loop_summary(
    challenge_dir: Path,
    *,
    contest_id: str,
    challenge_id: str,
    category: str,
    verification: Mapping[str, Any],
    submit_result: Mapping[str, Any],
) -> None:
    digest = str(verification.get("candidate_hash") or submit_result.get("flag_hash") or "")
    timestamp = utc_now()
    summary = [
        "# Solve Summary",
        "",
        f"- contest_id: {contest_id}",
        f"- challenge_id: {challenge_id}",
        f"- category: {category}",
        "- status: accepted",
        f"- accepted_flag_hash: {digest}",
        f"- solved_at: {timestamp}",
        f"- candidate_confidence: {verification.get('confidence')}",
        "",
    ]
    skill = [
        "# Skill Candidate",
        "",
        f"- contest_id: {contest_id}",
        f"- challenge_id: {challenge_id}",
        f"- category: {category}",
        "- pattern: interactive solve-loop produced and verified a high-confidence local candidate",
        "- reusable_signal: starter execution plus automatic candidate extraction and guarded submit",
        f"- accepted_flag_hash: {digest}",
        "",
    ]
    (challenge_dir / "solve_summary.md").write_text(_target_safe_text("\n".join(summary)), encoding="utf-8")
    (challenge_dir / "skill_candidate.md").write_text(_target_safe_text("\n".join(skill)), encoding="utf-8")


def _save_challenge_triage_metadata(root: Path, board: dict[str, Any], challenge_id: str, metadata: Mapping[str, Any]) -> None:
    _save_challenge_local_metadata(root, board, challenge_id, "challenge_triage_metadata", "triage_metadata", metadata)


def _save_challenge_solver_metadata(root: Path, board: dict[str, Any], challenge_id: str, metadata: Mapping[str, Any]) -> None:
    _save_challenge_local_metadata(root, board, challenge_id, "challenge_solver_metadata", "solver_metadata", metadata)


def _save_challenge_service_metadata(root: Path, board: dict[str, Any], challenge_id: str, metadata: Mapping[str, Any]) -> None:
    _save_challenge_local_metadata(root, board, challenge_id, "challenge_service_metadata", "service_metadata", _service_public_metadata(metadata))


def _ensure_service_metadata(root: Path, board: dict[str, Any], item: Mapping[str, Any], challenge_id: str) -> dict[str, Any]:
    metadata = _service_metadata_for_item(root, board, item, challenge_id)
    if metadata:
        return metadata
    context = _target_context(str(board.get("contest_id") or ""), root, item)
    endpoint = _service_endpoint_from_context(context)
    if not endpoint:
        return {}
    metadata = _build_service_metadata(
        challenge_id,
        endpoint=endpoint,
        endpoint_source="challenge_metadata",
        token_source={"type": "none"},
        pow_helper=None,
    )
    _save_challenge_service_metadata(root, board, challenge_id, metadata)
    return metadata


def _service_metadata_for_item(root: Path, board: Mapping[str, Any], item: Mapping[str, Any], challenge_id: str) -> dict[str, Any]:
    keys = _challenge_keys(item) | {_normalize(challenge_id)}
    sources: list[Any] = []
    config = _operator_config(root)
    sources.append(config.get("challenge_service_metadata") if isinstance(config.get("challenge_service_metadata"), Mapping) else {})
    sources.append(board.get("service_metadata") if isinstance(board.get("service_metadata"), Mapping) else {})
    if isinstance(item.get("service_metadata"), Mapping):
        sources.append({challenge_id: item.get("service_metadata")})
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        for key, metadata in source.items():
            if _normalize(str(key)) not in keys or not isinstance(metadata, Mapping):
                continue
            normalized = _normalize_service_metadata(metadata)
            if normalized:
                return normalized
    return {}


def _normalize_service_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    endpoint = metadata.get("endpoint") if isinstance(metadata.get("endpoint"), Mapping) else metadata
    host = str(endpoint.get("host") or metadata.get("host") or "").strip()
    port = _int_value(endpoint.get("port") or metadata.get("port"))
    if not host or not port:
        return {}
    transport = str(endpoint.get("transport") or endpoint.get("protocol") or metadata.get("transport") or "auto").lower()
    if transport not in SERVICE_TRANSPORTS:
        transport = "tls" if str(transport).lower() in {"ssl", "https"} else "auto"
    token_source = metadata.get("token_source") if isinstance(metadata.get("token_source"), Mapping) else {}
    pow_helper = metadata.get("pow_helper") if isinstance(metadata.get("pow_helper"), Mapping) else {}
    normalized_endpoint = {
        "host": host,
        "port": int(port),
        "transport": transport,
        "locality": str(endpoint.get("locality") or metadata.get("locality") or _service_host_locality(host)),
        "source": str(endpoint.get("source") or metadata.get("endpoint_source") or metadata.get("source") or ""),
        "raw": _service_sanitize_text(str(endpoint.get("raw") or metadata.get("raw") or "")),
    }
    result = {
        "schema": "interactive_service_metadata_v1",
        "challenge_id": str(metadata.get("challenge_id") or ""),
        "endpoint": normalized_endpoint,
        "token_source": _service_public_token_source({"token_source": token_source}),
        "pow_helper": {"path": str(pow_helper.get("path") or "")} if pow_helper.get("path") else {},
        "recommended_connect_command": str(metadata.get("recommended_connect_command") or _service_recommended_connect_command(normalized_endpoint)),
        "updated_at": str(metadata.get("updated_at") or ""),
        "warnings": [str(item) for item in _list_values(metadata.get("warnings"))],
    }
    return result


def _service_endpoint_from_args(*, host: str | None, port: int | None, tls: bool, plain: bool) -> dict[str, Any] | None:
    if not host and port is None:
        return None
    if not host or port is None:
        return None
    transport = "tls" if tls else ("plain" if plain else "auto")
    return {
        "host": str(host).strip(),
        "port": int(port),
        "transport": transport,
        "source": "cli",
        "raw": f"{host}:{port}",
    }


def _service_endpoint_from_context(context: Mapping[str, Any]) -> dict[str, Any] | None:
    service = context.get("service_metadata") if isinstance(context.get("service_metadata"), Mapping) else {}
    endpoint = service.get("endpoint") if isinstance(service.get("endpoint"), Mapping) else {}
    if endpoint.get("host") and endpoint.get("port"):
        return dict(endpoint)
    for endpoint_text in context.get("remote_endpoints") or []:
        parsed = _parse_service_endpoint(str(endpoint_text))
        if parsed:
            return parsed
    return None


def _parse_service_endpoint(value: str) -> dict[str, Any] | None:
    text = str(value or "").strip()
    if not text:
        return None
    parsed = urllib.parse.urlparse(text)
    if parsed.scheme in {"http", "https", "tcp", "tls", "ssl"} and parsed.hostname:
        port = parsed.port or (443 if parsed.scheme in {"https", "tls", "ssl"} else 80)
        return {
            "host": parsed.hostname,
            "port": int(port),
            "transport": "tls" if parsed.scheme in {"https", "tls", "ssl"} else "plain",
            "source": "url",
            "raw": text,
        }
    openssl = re.search(r"(?i)\bopenssl\s+s_client\b.*?\s-connect\s+([A-Za-z0-9_.-]+):([0-9]{1,5})", text)
    if openssl:
        return {"host": openssl.group(1), "port": int(openssl.group(2)), "transport": "tls", "source": "openssl", "raw": text}
    nc = re.search(r"(?i)\b(?:nc|ncat|netcat)\s+((?:--ssl|-ssl|--tls|-tls)\s+)?([A-Za-z0-9_.-]+)\s+([0-9]{1,5})\b", text)
    if nc:
        return {
            "host": nc.group(2),
            "port": int(nc.group(3)),
            "transport": "tls" if nc.group(1) else "plain",
            "source": "netcat",
            "raw": text,
        }
    host_port = re.search(r"\b((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0):([0-9]{1,5})\b", text)
    if host_port:
        return {
            "host": host_port.group(1),
            "port": int(host_port.group(2)),
            "transport": "auto",
            "source": "host_port",
            "raw": text,
        }
    return None


def _normalize_service_token_source(
    token_source: str | None,
    *,
    token_file: str | Path | None,
    token_env: str | None,
) -> dict[str, Any]:
    source = str(token_source or "").strip().lower()
    if not source:
        source = "file" if token_file else ("env" if token_env else "none")
    if source not in SERVICE_TOKEN_SOURCES:
        return {"status": "blocked", "reason": "invalid_token_source"}
    result: dict[str, Any] = {"status": "ok", "type": source}
    if source == "file":
        if not token_file:
            return {"status": "blocked", "reason": "token_file_required"}
        result["file"] = _display(Path(token_file).expanduser())
    elif source == "env":
        if not token_env:
            return {"status": "blocked", "reason": "token_env_required"}
        result["env"] = str(token_env)
    return result


def _build_service_metadata(
    challenge_id: str,
    *,
    endpoint: Mapping[str, Any],
    endpoint_source: str,
    token_source: Mapping[str, Any],
    pow_helper: str | Path | None,
) -> dict[str, Any]:
    endpoint_data = {
        "host": str(endpoint.get("host") or ""),
        "port": int(endpoint.get("port") or 0),
        "transport": str(endpoint.get("transport") or "auto") if str(endpoint.get("transport") or "auto") in SERVICE_TRANSPORTS else "auto",
        "locality": _service_host_locality(str(endpoint.get("host") or "")),
        "source": endpoint_source or str(endpoint.get("source") or ""),
        "raw": _service_sanitize_text(str(endpoint.get("raw") or "")),
    }
    metadata = {
        "schema": "interactive_service_metadata_v1",
        "challenge_id": challenge_id,
        "endpoint": endpoint_data,
        "token_source": _service_public_token_source({"token_source": token_source}),
        "pow_helper": {"path": _display(Path(pow_helper).expanduser())} if pow_helper else {},
        "recommended_connect_command": _service_recommended_connect_command(endpoint_data),
        "updated_at": utc_now(),
    }
    return metadata


def _service_public_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize_service_metadata(metadata) or dict(metadata)
    return {
        "schema": "interactive_service_metadata_v1",
        "challenge_id": str(normalized.get("challenge_id") or metadata.get("challenge_id") or ""),
        "endpoint": _service_endpoint_public(normalized),
        "token_source": _service_public_token_source(normalized),
        "pow_helper": dict(normalized.get("pow_helper") or {}) if isinstance(normalized.get("pow_helper"), Mapping) else {},
        "recommended_connect_command": str(normalized.get("recommended_connect_command") or ""),
        "updated_at": str(normalized.get("updated_at") or ""),
        "warnings": [str(item) for item in _list_values(normalized.get("warnings"))],
    }


def _service_endpoint_public(metadata: Mapping[str, Any]) -> dict[str, Any]:
    endpoint = metadata.get("endpoint") if isinstance(metadata.get("endpoint"), Mapping) else metadata
    host = str(endpoint.get("host") or "")
    port = _int_value(endpoint.get("port")) or 0
    transport = str(endpoint.get("transport") or "auto")
    return {
        "host": host,
        "port": int(port),
        "transport": transport if transport in SERVICE_TRANSPORTS else "auto",
        "locality": str(endpoint.get("locality") or _service_host_locality(host)),
        "source": str(endpoint.get("source") or ""),
    }


def _service_solve_loop_eligible(metadata: Mapping[str, Any]) -> bool:
    if not metadata:
        return False
    endpoint = _service_endpoint_public(metadata)
    # HTTP(S) URLs remain normal web targets unless the operator explicitly
    # configured host/port service metadata.
    return str(endpoint.get("source") or "") != "url"


def _service_public_token_source(metadata: Mapping[str, Any]) -> dict[str, Any]:
    token = metadata.get("token_source") if isinstance(metadata.get("token_source"), Mapping) else metadata
    source = str(token.get("type") or token.get("source") or "none").lower()
    if source not in SERVICE_TOKEN_SOURCES:
        source = "none"
    result: dict[str, Any] = {"type": source}
    if source == "file" and token.get("file"):
        result["file"] = str(token.get("file"))
    if source == "env" and token.get("env"):
        result["env"] = str(token.get("env"))
    return result


def _service_host_locality(host: str) -> str:
    value = str(host or "").strip().strip("[]").lower()
    if value in {"localhost", "0.0.0.0"}:
        return "local"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "public"
    if ip.is_loopback:
        return "local"
    if ip.is_private:
        return "private"
    return "public"


def _service_recommended_connect_command(endpoint: Mapping[str, Any]) -> str:
    host = str(endpoint.get("host") or "")
    port = str(endpoint.get("port") or "")
    if not host or not port:
        return ""
    transport = str(endpoint.get("transport") or "auto")
    if transport == "tls":
        return f"openssl s_client -connect {shlex.quote(host)}:{shlex.quote(port)} -servername {shlex.quote(host)} -quiet"
    if transport == "plain":
        return f"nc {shlex.quote(host)} {shlex.quote(port)}"
    return f"ctfctl interactive service-probe --contest-id <contest> --challenge-id <challenge> --json"


def _service_config_warnings(root: Path, metadata: Mapping[str, Any]) -> list[str]:
    warnings: list[str] = []
    endpoint = _service_endpoint_public(metadata)
    host = str(endpoint.get("host") or "").lower()
    profile_path = str(_operator_config(root).get("profile_path") or "").strip()
    if profile_path and profile_path != "TODO":
        loaded = load_config_metadata(_expand_display_path(profile_path))
        data = loaded.get("data") if isinstance(loaded.get("data"), Mapping) else {}
        base_url = str(data.get("base_url") or data.get("url") or "")
        base_host = urllib.parse.urlparse(base_url).hostname if base_url else ""
        if base_host and host and host != base_host.lower() and not host.endswith("." + base_host.lower()):
            warnings.append("remote_service_host_differs_from_platform_profile_origin")
    return warnings


def _service_probe_connection(metadata: Mapping[str, Any], *, timeout: int) -> dict[str, Any]:
    endpoint = _service_endpoint_public(metadata)
    transport = str(endpoint.get("transport") or "auto")
    transports = ["tls", "plain"] if transport == "auto" else [transport]
    errors: list[str] = []
    for attempt_transport in transports:
        try:
            opened = _open_service_connection(metadata, timeout=timeout, transport_override=attempt_transport)
            sock = opened["socket"]
            try:
                transcript = _service_recv_text(sock, timeout=timeout, limit=SERVICE_TRANSCRIPT_LIMIT)
            finally:
                sock.close()
            return {
                "status": "ok",
                "transport": opened.get("transport") or attempt_transport,
                "connector": opened.get("connector") or "",
                "transcript": transcript,
            }
        except OSError as exc:
            errors.append(f"{attempt_transport}:{_safe_public_note(str(exc), limit=160)}")
            continue
    return {"status": "error", "transport": transport, "connector": "", "transcript": "", "error": "; ".join(errors)}


def _open_service_connection(
    metadata: Mapping[str, Any],
    *,
    timeout: int,
    transport_override: str | None = None,
) -> dict[str, Any]:
    endpoint = _service_endpoint_public(metadata)
    host = str(endpoint.get("host") or "")
    port = int(endpoint.get("port") or 0)
    transport = transport_override or str(endpoint.get("transport") or "auto")
    if transport == "auto":
        transport = "tls"
    raw = socket.create_connection((host, port), timeout=max(1, timeout))
    raw.settimeout(max(1, timeout))
    if transport == "tls":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        wrapped = context.wrap_socket(raw, server_hostname=host)
        wrapped.settimeout(max(1, timeout))
        return {"socket": wrapped, "transport": "tls", "connector": "python_ssl"}
    return {"socket": raw, "transport": "plain", "connector": "python_socket"}


def _service_recv_text(sock: socket.socket | ssl.SSLSocket, *, timeout: int, limit: int) -> str:
    chunks: list[bytes] = []
    start = time.monotonic()
    deadline = start + max(0.2, float(timeout))
    idle_deadline: float | None = None
    while sum(len(chunk) for chunk in chunks) < limit:
        now = time.monotonic()
        active_deadline = idle_deadline or deadline
        if now >= active_deadline:
            break
        sock.settimeout(max(0.05, min(0.25, active_deadline - now)))
        try:
            chunk = sock.recv(min(4096, limit - sum(len(item) for item in chunks)))
        except (TimeoutError, socket.timeout):
            if chunks:
                break
            continue
        if not chunk:
            break
        chunks.append(chunk)
        idle_deadline = time.monotonic() + 0.25
    return b"".join(chunks).decode("utf-8", errors="replace")


def _service_send_line(sock: socket.socket | ssl.SSLSocket, data: bytes) -> None:
    sock.sendall(data.rstrip(b"\r\n") + b"\n")


def _detect_service_prompts(text: str) -> dict[str, Any]:
    body = str(text or "")
    token = bool(
        re.search(
            r"(?i)(team\s+token|service\s+token|enter\s+(?:your\s+)?token|provide\s+(?:team\s+)?token|token\s*[:?>])",
            body,
        )
    )
    pow_prompt = bool(re.search(r"(?i)(proof[- ]of[- ]work|\bpow\b|hashcash|solve\s+.*(?:sha|hash)|nonce)", body))
    menu = bool(re.search(r"(?m)(?:^|\n)\s*(?:>|choice\s*[:?]|option\s*[:?]|\[[0-9]+\])", body) or body.rstrip().endswith((">", ":")))
    prompt_type = "none"
    if token:
        prompt_type = "token"
    elif pow_prompt:
        prompt_type = "pow"
    elif menu:
        prompt_type = "menu"
    return {"token_prompt": token, "pow_prompt": pow_prompt, "menu_prompt": menu, "prompt_type": prompt_type}


def _service_prompt_summary(prompts: Mapping[str, Any] | None) -> str:
    prompts = prompts or {}
    values = []
    if prompts.get("token_prompt"):
        values.append("token")
    if prompts.get("pow_prompt"):
        values.append("pow")
    if prompts.get("menu_prompt"):
        values.append("menu")
    return ",".join(values) if values else str(prompts.get("prompt_type") or "none")


def _read_service_token(root: Path, metadata: Mapping[str, Any]) -> dict[str, Any]:
    token = _service_public_token_source(metadata)
    source = str(token.get("type") or "none")
    try:
        if source == "none":
            return {"status": "blocked", "reason": "service_token_source_not_configured"}
        if source == "file":
            path = _undisplay_path(str(token.get("file") or ""))
            if not path.exists():
                return {"status": "blocked", "reason": "service_token_file_missing"}
            return {"status": "ok", "value": path.read_text(encoding="utf-8").strip()}
        if source == "env":
            name = str(token.get("env") or "")
            if not name or name not in os.environ:
                return {"status": "blocked", "reason": "service_token_env_missing"}
            return {"status": "ok", "value": os.environ.get(name, "")}
        if source == "profile":
            profile_path = str(_operator_config(root).get("profile_path") or "").strip()
            if not profile_path or profile_path == "TODO":
                return {"status": "blocked", "reason": "profile_missing_for_service_token"}
            secret = load_auth_secret(_expand_display_path(profile_path), live=True)
            text = getattr(secret, "_secret_text", None)
            if not text:
                return {"status": "blocked", "reason": "profile_auth_does_not_expose_text_token"}
            return {"status": "ok", "value": str(text).strip()}
    except (OSError, ValueError, KeyError) as exc:
        return {"status": "blocked", "reason": _safe_public_note(str(exc), limit=160)}
    return {"status": "blocked", "reason": "service_token_source_not_supported"}


def _service_token_source_present(root: Path, metadata: Mapping[str, Any] | None) -> bool:
    if not metadata:
        return False
    token = _service_public_token_source(metadata)
    source = str(token.get("type") or "none")
    if source == "file":
        return bool(token.get("file") and _undisplay_path(str(token.get("file"))).exists())
    if source == "env":
        return bool(token.get("env") and str(token.get("env")) in os.environ)
    if source == "profile":
        profile_path = str(_operator_config(root).get("profile_path") or "").strip()
        if not profile_path or profile_path == "TODO":
            return False
        metadata = load_auth_metadata(_expand_display_path(profile_path))
        return bool(metadata.get("usable") or metadata.get("effective_method"))
    return False


def _run_service_pow_helper(metadata: Mapping[str, Any], prompt: str, *, timeout: int, challenge_dir: Path) -> dict[str, Any]:
    helper = metadata.get("pow_helper") if isinstance(metadata.get("pow_helper"), Mapping) else {}
    raw_path = str(helper.get("path") or "")
    if not raw_path:
        return {"status": "blocked", "reason": "pow_helper_missing"}
    path = _undisplay_path(raw_path)
    if not path.exists():
        return {"status": "blocked", "reason": "pow_helper_not_found"}
    endpoint = _service_endpoint_public(metadata)
    env = os.environ.copy()
    env.update(_service_script_env(metadata, root=None, contest_id="", challenge_id=""))
    try:
        completed = subprocess.run(
            _script_argv(path),
            cwd=challenge_dir,
            input=prompt,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=max(1, min(timeout, 30)),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "blocked", "reason": _safe_public_note(str(exc), limit=160)}
    solution = (completed.stdout or "").strip().splitlines()
    if completed.returncode != 0 or not solution:
        return {"status": "blocked", "reason": "pow_helper_failed", "returncode": completed.returncode}
    return {
        "status": "ok",
        "solution": solution[-1],
        "returncode": completed.returncode,
        "stdout_len": len(completed.stdout or ""),
        "stderr_len": len(completed.stderr or ""),
        "endpoint": endpoint,
    }


def _run_service_payload_script(
    script: str | Path | None,
    *,
    root: Path,
    challenge_dir: Path,
    contest_id: str,
    challenge_id: str,
    metadata: Mapping[str, Any],
    timeout: int,
) -> dict[str, Any]:
    if not script:
        return {"status": "ok", "payloads": [], "stdout": "", "stderr": "", "returncode": None}
    path = Path(script).expanduser()
    if not path.is_absolute():
        path = challenge_dir / path
    if not path.exists():
        return {"status": "blocked", "reason": "script_not_found"}
    env = os.environ.copy()
    env.update(_service_script_env(metadata, root=root, contest_id=contest_id, challenge_id=challenge_id))
    try:
        completed = subprocess.run(
            _script_argv(path),
            cwd=challenge_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env=env,
            timeout=max(1, min(timeout, 120)),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "ok",
            "payloads": [_process_output_bytes(exc.stdout)] if exc.stdout else [],
            "stdout": _process_output_text(exc.stdout),
            "stderr": _process_output_text(exc.stderr),
            "returncode": None,
            "timed_out": True,
        }
    except OSError as exc:
        return {"status": "blocked", "reason": _safe_public_note(str(exc), limit=160)}
    stdout_bytes = completed.stdout or b""
    return {
        "status": "ok",
        "payloads": [stdout_bytes] if stdout_bytes else [],
        "stdout": _process_output_text(stdout_bytes),
        "stderr": _process_output_text(completed.stderr),
        "returncode": int(completed.returncode),
    }


def _read_service_payload_file(payload_file: str | Path | None, *, challenge_dir: Path) -> dict[str, Any]:
    if not payload_file:
        return {"status": "ok", "payloads": []}
    path = Path(payload_file).expanduser()
    if not path.is_absolute():
        path = challenge_dir / path
    if not path.exists():
        return {"status": "blocked", "reason": "payload_file_not_found"}
    try:
        return {"status": "ok", "payloads": [path.read_bytes()]}
    except OSError as exc:
        return {"status": "blocked", "reason": _safe_public_note(str(exc), limit=160)}


def _service_script_env(
    metadata: Mapping[str, Any],
    *,
    root: Path | None,
    contest_id: str,
    challenge_id: str,
) -> dict[str, str]:
    endpoint = _service_endpoint_public(metadata)
    token = _service_public_token_source(metadata)
    env = {
        "CTF_CONTEST_ID": contest_id,
        "CTF_CHALLENGE_ID": challenge_id,
        "CTF_SERVICE_HOST": str(endpoint.get("host") or ""),
        "CTF_SERVICE_PORT": str(endpoint.get("port") or ""),
        "CTF_SERVICE_TRANSPORT": str(endpoint.get("transport") or "auto"),
        "CTF_SERVICE_TLS": "1" if endpoint.get("transport") == "tls" else "0",
        "CTF_SERVICE_ENDPOINT": f"{endpoint.get('host')}:{endpoint.get('port')}",
        "CTF_SERVICE_TOKEN_SOURCE": str(token.get("type") or "none"),
    }
    if token.get("file"):
        env["CTF_SERVICE_TOKEN_FILE"] = str(token["file"])
    if token.get("env"):
        env["CTF_SERVICE_TOKEN_ENV"] = str(token["env"])
    pow_helper = metadata.get("pow_helper") if isinstance(metadata.get("pow_helper"), Mapping) else {}
    if pow_helper.get("path"):
        env["CTF_SERVICE_POW_HELPER"] = str(pow_helper["path"])
    if root is not None:
        env["CTF_OPERATOR_ROOT"] = _display(root)
    return env


def _process_output_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", errors="replace")


def _service_attempt_command_display(metadata: Mapping[str, Any], *, script: str | Path | None, payload_file: str | Path | None) -> str:
    endpoint = _service_endpoint_public(metadata)
    parts = [
        "ctfctl interactive service-attempt",
        f"--challenge-id {shlex.quote(str(metadata.get('challenge_id') or '<challenge>'))}",
        f"--endpoint {shlex.quote(str(endpoint.get('host') or ''))}:{endpoint.get('port')}",
    ]
    if script:
        parts.append(f"--script {shlex.quote(str(script))}")
    if payload_file:
        parts.append(f"--payload-file {shlex.quote(str(payload_file))}")
    return " ".join(parts)


def _service_metric_payload(metadata: Mapping[str, Any], *, status: str, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    endpoint = _service_endpoint_public(metadata)
    payload = {
        "status": status,
        "host": endpoint.get("host") or "",
        "port": endpoint.get("port") or 0,
        "transport": endpoint.get("transport") or "auto",
        "locality": endpoint.get("locality") or "",
        "token_source_type": (_service_public_token_source(metadata).get("type") or "none"),
        "pow_helper_present": bool((metadata.get("pow_helper") or {}).get("path")) if isinstance(metadata.get("pow_helper"), Mapping) else False,
    }
    if extra:
        payload.update(dict(extra))
    return payload


def _service_record_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    if not record:
        return {}
    prompts = record.get("prompts") if isinstance(record.get("prompts"), Mapping) else {}
    return {
        "path": record.get("_path") or "",
        "status": record.get("status") or "",
        "completed_at": record.get("completed_at") or "",
        "transport": record.get("transport") or "",
        "prompt_type": _service_prompt_summary(prompts),
        "candidate_count": _int_value(record.get("candidate_count")) or 0,
        "transcript_len": _int_value(record.get("transcript_len")) or 0,
    }


def _last_service_record(directory: Path) -> dict[str, Any]:
    if not directory.exists():
        return {}
    paths = sorted(directory.glob("*.json"))
    if not paths:
        return {}
    record = _read_json_file(paths[-1])
    if record:
        record["_path"] = _display(paths[-1])
    return record


def _service_text_preview(text: str, limit: int) -> str:
    value = str(text or "")
    return value[:limit] + (" [truncated]" if len(value) > limit else "")


def _service_sanitize_text(text: str, *, secrets: Iterable[str] | None = None) -> str:
    safe = str(text or "")
    for secret in secrets or []:
        value = str(secret or "")
        if value:
            safe = safe.replace(value, "[REDACTED_SERVICE_SECRET]")
    safe = re.sub(r"(?im)^(\s*(?:authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)\s*:\s*).*$", r"\1[REDACTED]", safe)
    safe = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer [REDACTED]", safe)
    safe = re.sub(r"(?i)\b(cookie|set-cookie)\s*=\s*[^;\s&]+", lambda match: f"{match.group(1)}=[REDACTED]", safe)
    safe = re.sub(
        r"(?i)\b(session(?:id)?[\w.-]*|csrf(?:token)?[\w.-]*|auth[\w.-]*|password[\w.-]*|passwd[\w.-]*|secret[\w.-]*|api[_-]?key[\w.-]*|jwt[\w.-]*)\s*[:=]\s*['\"]?[^'\"\s,}]+",
        lambda match: f"{match.group(1)}=[REDACTED]",
        safe,
    )
    return safe


class _WebProbeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.links: list[dict[str, str]] = []
        self.scripts: list[dict[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self._in_title = False
        self._active_script: dict[str, str] | None = None
        self._active_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr = {key.lower(): value or "" for key, value in attrs}
        if tag == "title":
            self._in_title = True
        if tag in {"a", "link", "area"} and (attr.get("href") or attr.get("data-href") or attr.get("data-url")):
            self.links.append(
                {
                    "tag": tag,
                    "href": attr.get("href") or attr.get("data-href") or attr.get("data-url") or "",
                    "rel": attr.get("rel", ""),
                    "text": "",
                }
            )
        if tag in {"img", "source", "iframe"} and attr.get("src"):
            self.links.append({"tag": tag, "href": attr.get("src", ""), "rel": "", "text": ""})
        if tag == "script":
            self._active_script = {"src": attr.get("src", ""), "type": attr.get("type", ""), "id": attr.get("id", ""), "text": ""}
        if tag == "form":
            self._active_form = {
                "method": (attr.get("method") or "get").upper(),
                "action": attr.get("action", ""),
                "id": attr.get("id", ""),
                "name": attr.get("name", ""),
                "inputs": [],
            }
            self.forms.append(self._active_form)
        if tag in {"input", "textarea", "select", "button"} and self._active_form is not None:
            inputs = self._active_form.setdefault("inputs", [])
            if isinstance(inputs, list):
                inputs.append({"tag": tag, "name": attr.get("name", ""), "type": attr.get("type", ""), "id": attr.get("id", "")})

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._active_script is not None:
            text = str(self._active_script.get("text") or "")
            self._active_script["text"] = text[:WEB_TEXT_SCAN_LIMIT]
            self.scripts.append(self._active_script)
            self._active_script = None
        elif tag == "form":
            self._active_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title = " ".join((self.title + " " + data).split())[:300]
        if self._active_script is not None:
            self._active_script["text"] = str(self._active_script.get("text") or "") + data
        if self.links and data.strip():
            current = self.links[-1]
            if current.get("tag") == "a":
                current["text"] = " ".join((current.get("text", "") + " " + data.strip()).split())[:200]


def _save_challenge_web_metadata(root: Path, board: dict[str, Any], challenge_id: str, metadata: Mapping[str, Any]) -> None:
    _save_challenge_local_metadata(root, board, challenge_id, "challenge_web_metadata", "web_metadata", _web_public_metadata(metadata))


def _ensure_web_metadata(root: Path, board: dict[str, Any], item: Mapping[str, Any], challenge_id: str) -> dict[str, Any]:
    metadata = _web_metadata_for_item(root, board, item, challenge_id)
    if metadata:
        return metadata
    context = _target_context(str(board.get("contest_id") or ""), root, item)
    base_url = _web_base_url_from_context(context)
    if not base_url:
        return {}
    metadata = _build_web_metadata(
        challenge_id,
        base_url=base_url,
        base_url_source="challenge_metadata",
        auth_source={"status": "ok", "type": "none"},
    )
    _save_challenge_web_metadata(root, board, challenge_id, metadata)
    return metadata


def _web_metadata_for_item(root: Path, board: Mapping[str, Any], item: Mapping[str, Any], challenge_id: str) -> dict[str, Any]:
    keys = _challenge_keys(item) | {_normalize(challenge_id)}
    sources: list[Any] = []
    config = _operator_config(root)
    sources.append(config.get("challenge_web_metadata") if isinstance(config.get("challenge_web_metadata"), Mapping) else {})
    sources.append(board.get("web_metadata") if isinstance(board.get("web_metadata"), Mapping) else {})
    if isinstance(item.get("web_metadata"), Mapping):
        sources.append({challenge_id: item.get("web_metadata")})
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        for key, metadata in source.items():
            if _normalize(str(key)) not in keys or not isinstance(metadata, Mapping):
                continue
            normalized = _normalize_web_metadata(metadata)
            if normalized:
                return normalized
    return {}


def _normalize_web_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    base_url = str(metadata.get("base_url") or metadata.get("url") or "").strip()
    if not base_url:
        return {}
    auth_source = metadata.get("auth_source") if isinstance(metadata.get("auth_source"), Mapping) else {}
    result = {
        "schema": "interactive_web_metadata_v1",
        "challenge_id": str(metadata.get("challenge_id") or ""),
        "base_url": base_url.rstrip("/"),
        "base_url_source": str(metadata.get("base_url_source") or metadata.get("source") or ""),
        "auth_source": _web_public_auth_source({"auth_source": auth_source}),
        "updated_at": str(metadata.get("updated_at") or ""),
        "warnings": [str(item) for item in _list_values(metadata.get("warnings"))],
    }
    return result


def _build_web_metadata(
    challenge_id: str,
    *,
    base_url: str,
    base_url_source: str,
    auth_source: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "interactive_web_metadata_v1",
        "challenge_id": challenge_id,
        "base_url": str(base_url).strip().rstrip("/"),
        "base_url_source": base_url_source,
        "auth_source": _web_public_auth_source({"auth_source": auth_source}),
        "updated_at": utc_now(),
        "warnings": [],
    }


def _web_public_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize_web_metadata(metadata) or dict(metadata)
    return {
        "schema": "interactive_web_metadata_v1",
        "challenge_id": str(normalized.get("challenge_id") or metadata.get("challenge_id") or ""),
        "base_url": _web_public_url(str(normalized.get("base_url") or metadata.get("base_url") or "")),
        "base_url_source": str(normalized.get("base_url_source") or ""),
        "auth_source": _web_public_auth_source(normalized),
        "updated_at": str(normalized.get("updated_at") or ""),
        "warnings": [str(item) for item in _list_values(normalized.get("warnings"))],
    }


def _web_public_auth_source(metadata: Mapping[str, Any]) -> dict[str, Any]:
    auth = metadata.get("auth_source") if isinstance(metadata.get("auth_source"), Mapping) else metadata
    source = str(auth.get("type") or auth.get("source") or "none").strip().lower()
    if source not in WEB_AUTH_SOURCES:
        source = "none"
    result: dict[str, Any] = {"type": source}
    for key in ("cookie_file", "header_file", "storage_state", "env"):
        if auth.get(key):
            result[key] = str(auth.get(key))
    return result


def _normalize_web_auth_source(
    auth_source: str | None,
    *,
    cookie_file: str | Path | None,
    header_file: str | Path | None,
    storage_state: str | Path | None,
    auth_env: str | None,
    existing: Mapping[str, Any] | None,
) -> dict[str, Any]:
    source = str(auth_source or "").strip().lower()
    if not source:
        if cookie_file:
            source = "cookie-file"
        elif header_file:
            source = "header-file"
        elif storage_state:
            source = "storage-state"
        elif auth_env:
            source = "env"
        elif existing:
            source = str(existing.get("type") or "none")
        else:
            source = "none"
    if source not in WEB_AUTH_SOURCES:
        return {"status": "blocked", "reason": "invalid_auth_source"}
    result: dict[str, Any] = {"status": "ok", "type": source}
    if source == "cookie-file":
        path = cookie_file or (existing or {}).get("cookie_file")
        if not path:
            return {"status": "blocked", "reason": "cookie_file_required"}
        result["cookie_file"] = _display(Path(str(path)).expanduser())
    elif source == "header-file":
        path = header_file or (existing or {}).get("header_file")
        if not path:
            return {"status": "blocked", "reason": "header_file_required"}
        result["header_file"] = _display(Path(str(path)).expanduser())
    elif source == "storage-state":
        path = storage_state or (existing or {}).get("storage_state")
        if not path:
            return {"status": "blocked", "reason": "storage_state_required"}
        result["storage_state"] = _display(Path(str(path)).expanduser())
    elif source == "env":
        name = auth_env or (existing or {}).get("env")
        if not name:
            return {"status": "blocked", "reason": "auth_env_required"}
        result["env"] = str(name)
    return result


def _web_base_url_from_context(context: Mapping[str, Any]) -> str:
    metadata = context.get("web_metadata") if isinstance(context.get("web_metadata"), Mapping) else {}
    if metadata.get("base_url"):
        return str(metadata["base_url"])
    return _web_base_url_from_endpoints(context.get("remote_endpoints") or [])


def _web_base_url_from_endpoints(endpoints: Iterable[Any]) -> str:
    for endpoint in endpoints:
        text = str(endpoint or "").strip().rstrip(").,]")
        if not text.startswith(("http://", "https://")):
            continue
        check = _validate_endpoint_url_syntax(text, label="base_url")
        if check.get("allowed"):
            return text.rstrip("/")
    return ""


def _web_config_warnings(root: Path, metadata: Mapping[str, Any]) -> list[str]:
    warnings: list[str] = []
    base_url = str(metadata.get("base_url") or "")
    try:
        parsed = urllib.parse.urlsplit(base_url)
    except ValueError:
        return ["web_base_url_invalid"]
    if parsed.scheme == "http" and _service_host_locality(parsed.hostname or "") == "public":
        warnings.append("web_base_url_plain_http_public")
    if parsed.query:
        warnings.append("web_base_url_has_query")
    profile_path = str(_operator_config(root).get("profile_path") or "").strip()
    if profile_path and profile_path != "TODO":
        loaded = load_config_metadata(_expand_display_path(profile_path))
        data = loaded.get("data") if isinstance(loaded.get("data"), Mapping) else {}
        profile_base = str(data.get("base_url") or data.get("url") or "")
        if profile_base and _url_origin(profile_base) != _url_origin(base_url):
            warnings.append("web_base_url_origin_differs_from_platform_profile_origin")
    return sorted(set(warnings))


def _web_auth_source_present(root: Path, metadata: Mapping[str, Any]) -> bool:
    auth = _web_public_auth_source(metadata)
    source = str(auth.get("type") or "none")
    if source == "none":
        return False
    if source == "profile":
        profile_path = str(_operator_config(root).get("profile_path") or "").strip()
        if not profile_path or profile_path == "TODO":
            return False
        metadata = load_auth_metadata(_expand_display_path(profile_path))
        return bool(metadata.get("usable") or metadata.get("effective_method"))
    if source == "cookie-file":
        return bool(auth.get("cookie_file") and _undisplay_path(str(auth["cookie_file"])).exists())
    if source == "header-file":
        return bool(auth.get("header_file") and _undisplay_path(str(auth["header_file"])).exists())
    if source == "storage-state":
        return bool(auth.get("storage_state") and _undisplay_path(str(auth["storage_state"])).exists())
    if source == "env":
        return bool(auth.get("env") and str(auth["env"]) in os.environ)
    return False


def _web_live_headers(root: Path, metadata: Mapping[str, Any]) -> dict[str, Any]:
    auth = _web_public_auth_source(metadata)
    source = str(auth.get("type") or "none")
    base_url = str(metadata.get("base_url") or "")
    try:
        if source == "none":
            return {"status": "ok", "headers": {}}
        if source == "profile":
            profile_path = str(_operator_config(root).get("profile_path") or "").strip()
            if not profile_path or profile_path == "TODO":
                return {"status": "blocked", "reason": "profile_missing_for_web_auth"}
            secret = load_auth_secret(_expand_display_path(profile_path), live=True)
            return {"status": "ok", "headers": secret.build_headers(base_url=base_url)}
        if source == "cookie-file":
            path = _undisplay_path(str(auth.get("cookie_file") or ""))
            if not path.exists():
                return {"status": "blocked", "reason": "cookie_file_missing"}
            cookie = _web_normalize_cookie_header(path.read_text(encoding="utf-8", errors="replace"))
            return {"status": "ok", "headers": {"Cookie": cookie} if cookie else {}}
        if source == "header-file":
            path = _undisplay_path(str(auth.get("header_file") or ""))
            if not path.exists():
                return {"status": "blocked", "reason": "header_file_missing"}
            return {"status": "ok", "headers": _read_web_header_file(path)}
        if source == "storage-state":
            path = _undisplay_path(str(auth.get("storage_state") or ""))
            if not path.exists():
                return {"status": "blocked", "reason": "storage_state_missing"}
            cookie = _web_storage_state_cookie_header(path, base_url=base_url)
            return {"status": "ok", "headers": {"Cookie": cookie} if cookie else {}}
        if source == "env":
            name = str(auth.get("env") or "")
            if not name or name not in os.environ:
                return {"status": "blocked", "reason": "auth_env_missing"}
            return {"status": "ok", "headers": _web_headers_from_text(os.environ.get(name, ""))}
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return {"status": "blocked", "reason": _web_safe_text(str(exc), limit=160)}
    return {"status": "blocked", "reason": "auth_source_not_supported"}


def _web_normalize_cookie_header(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower().startswith("cookie:"):
        text = text.split(":", 1)[1].strip()
    parts: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("cookie:"):
            line = line.split(":", 1)[1].strip()
        if ";" in line and "=" in line:
            parts.extend(part.strip() for part in line.split(";") if part.strip())
        elif "=" in line:
            parts.append(line)
    return "; ".join(parts) if parts else re.sub(r"[\r\n]+", "; ", text)


def _read_web_header_file(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return {}
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        loaded = None
    if isinstance(loaded, Mapping):
        return _safe_request_headers({str(key): str(value) for key, value in loaded.items()})
    return _web_headers_from_text(text)


def _web_headers_from_text(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    stripped = str(text or "").strip()
    if not stripped:
        return headers
    try:
        loaded = json.loads(stripped)
    except json.JSONDecodeError:
        loaded = None
    if isinstance(loaded, Mapping):
        return _safe_request_headers({str(key): str(value) for key, value in loaded.items()})
    if "\n" in stripped or ":" in stripped:
        for line in stripped.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return _safe_request_headers(headers)
    if "=" in stripped:
        return {"Cookie": _web_normalize_cookie_header(stripped)}
    return {"Authorization": f"Bearer {stripped}"}


def _safe_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    blocked = {"host", "content-length", "transfer-encoding", "connection"}
    result: dict[str, str] = {}
    for key, value in headers.items():
        name = str(key).strip()
        if not name or name.lower() in blocked:
            continue
        result[name] = str(value)
    return result


def _web_storage_state_cookie_header(path: Path, *, base_url: str) -> str:
    state = json.loads(path.read_text(encoding="utf-8"))
    cookies = state.get("cookies") if isinstance(state, Mapping) else []
    if not isinstance(cookies, list):
        return ""
    host = urllib.parse.urlsplit(base_url).hostname or ""
    values: list[str] = []
    for cookie in cookies:
        if not isinstance(cookie, Mapping):
            continue
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "").strip()
        domain = str(cookie.get("domain") or "").lstrip(".").lower()
        if not name or not value:
            continue
        if host and domain and host.lower() != domain and not host.lower().endswith("." + domain):
            continue
        values.append(f"{name}={value}")
    return "; ".join(values)


def _web_fetch(url: str, *, headers: Mapping[str, str], timeout: int) -> dict[str, Any]:
    return _web_request("GET", url, headers=headers, body=None, timeout=timeout)


def _web_request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: int,
) -> dict[str, Any]:
    request_headers = {
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "User-Agent": "dding-ctf-runner-web-harness/0.1",
        **dict(headers),
    }
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method.upper())
    start = time.perf_counter()
    raw = b""
    response_headers: dict[str, str] = {}
    final_url = url
    status_code: int | None = None
    status = "error"
    error = ""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured challenge URL.
            raw = response.read(WEB_RESPONSE_LIMIT + 1)
            if len(raw) > WEB_RESPONSE_LIMIT:
                raw = raw[:WEB_RESPONSE_LIMIT]
            final_url = str(getattr(response, "url", "") or response.geturl() or url)
            status_code = int(getattr(response, "status", 0) or getattr(response, "code", 0) or 200)
            response_headers = {str(key): str(value) for key, value in response.headers.items()}
            status = "ok" if status_code < 400 else "http_error"
    except urllib.error.HTTPError as exc:
        status_code = int(exc.code)
        final_url = str(getattr(exc, "url", "") or url)
        response_headers = {str(key): str(value) for key, value in (exc.headers.items() if exc.headers else [])}
        try:
            raw = exc.read(WEB_RESPONSE_LIMIT + 1)
        except Exception:
            raw = b""
        if len(raw) > WEB_RESPONSE_LIMIT:
            raw = raw[:WEB_RESPONSE_LIMIT]
        status = "http_error"
        error = f"http_error_{status_code}"
    except urllib.error.URLError as exc:
        status = "network_error"
        error = _web_safe_text(str(getattr(exc, "reason", exc)), limit=300)
    except OSError as exc:
        status = "error"
        error = _web_safe_text(str(exc), limit=300)
    content_type = response_headers.get("Content-Type") or response_headers.get("content-type") or ""
    text = _web_decode_body(raw, content_type)
    return {
        "client": "urllib.request",
        "status": status,
        "http_status": status_code,
        "final_url": final_url,
        "content_type": content_type,
        "headers": response_headers,
        "body": text,
        "body_len": len(text),
        "body_sha256": hashlib.sha256(raw).hexdigest() if raw else "",
        "runtime_sec": round(time.perf_counter() - start, 3),
        "error": error,
    }


def _web_decode_body(raw: bytes, content_type: str) -> str:
    match = re.search(r"charset=([A-Za-z0-9_.-]+)", str(content_type or ""), re.IGNORECASE)
    encoding = match.group(1) if match else "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _parse_web_probe_response(response: Mapping[str, Any], base_url: str) -> dict[str, Any]:
    body = str(response.get("body") or "")
    parser = _WebProbeParser()
    if body:
        try:
            parser.feed(body[:WEB_TEXT_SCAN_LIMIT])
        except Exception:
            pass
    forms = [_web_form_summary(row, base_url) for row in parser.forms[:40]]
    links = [_web_url_summary(row.get("href", ""), base_url, tag=row.get("tag", ""), text=row.get("text", "")) for row in parser.links[:120]]
    scripts = [_web_script_summary(row, base_url) for row in parser.scripts[:80]]
    static_links = [
        row
        for row in [*links, *scripts]
        if str(row.get("kind") or "") in {"script", "stylesheet", "image", "asset"} or Path(str(row.get("path") or "")).suffix.lower() in {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".wasm"}
    ][:80]
    endpoints = _web_endpoint_candidates(body, base_url, forms=forms, links=links, scripts=scripts)
    return {
        "title": parser.title,
        "forms": forms,
        "links": links[:80],
        "scripts": scripts,
        "static_links": static_links,
        "endpoint_candidates": endpoints,
    }


def _web_form_summary(form: Mapping[str, Any], base_url: str) -> dict[str, Any]:
    action = str(form.get("action") or "")
    resolved = urllib.parse.urljoin(base_url.rstrip("/") + "/", action or ".")
    inputs = form.get("inputs") if isinstance(form.get("inputs"), list) else []
    return {
        "method": str(form.get("method") or "GET").upper(),
        "action_path": _web_url_path(resolved),
        "action_hash": hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16],
        "id": _web_safe_text(str(form.get("id") or ""), limit=80),
        "name": _web_safe_text(str(form.get("name") or ""), limit=80),
        "inputs": [
            {
                "tag": str(item.get("tag") or ""),
                "name": _web_safe_text(str(item.get("name") or ""), limit=80),
                "type": _web_safe_text(str(item.get("type") or ""), limit=40),
                "id": _web_safe_text(str(item.get("id") or ""), limit=80),
            }
            for item in inputs[:40]
            if isinstance(item, Mapping)
        ],
    }


def _web_url_summary(raw_url: str, base_url: str, *, tag: str, text: str = "") -> dict[str, Any]:
    resolved = urllib.parse.urljoin(base_url.rstrip("/") + "/", str(raw_url or ""))
    path = _web_url_path(resolved)
    suffix = Path(urllib.parse.urlsplit(resolved).path).suffix.lower()
    kind = "link"
    if tag == "script" or suffix == ".js":
        kind = "script"
    elif suffix == ".css" or tag == "link":
        kind = "stylesheet" if suffix == ".css" else "asset"
    elif suffix in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp"}:
        kind = "image"
    elif suffix:
        kind = "asset"
    return {
        "tag": tag,
        "kind": kind,
        "path": path,
        "same_origin": _same_url_origin(base_url, resolved),
        "url_hash": hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:16],
        "text": _web_safe_text(text, limit=120) if text else "",
    }


def _web_script_summary(script: Mapping[str, str], base_url: str) -> dict[str, Any]:
    src = str(script.get("src") or "")
    text = str(script.get("text") or "")
    if src:
        return {**_web_url_summary(src, base_url, tag="script"), "type": _web_safe_text(str(script.get("type") or ""), limit=80), "inline_size": 0, "inline_sha256": ""}
    return {
        "tag": "script",
        "kind": "script",
        "path": "inline",
        "same_origin": True,
        "url_hash": "",
        "type": _web_safe_text(str(script.get("type") or ""), limit=80),
        "inline_size": len(text),
        "inline_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16] if text else "",
    }


def _web_endpoint_candidates(
    body: str,
    base_url: str,
    *,
    forms: list[dict[str, Any]],
    links: list[dict[str, Any]],
    scripts: list[dict[str, Any]],
) -> list[str]:
    candidates: list[str] = []
    for row in forms:
        path = str(row.get("action_path") or "")
        if path:
            candidates.append(path)
    for row in links:
        path = str(row.get("path") or "")
        if path and re.search(r"(?i)(api|graphql|login|auth|admin|upload|download|search|flag|check)", path):
            candidates.append(path)
    for match in re.finditer(r"""(?:(?:fetch|axios\.(?:get|post)|XMLHttpRequest|open)\s*\(?\s*|["'`])((?:https?://|/)[^"'`<>\s)]+)""", body[:WEB_TEXT_SCAN_LIMIT]):
        raw = match.group(1).rstrip(".,;)")
        if raw:
            candidates.append(_web_url_path(urllib.parse.urljoin(base_url.rstrip("/") + "/", raw)))
    for row in scripts:
        path = str(row.get("path") or "")
        if path and path != "inline":
            candidates.append(path)
    return _dedupe_strings(candidates)[:80]


def _web_headers_summary(headers: Mapping[str, Any]) -> dict[str, Any]:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    content_length = _int_value(lowered.get("content-length"))
    names = sorted(key for key in lowered if key not in {"set-cookie", "cookie", "authorization"})
    return {
        "content_type": lowered.get("content-type", "").split(";", 1)[0],
        "content_length": content_length,
        "header_names": names[:80],
        "set_cookie_present": "set-cookie" in lowered,
        "server_present": bool(lowered.get("server")),
        "cache_control": _web_safe_text(lowered.get("cache-control", ""), limit=120),
    }


def _web_probe_error_record(
    contest_id: str,
    challenge_id: str,
    metadata: Mapping[str, Any],
    *,
    started_at: str,
    timeout: int,
    status: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "schema": "interactive_web_probe_v1",
        "contest_id": contest_id,
        "challenge_id": challenge_id,
        "started_at": started_at,
        "completed_at": utc_now(),
        "timeout_sec": timeout,
        "base_url": _web_public_url(str(metadata.get("base_url") or "")),
        "auth_source": _web_public_auth_source(metadata),
        "status": status,
        "http_status": None,
        "title": "",
        "forms": [],
        "links": [],
        "scripts": [],
        "static_links": [],
        "endpoint_candidates": [],
        "headers_summary": {},
        "body_len": 0,
        "body_sha256": "",
        "error": _web_safe_text(reason, limit=300),
    }


def _web_probe_public_result(record: Mapping[str, Any], probe_path: Path) -> dict[str, Any]:
    return {
        "status": record.get("status") or "error",
        "contest_id": record.get("contest_id"),
        "challenge_id": record.get("challenge_id"),
        "base_url": record.get("base_url") or "",
        "http_status": record.get("http_status"),
        "title": record.get("title") or "",
        "forms": record.get("forms") or [],
        "links": record.get("links") or [],
        "scripts": record.get("scripts") or [],
        "static_links": record.get("static_links") or [],
        "endpoint_candidates": record.get("endpoint_candidates") or [],
        "headers_summary": record.get("headers_summary") or {},
        "probe_path": _display(probe_path),
        "error": record.get("error") or "",
    }


def _web_browser_capture(
    root: Path,
    metadata: Mapping[str, Any],
    *,
    screenshot_path: Path,
    timeout: int,
    kind: str,
) -> dict[str, Any]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001 - browser support is optional.
        return {
            "status": "unavailable",
            "reason": "playwright_unavailable",
            "browser_error_type": exc.__class__.__name__,
            "title": "",
            "final_url": "",
            "final_path": "",
            "screenshot_path": "",
            "console_summary": [],
            "network_summary": [],
            "blocked_requests": [],
            "error": _web_safe_text(str(exc), limit=300),
        }
    context_options = _web_browser_context_options(root, metadata)
    if context_options.get("status") != "ok":
        return {
            "status": "blocked",
            "reason": context_options.get("reason") or "auth_context_unavailable",
            "title": "",
            "final_url": "",
            "final_path": "",
            "screenshot_path": "",
            "console_summary": [],
            "network_summary": [],
            "blocked_requests": [],
            "error": str(context_options.get("reason") or ""),
        }
    base_url = str(metadata.get("base_url") or "")
    console: list[dict[str, Any]] = []
    network: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    browser = None
    context = None
    launched = False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            launched = True
            context = browser.new_context(**dict(context_options.get("options") or {}))

            def route_handler(route: Any, request: Any) -> None:
                should_block, reason = _web_should_block_browser_request(str(request.method), str(request.url))
                if should_block:
                    blocked.append({"method": str(request.method).upper(), "path": _web_url_path(str(request.url)), "reason": reason})
                    route.abort()
                    return
                route.continue_()

            context.route("**/*", route_handler)
            page = context.new_page()

            def console_handler(message: Any) -> None:
                if len(console) >= WEB_BROWSER_CONSOLE_LIMIT:
                    return
                console.append({"type": str(getattr(message, "type", "") or ""), "text": _web_auth_sanitize_text(str(message.text))[:500]})

            def response_handler(response: Any) -> None:
                if len(network) >= WEB_BROWSER_NETWORK_LIMIT:
                    return
                headers = response.headers or {}
                network.append(
                    {
                        "method": str(response.request.method).upper(),
                        "path": _web_url_path(str(response.url)),
                        "status": int(response.status),
                        "content_type": str(headers.get("content-type") or "").split(";", 1)[0],
                    }
                )

            page.on("console", console_handler)
            page.on("response", response_handler)
            page.goto(base_url, wait_until="domcontentloaded", timeout=max(1, timeout) * 1000)
            try:
                page.wait_for_load_state("networkidle", timeout=min(5000, max(1000, timeout * 1000 // 3)))
            except PlaywrightTimeoutError:
                pass
            title = _web_auth_sanitize_text(page.title())[:300]
            final_url = str(page.url)
            screenshot_path.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(screenshot_path), full_page=True)
            context.close()
            browser.close()
            return {
                "status": "ok",
                "kind": kind,
                "auth_context": context_options.get("metadata") or {},
                "title": title,
                "final_url": _web_public_url(final_url),
                "final_path": _web_url_path(final_url),
                "screenshot_path": _display(screenshot_path),
                "console_summary": console,
                "network_summary": network,
                "blocked_requests": blocked,
                "error": "",
            }
    except Exception as exc:  # noqa: BLE001 - probes should fail closed and preserve summaries.
        status = "error" if launched else "unavailable"
        reason = "" if launched else "playwright_unavailable"
        return {
            "status": status,
            "reason": reason,
            "kind": kind,
            "auth_context": context_options.get("metadata") or {},
            "title": "",
            "final_url": "",
            "final_path": "",
            "screenshot_path": _display(screenshot_path) if screenshot_path.exists() else "",
            "console_summary": console,
            "network_summary": network,
            "blocked_requests": blocked,
            "error": _web_safe_text(str(exc), limit=300),
            "browser_error_type": exc.__class__.__name__,
        }
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass


def _web_browser_context_options(root: Path, metadata: Mapping[str, Any]) -> dict[str, Any]:
    auth = _web_public_auth_source(metadata)
    source = str(auth.get("type") or "none")
    if source == "storage-state":
        path = _undisplay_path(str(auth.get("storage_state") or ""))
        if not path.exists():
            return {"status": "blocked", "reason": "storage_state_missing"}
        return {"status": "ok", "options": {"storage_state": str(path)}, "metadata": {"auth_source_type": source, "storage_state_path": _display(path)}}
    if source == "profile":
        profile_path = str(_operator_config(root).get("profile_path") or "").strip()
        if profile_path and profile_path != "TODO":
            meta = load_auth_metadata(_expand_display_path(profile_path))
            if meta.get("effective_method") == "storage_state_file" and meta.get("path"):
                path = _undisplay_path(str(meta.get("path") or ""))
                if path.exists():
                    return {"status": "ok", "options": {"storage_state": str(path)}, "metadata": {"auth_source_type": source, "storage_state_path": _display(path)}}
    headers = _web_live_headers(root, metadata)
    if headers.get("status") != "ok":
        return {"status": "blocked", "reason": headers.get("reason") or "auth_source_unavailable"}
    request_headers = dict(headers.get("headers") or {})
    request_headers.setdefault("User-Agent", "dding-ctf-runner-web-harness/0.1")
    return {
        "status": "ok",
        "options": {"extra_http_headers": request_headers} if request_headers else {},
        "metadata": {
            "auth_source_type": source,
            "header_names": sorted(key for key in request_headers if key.lower() not in {"cookie", "authorization"}),
            "cookie_header_present": any(key.lower() == "cookie" for key in request_headers),
            "authorization_header_present": any(key.lower() == "authorization" for key in request_headers),
        },
    }


def _browser_probe_public_result(record: Mapping[str, Any], probe_path: Path) -> dict[str, Any]:
    return {
        "status": record.get("status") or "error",
        "contest_id": record.get("contest_id"),
        "challenge_id": record.get("challenge_id"),
        "base_url": record.get("base_url") or "",
        "title": record.get("title") or "",
        "final_url": record.get("final_url") or "",
        "screenshot_path": record.get("screenshot_path") or "",
        "console_summary": record.get("console_summary") or [],
        "network_summary": record.get("network_summary") or [],
        "blocked_requests": record.get("blocked_requests") or [],
        "probe_path": _display(probe_path),
        "reason": record.get("reason") or "",
        "error": record.get("error") or "",
    }


def _web_should_block_browser_request(method: str, url: str) -> tuple[bool, str]:
    if str(method).upper() not in {"GET", "HEAD"}:
        return True, "non_get_head_blocked"
    path = urllib.parse.urlsplit(str(url)).path.lower()
    destructive = ("attempt", "submit", "submission", "start", "instance", "deploy", "reset", "delete", "logout", "register", "password", "admin")
    if any(token in path for token in destructive):
        return True, "destructive_path_blocked"
    return False, ""


def _run_web_request_json(
    request_json: str | Path,
    *,
    root: Path,
    challenge_dir: Path,
    metadata: Mapping[str, Any],
    timeout: int,
) -> dict[str, Any]:
    path = Path(request_json).expanduser()
    if not path.is_absolute():
        path = challenge_dir / path
    if not path.exists():
        return {"status": "blocked", "reason": "request_json_not_found"}
    try:
        spec = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "blocked", "reason": _web_safe_text(str(exc), limit=160)}
    if not isinstance(spec, Mapping):
        return {"status": "blocked", "reason": "request_json_must_be_object"}
    method = str(spec.get("method") or "GET").upper()
    if not re.fullmatch(r"[A-Z]{3,8}", method):
        return {"status": "blocked", "reason": "request_method_invalid"}
    base_url = str(metadata.get("base_url") or "")
    url = str(spec.get("url") or "").strip()
    if not url:
        raw_path = str(spec.get("path") or "/")
        url = urllib.parse.urljoin(base_url.rstrip("/") + "/", raw_path.lstrip("/"))
    check = _validate_endpoint_url_syntax(url, label="request_url")
    if not check.get("allowed"):
        return {"status": "blocked", "reason": check.get("reason") or "request_url_invalid"}
    auth = _web_live_headers(root, metadata)
    if auth.get("status") != "ok":
        return {"status": "blocked", "reason": auth.get("reason") or "auth_source_unavailable"}
    headers = dict(auth.get("headers") or {})
    if isinstance(spec.get("headers"), Mapping):
        headers.update(_safe_request_headers({str(key): str(value) for key, value in spec["headers"].items()}))
    body: bytes | None = None
    if "json" in spec:
        body = json.dumps(spec.get("json"), sort_keys=True).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif "body" in spec:
        body = str(spec.get("body") or "").encode("utf-8")
    start = time.perf_counter()
    response = _web_request(method, url, headers=headers, body=body, timeout=timeout)
    runtime_sec = round(time.perf_counter() - start, 3)
    stdout = str(response.get("body") or "")
    return {
        "status": "ok",
        "command": f"request-json {shlex.quote(_display(path))}",
        "stdout": stdout,
        "stderr": "",
        "returncode": 0 if str(response.get("status")) == "ok" else 1,
        "runtime_sec": runtime_sec,
        "timed_out": False,
        "response": {
            "status": response.get("status"),
            "http_status": response.get("http_status"),
            "final_url": _web_public_url(str(response.get("final_url") or "")),
            "final_path": _web_url_path(str(response.get("final_url") or url)),
            "content_type": response.get("content_type") or "",
            "body_len": response.get("body_len") or 0,
            "body_sha256": response.get("body_sha256") or "",
            "header_names": sorted(key for key in headers if key.lower() not in {"cookie", "authorization"}),
            "auth_header_present": any(key.lower() in {"cookie", "authorization"} for key in headers),
        },
        "error": response.get("error") or "",
    }


def _run_web_attempt_script(
    script: str | Path | None,
    *,
    root: Path,
    challenge_dir: Path,
    contest_id: str,
    challenge_id: str,
    metadata: Mapping[str, Any],
    timeout: int,
) -> dict[str, Any]:
    if not script:
        return {"status": "blocked", "reason": "script_or_request_json_required"}
    return _run_script_with_env(
        script,
        challenge_dir=challenge_dir,
        env_updates=_web_script_env(root, contest_id=contest_id, challenge_id=challenge_id, metadata=metadata),
        timeout=timeout,
    )


def _run_script_with_env(
    script: str | Path,
    *,
    challenge_dir: Path,
    env_updates: Mapping[str, str],
    timeout: int,
) -> dict[str, Any]:
    path = Path(script).expanduser()
    if not path.is_absolute():
        path = challenge_dir / path
    if not path.exists():
        return {"status": "blocked", "reason": "script_not_found"}
    env = os.environ.copy()
    env.update({str(key): str(value) for key, value in env_updates.items() if value is not None})
    command = _script_argv(path)
    start = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=challenge_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )
        return {
            "status": "ok",
            "command": " ".join(shlex.quote(part) for part in command),
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
            "returncode": int(completed.returncode),
            "runtime_sec": round(time.perf_counter() - start, 3),
            "timed_out": False,
            "error": "",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "ok",
            "command": " ".join(shlex.quote(part) for part in command),
            "stdout": _process_output_text(exc.stdout),
            "stderr": _process_output_text(exc.stderr),
            "returncode": None,
            "runtime_sec": round(time.perf_counter() - start, 3),
            "timed_out": True,
            "error": "timeout",
        }
    except OSError as exc:
        return {"status": "blocked", "reason": _web_safe_text(str(exc), limit=160)}


def _web_script_env(root: Path, *, contest_id: str, challenge_id: str, metadata: Mapping[str, Any]) -> dict[str, str]:
    auth = _web_public_auth_source(metadata)
    env = {
        "CTF_CONTEST_ID": contest_id,
        "CTF_CHALLENGE_ID": challenge_id,
        "CTF_OPERATOR_ROOT": _display(root),
        "CTF_WEB_BASE_URL": str(metadata.get("base_url") or ""),
        "CTF_WEB_AUTH_SOURCE": str(auth.get("type") or "none"),
    }
    if auth.get("cookie_file"):
        env["CTF_WEB_COOKIE_FILE"] = str(auth["cookie_file"])
    if auth.get("header_file"):
        env["CTF_WEB_HEADER_FILE"] = str(auth["header_file"])
    if auth.get("storage_state"):
        env["CTF_WEB_STORAGE_STATE"] = str(auth["storage_state"])
    if auth.get("env"):
        env["CTF_WEB_AUTH_ENV"] = str(auth["env"])
    profile_path = str(_operator_config(root).get("profile_path") or "").strip()
    if profile_path and profile_path != "TODO":
        env["CTF_WEB_PROFILE"] = profile_path
    return env


def _web_metric_payload(metadata: Mapping[str, Any], *, status: str, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    base_url = str(metadata.get("base_url") or "")
    payload = {
        "status": status,
        "base_url_origin": _url_origin(base_url) if base_url else "",
        "base_url_path": _web_url_path(base_url) if base_url else "",
        "base_url_locality": _service_host_locality(urllib.parse.urlsplit(base_url).hostname or "") if base_url else "",
        "auth_source_type": (_web_public_auth_source(metadata).get("type") or "none"),
    }
    if extra:
        payload.update(dict(extra))
    return payload


def _last_web_record(directory: Path) -> dict[str, Any]:
    if not directory.exists():
        return {}
    paths = sorted(directory.glob("*.json"))
    if not paths:
        return {}
    record = _read_json_file(paths[-1])
    if record:
        record["_path"] = _display(paths[-1])
    return record


def _web_record_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    if not record:
        return {}
    return {
        "path": record.get("_path") or "",
        "status": record.get("status") or "",
        "completed_at": record.get("completed_at") or "",
        "http_status": record.get("http_status"),
        "title": record.get("title") or "",
        "candidate_count": _int_value(record.get("candidate_count")) or 0,
        "screenshot_present": _record_has_screenshot(record),
    }


def _record_has_screenshot(record: Mapping[str, Any]) -> bool:
    path = str(record.get("screenshot_path") or "")
    return bool(path and _undisplay_path(path).exists())


def _existing_artifact_path(path: Path) -> str:
    return _display(path) if path.exists() and path.is_file() else ""


def _web_artifact_console_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows[:WEB_BROWSER_CONSOLE_LIMIT]:
        result.append(
            {
                "type": _web_safe_text(str(row.get("type") or ""), limit=60),
                "text": _web_auth_sanitize_text(str(row.get("text") or row.get("message") or ""))[:500],
            }
        )
    return result


def _web_artifact_network_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows[:WEB_BROWSER_NETWORK_LIMIT]:
        url = str(row.get("url") or row.get("path") or "")
        result.append(
            {
                "method": str(row.get("method") or "GET").upper(),
                "path": _web_url_path(url) if url else "",
                "status": _int_value(row.get("status")),
                "content_type": _web_safe_text(str(row.get("content_type") or ""), limit=100),
            }
        )
    return result


def _jsonl_text_for_candidate_scan(rows: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for row in rows[:200]:
        for key in ("text", "message", "body", "response", "candidate"):
            if row.get(key):
                parts.append(str(row.get(key)))
    return "\n".join(parts)


def _starter_looks_browser_based(path: Path) -> bool:
    try:
        if path.stat().st_size > 256 * 1024:
            return path.name in {"solve_browser.py", "browser_solve.py"}
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return path.name in {"solve_browser.py", "browser_solve.py"} or "sync_playwright" in text or "async_playwright" in text


def _web_public_url(url: str) -> str:
    return redact_text(str(url or ""))


def _web_url_path(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(url))
    except ValueError:
        return ""
    return parsed.path or "/"


def _web_safe_text(value: str, *, limit: int) -> str:
    return _service_sanitize_text(str(value or "")).replace("\n", " ")[:limit]


def _web_auth_sanitize_text(value: str) -> str:
    return _service_sanitize_text(str(value or ""))


def _save_challenge_local_metadata(
    root: Path,
    board: dict[str, Any],
    challenge_id: str,
    operator_key: str,
    board_key: str,
    metadata: Mapping[str, Any],
) -> None:
    normalized = _redact_object(dict(metadata))
    config_path = root / "operator.json"
    config = _operator_config(root)
    configured = dict(config.get(operator_key) or {}) if isinstance(config.get(operator_key), Mapping) else {}
    configured[challenge_id] = normalized
    config[operator_key] = configured
    config["updated_at"] = utc_now()
    _write_json(config_path, config)

    board_meta = dict(board.get(board_key) or {}) if isinstance(board.get(board_key), Mapping) else {}
    board_meta[challenge_id] = normalized
    board[board_key] = board_meta
    item = _find_challenge(board, challenge_id)
    if isinstance(item, dict):
        item[board_key] = normalized
    board["updated_at"] = utc_now()
    _write_board(root, board)
    _write_board_md(root, board)


def _starter_filename(category: str) -> str:
    return {
        "web": "solve_web.py",
        "pwn": "exploit.py",
        "rev": "solve_rev.py",
        "crypto": "solve_crypto.py",
        "forensics/misc": "solve_misc.py",
        "osint": "solve_misc.py",
        "ai/ml": "solve_ai_ml.py",
    }.get(category, "solve_misc.py")


def _starter_source(category: str, contest_id: str, item: Mapping[str, Any], context: Mapping[str, Any]) -> str:
    files = _triage_file_inventory(context)
    data = _starter_context_data(contest_id, item, context, files, category=category)
    if category == "web":
        return _starter_web_source(data)
    if category == "pwn":
        return _starter_pwn_source(data)
    if category == "rev":
        return _starter_rev_source(data)
    if category == "crypto":
        return _starter_crypto_source(data)
    if category == "ai/ml":
        return _starter_aiml_source(data)
    return _starter_misc_source(data, category=category)


def _starter_context_data(
    contest_id: str,
    item: Mapping[str, Any],
    context: Mapping[str, Any],
    files: list[dict[str, Any]],
    *,
    category: str,
) -> dict[str, Any]:
    challenge_dir = _absolute_path(Path(context["challenge_dir"]))
    brief = _absolute_path(Path(context["brief_path"])) if context.get("brief_path") else ""
    raw_dirs = [_absolute_path(Path(path)) for path in context.get("raw_dirs") or []]
    extracted_dirs = [_absolute_path(Path(path)) for path in context.get("extracted_dirs") or []]
    top_files = [_absolute_path(_triage_file_path(row)) for row in files if not str(row.get("role") or "").startswith("memo:")][:16]
    primary_files = _primary_triage_files(category, files)
    primary = _absolute_path(primary_files[0]) if primary_files else ""
    toolchain = context.get("toolchain_summary") if isinstance(context.get("toolchain_summary"), Mapping) else {}
    return {
        "contest_id": contest_id,
        "challenge_id": str(item.get("challenge_id") or ""),
        "name": str(item.get("canonical_name") or item.get("name") or item.get("challenge_id") or ""),
        "category": category,
        "challenge_dir": challenge_dir,
        "brief_path": brief,
        "raw_dirs": raw_dirs,
        "extracted_dirs": extracted_dirs,
        "top_files": top_files,
        "primary_file": primary,
        "remote_endpoints": [str(value) for value in context.get("remote_endpoints") or []],
        "service_metadata": _service_public_metadata(context.get("service_metadata") or {}) if context.get("service_metadata") else {},
        "web_metadata": _web_public_metadata(context.get("web_metadata") or {}) if context.get("web_metadata") else {},
        "available_tools": list(toolchain.get("available_tools") or []),
        "missing_critical_tools": list(toolchain.get("missing_critical_tools") or []),
        "recommended_fallbacks": list(toolchain.get("recommended_fallbacks") or []),
    }


def _absolute_path(path: Path) -> str:
    try:
        return str(path.expanduser().resolve())
    except OSError:
        return str(path.expanduser())


def _py_json(value: Any) -> str:
    return json.dumps(value, indent=4, sort_keys=True)


def _starter_header(data: Mapping[str, Any]) -> str:
    return f'''from __future__ import annotations

from pathlib import Path


CONTEST_ID = {json.dumps(data["contest_id"])}
CHALLENGE_ID = {json.dumps(data["challenge_id"])}
CHALLENGE_NAME = {json.dumps(data["name"])}
CHALLENGE_DIR = Path({json.dumps(data["challenge_dir"])})
BRIEF_PATH = Path({json.dumps(data["brief_path"])}) if {json.dumps(bool(data["brief_path"]))} else None
RAW_DIRS = [Path(item) for item in {_py_json(data["raw_dirs"])}]
EXTRACTED_DIRS = [Path(item) for item in {_py_json(data["extracted_dirs"])}]
TOP_FILES = [Path(item) for item in {_py_json(data["top_files"])}]
REMOTE_ENDPOINTS = {_py_json(data["remote_endpoints"])}
SERVICE_METADATA = {_py_json(data["service_metadata"])}
SERVICE_ENDPOINT = SERVICE_METADATA.get("endpoint", {{}})
SERVICE_TOKEN_SOURCE = SERVICE_METADATA.get("token_source", {{"type": "none"}})
WEB_METADATA = {_py_json(data["web_metadata"])}
WEB_BASE_URL = WEB_METADATA.get("base_url", "")
WEB_AUTH_SOURCE = WEB_METADATA.get("auth_source", {{"type": "none"}})
PRIMARY_FILE = Path({json.dumps(data["primary_file"])}) if {json.dumps(bool(data["primary_file"]))} else None
AVAILABLE_TOOLS = {_py_json(data["available_tools"])}
MISSING_CRITICAL_TOOLS = {_py_json(data["missing_critical_tools"])}
RECOMMENDED_FALLBACKS = {_py_json(data["recommended_fallbacks"])}

'''


def _starter_web_source(data: Mapping[str, Any]) -> str:
    return _starter_header(data) + '''import os
import re
import sys
import urllib.request

try:
    import requests
except ImportError:  # pragma: no cover - starter guidance.
    requests = None


FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,32}\\{[^{}\\s]+\\}")


def read_text(path: Path, limit: int = 20000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def candidate_base_url() -> str:
    env_url = os.environ.get("CTF_WEB_BASE_URL", "").strip()
    if env_url:
        return env_url.rstrip("/")
    if WEB_BASE_URL:
        return str(WEB_BASE_URL).rstrip("/")
    if SERVICE_ENDPOINT.get("host") and SERVICE_ENDPOINT.get("port"):
        scheme = "https" if SERVICE_ENDPOINT.get("transport") == "tls" else "http"
        return f"{scheme}://{SERVICE_ENDPOINT['host']}:{SERVICE_ENDPOINT['port']}"
    for endpoint in REMOTE_ENDPOINTS:
        if endpoint.startswith(("http://", "https://")):
            return endpoint.rstrip("/")
    return ""


def session_headers() -> dict[str, str]:
    # ctfctl web-attempt passes auth source paths/env names, not raw secret values.
    return {}


def optional_browser_probe(base_url: str) -> None:
    # Optional Playwright hook for DOM-only bugs. Run this file through
    # browser-attempt after replacing the TODO body with a real action path.
    if not os.environ.get("CTF_BROWSER_SCREENSHOT"):
        return
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(base_url, wait_until="domcontentloaded", timeout=10000)
        page.screenshot(path=os.environ["CTF_BROWSER_SCREENSHOT"], full_page=True)
        browser.close()


def main() -> int:
    base_url = candidate_base_url()
    if not base_url:
        print("TODO: run ctfctl interactive web-config with --base-url or set CTF_WEB_BASE_URL.", file=sys.stderr)
        return 1

    # TODO: map route/auth state from TOP_FILES and replace this probe.
    if requests is not None:
        session = requests.Session()
        session.headers.update(session_headers())
        response = session.get(base_url, timeout=10)
        print(response.status_code)
        body = response.text
    else:
        request = urllib.request.Request(base_url, headers=session_headers(), method="GET")
        with urllib.request.urlopen(request, timeout=10) as response:
            print(response.status)
            body = response.read().decode("utf-8", errors="replace")
    optional_browser_probe(base_url)
    match = FLAG_RE.search(body)
    if match:
        print(match.group(0))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _starter_pwn_source(data: Mapping[str, Any]) -> str:
    return _starter_header(data) + '''import os
import re
import socket
import subprocess
import sys

try:
    from pwn import *  # type: ignore
    PWNLIB_AVAILABLE = True
except ImportError:  # pragma: no cover - starter fallback guidance.
    PWNLIB_AVAILABLE = False
    args = None  # type: ignore
    context = None  # type: ignore


if PWNLIB_AVAILABLE:
    context.log_level = "info"
    if PRIMARY_FILE and PRIMARY_FILE.exists():
        elf = ELF(str(PRIMARY_FILE), checksec=False)
        context.binary = elf
    else:
        elf = None
else:
    elf = None


class SocketTube:
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def sendline(self, data: bytes) -> None:
        self.sock.sendall(data + b"\\n")

    def interactive(self) -> None:
        self.sock.settimeout(1.0)
        try:
            chunk = self.sock.recv(4096)
            if chunk:
                sys.stdout.buffer.write(chunk)
                sys.stdout.flush()
        except TimeoutError:
            pass


class ProcessTube:
    def __init__(self, proc: subprocess.Popen[bytes]):
        self.proc = proc

    def sendline(self, data: bytes) -> None:
        if self.proc.stdin:
            self.proc.stdin.write(data + b"\\n")
            self.proc.stdin.flush()

    def interactive(self) -> None:
        stdout, stderr = self.proc.communicate(timeout=5)
        sys.stdout.buffer.write(stdout or b"")
        sys.stderr.buffer.write(stderr or b"")


def arg_value(name: str, default: str = "") -> str:
    if PWNLIB_AVAILABLE and args is not None:
        value = getattr(args, name, None)
        if value:
            return str(value)
    return os.environ.get(name, default)


def remote_host_port() -> tuple[str, int]:
    if SERVICE_ENDPOINT.get("host") and SERVICE_ENDPOINT.get("port"):
        return str(SERVICE_ENDPOINT["host"]), int(SERVICE_ENDPOINT["port"])
    for endpoint in REMOTE_ENDPOINTS:
        match = re.search(r"\\b(?:nc|ncat|netcat)\\s+(?:--ssl\\s+)?([A-Za-z0-9_.-]+)\\s+([0-9]{2,5})", endpoint)
        if not match:
            match = re.search(r"\\b((?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,}|localhost|127(?:\\.\\d{1,3}){3}):([0-9]{2,5})\\b", endpoint)
        if match:
            return match.group(1), int(match.group(2))
    return arg_value("HOST", "127.0.0.1"), int(arg_value("PORT", "31337"))


def start():
    if arg_value("REMOTE"):
        host, port = remote_host_port()
        if PWNLIB_AVAILABLE:
            return remote(host, port)
        return SocketTube(socket.create_connection((host, port), timeout=10))
    if not PRIMARY_FILE:
        raise SystemExit("Primary binary missing; inspect TOP_FILES.")
    if PWNLIB_AVAILABLE:
        return process([str(PRIMARY_FILE)])
    proc = subprocess.Popen([str(PRIMARY_FILE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return ProcessTube(proc)


def build_payload() -> bytes:
    # TODO: replace with crash offset, primitive, ROP, or shellcode.
    return b"A" * 64


def main() -> None:
    io = start()
    io.sendline(build_payload())
    io.interactive()


if __name__ == "__main__":
    main()
'''


def _starter_rev_source(data: Mapping[str, Any]) -> str:
    return _starter_header(data) + '''import re
import subprocess
import sys

try:
    import z3  # type: ignore
except ImportError:  # pragma: no cover - optional starter dependency.
    z3 = None


FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,32}\\{[^{}\\s]+\\}")


def run_candidate(candidate: str) -> subprocess.CompletedProcess[str] | None:
    if not PRIMARY_FILE or not PRIMARY_FILE.exists():
        return None
    return subprocess.run([str(PRIMARY_FILE), candidate], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)


def solve_with_z3() -> str:
    if z3 is None:
        return ""
    # TODO: translate validation constraints after reversing the check routine.
    return ""


def main() -> int:
    candidate = solve_with_z3()
    if candidate:
        print(candidate)
        return 0
    print(f"TODO: reverse {PRIMARY_FILE or TOP_FILES[:1]} and implement solver", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _starter_crypto_source(data: Mapping[str, Any]) -> str:
    return _starter_header(data) + '''import re
from pathlib import Path


INT_RE = re.compile(r"\\b(?P<name>n|e|c|p|q|phi|modulus|ciphertext|ct)\\s*[:=]\\s*(?P<value>0x[0-9a-fA-F]+|\\d+)\\b")


def read_texts() -> str:
    chunks: list[str] = []
    for path in TOP_FILES:
        if path.is_file() and path.stat().st_size <= 1024 * 1024:
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\\n".join(chunks)


def parse_ints(text: str) -> dict[str, int]:
    params: dict[str, int] = {}
    for match in INT_RE.finditer(text):
        value = match.group("value")
        params[match.group("name")] = int(value, 16) if value.startswith("0x") else int(value)
    return params


def solve(params: dict[str, int]) -> bytes:
    # TODO: identify the primitive/weakness and return plaintext or forged token bytes.
    raise NotImplementedError(params)


def main() -> int:
    params = parse_ints(read_texts())
    print(f"parsed params: {sorted(params)}")
    result = solve(params)
    print(result.decode("utf-8", errors="replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _starter_misc_source(data: Mapping[str, Any], *, category: str) -> str:
    return _starter_header(data) + f'''import subprocess
from pathlib import Path


CATEGORY = {json.dumps(category)}


def run_tool(argv: list[str]) -> str:
    try:
        completed = subprocess.run(argv, cwd=CHALLENGE_DIR, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    except FileNotFoundError:
        return f"missing tool: {argv[0]}\\n"
    return completed.stdout + completed.stderr


def carve_bytes(path: Path, needle: bytes) -> int:
    data = path.read_bytes()
    return data.find(needle)


def main() -> int:
    primary = PRIMARY_FILE or (TOP_FILES[0] if TOP_FILES else None)
    if not primary:
        print("No primary local artifact found; inspect challenge directory.")
        return 1
    print(f"primary={{primary}} size={{primary.stat().st_size}}")
    # TODO: run category-specific carving/metadata/decoding based on triage evidence.
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _starter_aiml_source(data: Mapping[str, Any]) -> str:
    return _starter_header(data) + '''from pathlib import Path


MODEL_SUFFIXES = {".pt", ".pth", ".onnx", ".pkl", ".pickle", ".safetensors", ".h5", ".joblib"}


def model_files() -> list[Path]:
    return [path for path in TOP_FILES if path.suffix.lower() in MODEL_SUFFIXES]


def main() -> int:
    models = model_files()
    print(f"models={models}")
    # TODO: inspect model format, reconstruct inference path, and generate candidate/adversarial input.
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _render_target_pack(contest_id: str, item: Mapping[str, Any], context: Mapping[str, Any], *, agent: str | None) -> str:
    category_guess = context["category_guess"]
    playbook = _category_playbook(str(category_guess["category"]))
    commands = _recommended_first_commands(item, context, playbook)
    toolchain = context.get("toolchain_summary") if isinstance(context.get("toolchain_summary"), Mapping) else {}
    toolchain_report = context.get("toolchain_report") if isinstance(context.get("toolchain_report"), Mapping) else {}
    aliases = _list_values(item.get("aliases"))
    artifact_sources = _list_values(item.get("artifact_sources"))
    source_ids = _list_values(item.get("source_ids"))
    lines = [
        f"# Solver Launch Pack: {_md(str(item.get('canonical_name') or item.get('name') or item.get('challenge_id') or 'challenge'))}",
        "",
        f"- generated_at: {utc_now()}",
        f"- contest_id: {_md(contest_id)}",
        f"- agent: {_md(agent or 'unassigned')}",
        f"- status: {_md(str(item.get('status') or 'todo'))}",
        "",
        "## Identity",
        f"- canonical_name: {_md(str(item.get('canonical_name') or item.get('name') or ''))}",
        f"- canonical_id: {_md(str(item.get('canonical_id') or item.get('challenge_id') or ''))}",
        f"- challenge_id: {_md(str(item.get('challenge_id') or ''))}",
        f"- aliases: {_md(', '.join(str(value) for value in aliases) if aliases else 'none')}",
        f"- artifact_sources: {_md(', '.join(str(value) for value in artifact_sources) if artifact_sources else 'none')}",
        f"- source_ids: {_md(', '.join(str(value) for value in source_ids) if source_ids else 'none')}",
        "",
        "## Category",
        f"- guess: {_md(str(category_guess.get('category') or 'unknown'))}",
        f"- declared: {_md(str(category_guess.get('declared') or ''))}",
        f"- confidence: {int(category_guess.get('confidence') or 0)}",
        f"- sources: {_md(', '.join(str(value) for value in _list_values(category_guess.get('sources'))) or 'none')}",
        "",
        "## Paths",
        f"- challenge_path: {_md(_display(context['challenge_dir']))}",
        f"- brief_path: {_md(_display(context['brief_path']) if context.get('brief_path') else 'missing')}",
        f"- raw_dirs: {_md(', '.join(_display(Path(path)) for path in context.get('raw_dirs') or []) or 'none')}",
        f"- extracted_dirs: {_md(', '.join(_display(Path(path)) for path in context.get('extracted_dirs') or []) or 'none')}",
        f"- manifest_paths: {_md(', '.join(_display(Path(path)) for path in context.get('manifest_paths') or []) or 'none')}",
        "",
        "## Toolchain Capability",
        f"- available_tools: {_md(', '.join(toolchain.get('available_tools') or []) or 'none')}",
        f"- missing_critical_tools: {_md(', '.join(toolchain.get('missing_critical_tools') or []) or 'none')}",
        f"- recommended_fallbacks: {_md(_fallbacks_inline(toolchain.get('recommended_fallbacks') or []))}",
        f"- platform_notes: {_md('; '.join(str(note) for note in toolchain.get('platform_notes') or []) or 'none')}",
        "",
        "## Remote",
    ]
    if context["remote_endpoints"]:
        lines.extend(f"- {_md(endpoint)}" for endpoint in context["remote_endpoints"])
    else:
        lines.append("- none detected")
    service_metadata = context.get("service_metadata") if isinstance(context.get("service_metadata"), Mapping) else {}
    service = _service_public_metadata(service_metadata) if service_metadata else {}
    endpoint = service.get("endpoint") if isinstance(service.get("endpoint"), Mapping) else {}
    lines.extend(["", "## Remote Service"])
    if endpoint.get("host") and endpoint.get("port"):
        lines.extend(
            [
                f"- host: {_md(str(endpoint.get('host') or ''))}",
                f"- port: {int(endpoint.get('port') or 0)}",
                f"- transport: {_md(str(endpoint.get('transport') or 'auto'))}",
                f"- locality: {_md(str(endpoint.get('locality') or ''))}",
                f"- token_source: {_md(str((service.get('token_source') or {}).get('type') or 'none'))}",
                f"- pow_helper_present: {bool((service.get('pow_helper') or {}).get('path'))}",
                f"- recommended_connect_command: `{_md(str(service.get('recommended_connect_command') or ''))}`",
                f"- probe_command: `ctfctl interactive service-probe --contest-id {shlex.quote(contest_id)} --challenge-id {shlex.quote(str(item.get('challenge_id') or ''))} --json`",
                f"- attempt_command: `ctfctl interactive service-attempt --contest-id {shlex.quote(contest_id)} --challenge-id {shlex.quote(str(item.get('challenge_id') or ''))} --json`",
            ]
        )
    else:
        lines.append("- none configured")
    web_metadata = context.get("web_metadata") if isinstance(context.get("web_metadata"), Mapping) else {}
    web = _web_public_metadata(web_metadata) if web_metadata else {}
    lines.extend(["", "## Web"])
    if web.get("base_url"):
        lines.extend(
            [
                f"- base_url: {_md(str(web.get('base_url') or ''))}",
                f"- base_url_source: {_md(str(web.get('base_url_source') or ''))}",
                f"- auth_source: {_md(str((web.get('auth_source') or {}).get('type') or 'none'))}",
                f"- warning_count: {len(web.get('warnings') or [])}",
                f"- status_command: `ctfctl interactive web-status --contest-id {shlex.quote(contest_id)} --challenge-id {shlex.quote(str(item.get('challenge_id') or ''))} --json`",
                f"- probe_command: `ctfctl interactive web-probe --contest-id {shlex.quote(contest_id)} --challenge-id {shlex.quote(str(item.get('challenge_id') or ''))} --json`",
                f"- browser_probe_command: `ctfctl interactive browser-probe --contest-id {shlex.quote(contest_id)} --challenge-id {shlex.quote(str(item.get('challenge_id') or ''))} --json`",
                f"- attempt_command: `ctfctl interactive web-attempt --contest-id {shlex.quote(contest_id)} --challenge-id {shlex.quote(str(item.get('challenge_id') or ''))} --script solve_web.py --json`",
            ]
        )
    else:
        lines.append("- none configured")
    lines.extend(["", "## Top Interesting Files"])
    if context["top_files"]:
        for entry in context["top_files"][:18]:
            reasons = ", ".join(str(value) for value in _list_values(entry.get("reasons"))[:4])
            root = str(entry.get("root") or "")
            rel = str(entry.get("path") or "")
            lines.append(
                f"- {_md(rel)}"
                + (f" (root: {_md(root)})" if root else "")
                + f" [{_md(str(entry.get('category') or 'unknown'))}] score={int(entry.get('score') or 0)}"
                + (f" reasons={_md(reasons)}" if reasons else "")
            )
    else:
        lines.append("- none detected; inspect challenge_path and sync/download state first")
    lines.extend(["", "## Existing Memory"])
    for kind in MEMO_KINDS:
        memo = context["memo_summaries"][kind]
        lines.append(f"- {kind}: {memo['path']}")
        if memo.get("summary"):
            lines.append(f"  summary: {_md(str(memo['summary']))}")
    lines.extend(["", "## Recommended First Commands", "```bash"])
    lines.extend(commands)
    lines.extend(["```", "", "## Category Playbook", f"- category: {_md(playbook['category'])}"])
    for key in ("first_commands", "common_tools", "expected_evidence", "when_to_stall", "when_to_switch_target"):
        values = _available_shell_commands(playbook[key], toolchain_report) if key == "first_commands" else list(playbook[key])
        lines.append(f"- {key}: {_md('; '.join(values) if values else 'none')}")
    lines.extend(["", "## Avoid Wasted Time"])
    lines.extend(f"- {_md(item)}" for item in _avoid_wasted_time(item, context, playbook))
    lines.extend(
        [
            "",
            "## Stop / Stall Criteria",
            "- Stall only after recording concrete memory, evidence, attempts, and next_steps.",
            "- Prefer switching target when no new observable signal remains, setup is blocked, or required remote/service state is unavailable.",
            "- If stalled, run ctfctl interactive stalled with a compact reason and then ctfctl interactive next.",
            "",
            "## Writeup / Cleanup Reminders",
            "- Submit only high-confidence candidates through ctfctl interactive submit or upload-submit with guards.",
            "- Local terminal output may include raw flags during solving, verification, and local operator visibility. Do not publish, upload, commit, push, paste publicly, or place flags, writeups, exploits, auth material, cookies, tokens, sessions, browser storage/storage_state, auth headers, or private keys in public locations or public snapshots during the contest.",
            "- Accepted-only writeups: ctfctl interactive writeup --languages ko,en --include-code.",
            "- Run ctfctl interactive cleanup --safe after accepted solve or before leaving a local worktree in a stable state.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_compact_brief(contest_id: str, item: Mapping[str, Any], context: Mapping[str, Any]) -> str:
    memos = context["memo_summaries"]
    next_steps = str(memos.get("next_steps", {}).get("summary") or "")
    attempts = str(memos.get("attempts", {}).get("summary") or "")
    endpoints = ", ".join(context["remote_endpoints"][:4]) if context["remote_endpoints"] else "none"
    files = ", ".join(str(entry.get("path") or "") for entry in context["top_files"][:5]) if context["top_files"] else "none"
    lines = [
        f"# Brief: {_md(str(item.get('canonical_name') or item.get('name') or item.get('challenge_id') or 'challenge'))}",
        "",
        f"- contest_id: {_md(contest_id)}",
        f"- challenge_id: {_md(str(item.get('challenge_id') or ''))}",
        f"- category: {_md(str(context['category_guess'].get('category') or 'unknown'))} ({int(context['category_guess'].get('confidence') or 0)})",
        f"- status: {_md(str(item.get('status') or 'todo'))}",
        f"- path: {_md(_display(context['challenge_dir']))}",
        f"- brief_path: {_md(_display(context['brief_path']) if context.get('brief_path') else 'missing')}",
        f"- aliases: {_md(', '.join(str(value) for value in _list_values(item.get('aliases'))) or 'none')}",
        f"- artifact_sources: {_md(', '.join(str(value) for value in _list_values(item.get('artifact_sources'))) or 'none')}",
        f"- remote: {_md(endpoints)}",
        f"- top_files: {_md(files)}",
        f"- attempts: {_md(attempts or 'none')}",
        f"- next_steps: {_md(next_steps or 'none')}",
    ]
    return "\n".join(lines) + "\n"


def _recommended_first_commands(item: Mapping[str, Any], context: Mapping[str, Any], playbook: Mapping[str, Any]) -> list[str]:
    challenge_dir = Path(context["challenge_dir"]).expanduser()
    report = context.get("toolchain_report") if isinstance(context.get("toolchain_report"), Mapping) else {}
    commands = [
        f"cd {shlex.quote(str(challenge_dir))}",
        "pwd && find . -maxdepth 3 -type f | sort | sed -n '1,120p'",
    ]
    if context.get("brief_path"):
        try:
            rel = Path(context["brief_path"]).expanduser().relative_to(challenge_dir)
            commands.append(f"sed -n '1,220p' {shlex.quote(rel.as_posix())}")
        except ValueError:
            commands.append(f"sed -n '1,220p' {shlex.quote(str(Path(context['brief_path']).expanduser()))}")
    if context.get("remote_endpoints"):
        commands.append("printf '%s\n' " + " ".join(shlex.quote(endpoint) for endpoint in context["remote_endpoints"][:4]))
    if context.get("service_metadata"):
        commands.append(
            "ctfctl interactive service-status --contest-id "
            + shlex.quote(str(context.get("contest_id") or "<contest>"))
            + " --challenge-id "
            + shlex.quote(str((context.get("service_metadata") or {}).get("challenge_id") or "<challenge>"))
            + " --json"
        )
        commands.append(
            "ctfctl interactive service-probe --contest-id "
            + shlex.quote(str(context.get("contest_id") or "<contest>"))
            + " --challenge-id "
            + shlex.quote(str((context.get("service_metadata") or {}).get("challenge_id") or "<challenge>"))
            + " --json"
        )
    if context.get("web_metadata"):
        web_challenge = str((context.get("web_metadata") or {}).get("challenge_id") or "<challenge>")
        commands.append(
            "ctfctl interactive web-status --contest-id "
            + shlex.quote(str(context.get("contest_id") or "<contest>"))
            + " --challenge-id "
            + shlex.quote(web_challenge)
            + " --json"
        )
        commands.append(
            "ctfctl interactive web-probe --contest-id "
            + shlex.quote(str(context.get("contest_id") or "<contest>"))
            + " --challenge-id "
            + shlex.quote(web_challenge)
            + " --json"
        )
        commands.append(
            "ctfctl interactive browser-probe --contest-id "
            + shlex.quote(str(context.get("contest_id") or "<contest>"))
            + " --challenge-id "
            + shlex.quote(web_challenge)
            + " --json"
        )
    if context.get("remote_endpoints"):
        commands.extend(_remote_probe_commands(context, report))
    commands.extend(_available_shell_commands(playbook["first_commands"], report))
    category = str(playbook.get("category") or "")
    if category in {"pwn", "rev"}:
        first_binary = _first_top_file(context, categories={"binary", "shared_library"})
        if first_binary:
            if command_available(report, "file"):
                commands.append(f"file {shlex.quote(first_binary)}")
            if category == "pwn":
                if command_available(report, "checksec"):
                    commands.append(f"checksec --file={shlex.quote(first_binary)} || true")
                elif command_available(report, "readelf"):
                    commands.append(f"readelf -h {shlex.quote(first_binary)}")
            if command_available(report, "strings"):
                commands.append(f"strings -a -n 4 {shlex.quote(first_binary)} | sed -n '1,120p'")
    elif category == "web":
        if _shell_tool_available("rg", report):
            commands.append("rg -n \"route|app\\.|router\\.|render|template|session|jwt|cookie|upload|fetch|request|sql|eval|exec\" .")
    elif category == "crypto":
        if _shell_tool_available("rg", report):
            commands.append("rg -n \"RSA|AES|ECC|ECDSA|CBC|CTR|GCM|modulus|cipher|decrypt|encrypt|random|seed|nonce\" .")
    elif category == "forensics/misc":
        if _shell_tool_available("find", report) and command_available(report, "file"):
            commands.append("find raw handout extracted -maxdepth 3 -type f -print 2>/dev/null | xargs -r file")
    elif category == "osint":
        if _shell_tool_available("rg", report):
            commands.append("rg -n \"https?://|@|coord|lat|lon|username|handle|domain\" .")
    elif category == "ai/ml":
        if _shell_tool_available("find", report):
            commands.append("find . -maxdepth 4 -type f \\( -name '*.ipynb' -o -name '*.pt' -o -name '*.pth' -o -name '*.onnx' -o -name '*.pkl' -o -name '*.safetensors' -o -name '*.json' \\) | sort")
    return _dedupe_strings(commands)[:14]


def _available_shell_commands(commands: Iterable[str], report: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    for command in commands:
        tool = _first_shell_tool(command)
        if not tool or _shell_tool_available(tool, report):
            result.append(command)
    return result


def _first_shell_tool(command: str) -> str:
    head = re.split(r"\s*(?:&&|\|\||\||;)\s*", str(command or "").strip(), maxsplit=1)[0]
    try:
        parts = shlex.split(head)
    except ValueError:
        parts = head.split()
    return parts[0] if parts else ""


def _shell_tool_available(tool: str, report: Mapping[str, Any]) -> bool:
    if command_available(report, tool):
        return True
    return shutil.which(tool) is not None


def _remote_probe_commands(context: Mapping[str, Any], report: Mapping[str, Any]) -> list[str]:
    endpoints = [str(value) for value in context.get("remote_endpoints") or []]
    if not endpoints:
        return []
    endpoint = endpoints[0]
    host = ""
    port = ""
    tls = endpoint.startswith("https://") or " --ssl " in f" {endpoint} " or endpoint.startswith("tls://")
    nc_match = re.search(r"\b(?:nc|ncat|netcat)\s+(?:--ssl\s+)?([A-Za-z0-9_.-]+)\s+([0-9]{2,5})", endpoint)
    host_port = re.search(r"\b((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|localhost|127(?:\.\d{1,3}){3}):([0-9]{2,5})\b", endpoint)
    if nc_match:
        host, port = nc_match.group(1), nc_match.group(2)
    elif host_port:
        host, port = host_port.group(1), host_port.group(2)
    if not host or not port:
        return []
    if tls and command_available(report, "openssl"):
        return [f"openssl s_client -connect {shlex.quote(host)}:{shlex.quote(port)} -servername {shlex.quote(host)} -quiet"]
    if command_available(report, "ncat"):
        return [f"ncat {shlex.quote(host)} {shlex.quote(port)}"]
    if command_available(report, "nc"):
        return [f"nc {shlex.quote(host)} {shlex.quote(port)}"]
    return []


def _first_top_file(context: Mapping[str, Any], *, categories: set[str]) -> str:
    for entry in context.get("top_files") or []:
        if str(entry.get("category") or "") not in categories:
            continue
        root = _expand_display_path(str(entry.get("root") or ""))
        rel = str(entry.get("path") or "")
        return str(root / rel) if rel else ""
    return ""


def _category_playbook(category: str) -> dict[str, Any]:
    normalized = category if category in PLAYBOOK_CATEGORIES else "forensics/misc"
    playbooks: dict[str, dict[str, Any]] = {
        "web": {
            "category": "web",
            "first_commands": ["rg -n \"TODO|flag|admin|debug|secret\" .", "find . -maxdepth 2 -name 'package.json' -o -name 'requirements.txt' -o -name 'Dockerfile'"],
            "common_tools": ["curl/httpie", "browser devtools", "python requests", "sqlite3", "node/npm", "flask/express tooling"],
            "expected_evidence": ["route map", "auth/session model", "input-to-sink path", "working payload and response"],
            "when_to_stall": ["no reachable service or no route/source signal after bounded triage", "payload class disproven with evidence"],
            "when_to_switch_target": ["no files and generic statement", "remote down without local reproduction", "needs long blind brute force"],
        },
        "pwn": {
            "category": "pwn",
            "first_commands": [
                "file ./* raw/* handout/* extracted/**/* 2>/dev/null",
                "checksec --file ./chall 2>/dev/null || true",
                "python3 - <<'PY'\ntry:\n    import pwn\n    print('pwntools ok')\nexcept ImportError:\n    print('pwntools missing; use socket/subprocess fallback')\nPY",
            ],
            "common_tools": ["file", "checksec", "strings", "gdb/pwndbg", "pwntools", "ROPgadget", "one_gadget"],
            "expected_evidence": ["protections", "crash offset", "primitive", "libc/ld match", "local exploit transcript"],
            "when_to_stall": ["no crash or primitive after bounded fuzz/manual audit", "remote-only state cannot be reproduced"],
            "when_to_switch_target": ["missing binary/libc", "architecture/tooling blocked", "exploit path requires long research"],
        },
        "rev": {
            "category": "rev",
            "first_commands": ["file ./* raw/* handout/* extracted/**/* 2>/dev/null", "strings -a ./* raw/* handout/* 2>/dev/null | sed -n '1,160p'", "rg -n \"check|verify|flag|key|decrypt|xor|base64\" ."],
            "common_tools": ["file", "strings", "objdump", "ghidra", "rizin/radare2", "python", "ltrace/strace"],
            "expected_evidence": ["validation logic", "constants", "decoder/decryptor", "solver script", "verified candidate"],
            "when_to_stall": ["packed/VM/anti-debug path exceeds bounded triage", "no useful strings or decompile path found"],
            "when_to_switch_target": ["needs heavy manual reversing while easier targets remain", "tooling cannot open primary artifact"],
        },
        "crypto": {
            "category": "crypto",
            "first_commands": ["find . -maxdepth 3 -type f | sort", "rg -n \"RSA|ECC|ECDSA|AES|CBC|CTR|GCM|hash|nonce|seed|random|modulus|cipher|sage|Crypto\" ."],
            "common_tools": ["python", "sage", "sympy", "pycryptodome", "z3", "openssl"],
            "expected_evidence": ["parameters", "ciphertexts", "oracle behavior", "weakness hypothesis", "decrypt/forge script"],
            "when_to_stall": ["parameters incomplete", "attack requires unbounded brute force", "oracle/rate limit blocks verification"],
            "when_to_switch_target": ["only generic statement and no data", "math path unclear after deriving constraints"],
        },
        "forensics/misc": {
            "category": "forensics/misc",
            "first_commands": ["find . -maxdepth 4 -type f | sort", "find raw handout extracted -maxdepth 3 -type f -print 2>/dev/null | xargs -r file"],
            "common_tools": ["file", "binwalk", "exiftool", "xxd", "strings", "tshark", "zsteg", "foremost"],
            "expected_evidence": ["file type/metadata", "hidden stream or payload", "extraction command", "decoded candidate"],
            "when_to_stall": ["artifact absent/corrupt", "tool output exhausted without signal", "requires manual guessing"],
            "when_to_switch_target": ["large artifact with no triage signal", "no files and no remote"],
        },
        "osint": {
            "category": "osint",
            "first_commands": ["sed -n '1,220p' brief.md 2>/dev/null || true", "rg -n \"https?://|domain|username|handle|coord|latitude|longitude|image|photo\" ."],
            "common_tools": ["whois/dig", "Wayback", "exiftool", "reverse image search", "maps", "username search"],
            "expected_evidence": ["source URL", "timeline/location/entity", "repeatable query path", "flag derivation"],
            "when_to_stall": ["current-event writeup search would be required", "only ambiguous guesses remain"],
            "when_to_switch_target": ["no unique identifiers", "external sites rate-limit or require accounts"],
        },
        "ai/ml": {
            "category": "ai/ml",
            "first_commands": ["find . -maxdepth 4 -type f | sort", "rg -n \"torch|tensorflow|sklearn|transformers|onnx|pickle|prompt|system\" ."],
            "common_tools": ["python", "numpy", "torch", "tensorflow", "onnxruntime", "pickletools", "jq"],
            "expected_evidence": ["model/config format", "inference path", "prompt/training artifact", "exploit/adversarial input"],
            "when_to_stall": ["model artifact missing", "training/inference cost is too high", "black-box query budget unclear"],
            "when_to_switch_target": ["requires long model training", "no reproducible evaluation harness"],
        },
    }
    return playbooks[normalized]


def _avoid_wasted_time(item: Mapping[str, Any], context: Mapping[str, Any], playbook: Mapping[str, Any]) -> list[str]:
    avoid = [
        "Do not work from alias/static/artifact-source names; use the canonical challenge path and IDs above.",
        "Do not search current-event writeups; use official docs or CVEs only when local version evidence justifies it.",
        "Do not paste raw auth, browser storage/storage_state, cookies, tokens, sessions, private keys, or private artifacts into public services, public pastes, public repositories, or public snapshots.",
    ]
    if not _target_has_files(item, context):
        avoid.append("No local attachments detected; do not assume hidden files exist before checking sync/download state.")
    if not context.get("remote_endpoints"):
        avoid.append("No remote endpoint detected; avoid remote exploit work until connection info is found or recorded.")
    category = str(playbook.get("category") or "")
    if category == "web":
        avoid.append("Avoid payload spraying before mapping routes, auth, and sinks.")
    elif category == "pwn":
        avoid.append("Avoid remote-only exploitation before a local crash/primitive is documented.")
    elif category == "crypto":
        avoid.append("Avoid brute force without a bounded keyspace or mathematical shortcut.")
    return avoid


def _dir_has_files(path: Path) -> bool:
    try:
        return any(child.is_file() for child in path.rglob("*"))
    except OSError:
        return False


def _read_target_text(path: Path, limit: int) -> str:
    try:
        with path.expanduser().open("rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return ""
    return _target_safe_text(data[:limit].decode("utf-8", errors="replace"))


def _target_summary(text: str, limit: int) -> str:
    lines = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    compact = re.sub(r"\s+", " ", " ".join(lines)).strip()
    if len(compact) > limit:
        compact = compact[:limit].rstrip() + " [truncated]"
    return _target_safe_text(compact)


def _target_safe_text(text: str) -> str:
    safe = redact_text(str(text or ""))
    safe = re.sub(r"(?i)\b(cookie|set-cookie)\s*=\s*[^;\s&]+", lambda match: f"{match.group(1)}=[REDACTED]", safe)
    safe = re.sub(
        r"(?i)\b(cookie|token|session|storage[_-]?state|private[ _-]?key|password|secret|auth|bearer|jwt)\b\s+([A-Za-z0-9_.-]{4,})",
        _target_sensitive_word_replacement,
        safe,
    )
    safe = re.sub(
        r"(?i)\b(?=[A-Za-z0-9_.-]{16,}\b)[A-Za-z0-9_.-]*(?:token|cookie|session|storage[_-]?state|private[_-]?key|password|secret|auth|bearer|jwt)[A-Za-z0-9_.-]*\b",
        "[REDACTED]",
        safe,
    )
    return safe


def _target_sensitive_word_replacement(match: re.Match[str]) -> str:
    label = match.group(1)
    value = match.group(2)
    if len(value) >= 12 or not value.isalpha():
        return f"{label} [REDACTED]"
    return match.group(0)


def _expand_display_path(raw: str) -> Path:
    text = str(raw or "").strip()
    if text.startswith("~/"):
        text = str(Path.home()) + text[1:]
    return Path(text).expanduser()


def _ensure_challenge_memos(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for kind in MEMO_KINDS:
        memo = path / f"{kind}.md"
        if not memo.exists():
            title = kind.replace("_", " ").title()
            memo.write_text(f"# {title}\n", encoding="utf-8")


def _writeup_paths(contest_id: str, item: Mapping[str, Any]) -> dict[str, str]:
    root = operator_root(contest_id)
    writeups = Path(_operator_config(root).get("writeup_root") or root / "writeups").expanduser()
    category = str(item.get("category") or "")
    name = str(item.get("name") or item.get("challenge_id") or "challenge")
    return {
        "ko": _display(writeups / f"[{_safe_filename(category)}]{_safe_filename(name)}Writeup.ko.md"),
        "en": _display(writeups / f"[{_safe_filename(category)}]{_safe_filename(name)}Writeup.en.md"),
    }


def _write_e2e_solver(contest_id: str, challenge_id: str) -> dict[str, str]:
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id, "category": "misc"}
    challenge_dir = _challenge_path(contest_id, item)
    challenge_dir.mkdir(parents=True, exist_ok=True)
    solver = challenge_dir / "solver.py"
    solver.write_text(_e2e_solver_source(), encoding="utf-8")
    completed = subprocess.run(
        [sys.executable, str(solver), str(challenge_dir)],
        cwd=challenge_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    candidate = completed.stdout.strip()
    if completed.returncode != 0 or not candidate:
        candidate = default_correct_flag()
    flag_file = challenge_dir / "candidate.txt"
    flag_file.write_text(candidate + "\n", encoding="utf-8")
    (challenge_dir / "run.log").write_text(redact_text(completed.stderr or "solver completed\n"), encoding="utf-8")
    return {"solver": _display(solver), "flag_file": _display(flag_file)}


def _e2e_solver_source() -> str:
    return '''from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    challenge_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    texts = []
    for path in sorted(challenge_dir.rglob("*")):
        if path.is_file() and path.suffix.lower() in {"", ".txt", ".md", ".py"}:
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
    match = re.search(r"DDING\\{[^{}\\s]+\\}", "\\n".join(texts))
    if not match:
        return 1
    print(match.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _validate_e2e_smoke(
    *,
    root: Path,
    writeup_result: Mapping[str, Any],
    summary: Mapping[str, Any],
    duplicate_blocked: Mapping[str, Any],
    duplicate_allowed: Mapping[str, Any],
    submit_result: Mapping[str, Any],
    stalled_result: Mapping[str, Any],
    next_claim: Mapping[str, Any],
) -> dict[str, Any]:
    files = writeup_result.get("files") if isinstance(writeup_result.get("files"), Mapping) else {}
    ko = _undisplay_path(str(files.get("ko") or ""))
    en = _undisplay_path(str(files.get("en") or ""))
    stalled_writeups = list(Path(root / "writeups").glob("*stalled*Writeup.*.md"))
    checks = {
        "submit_accepted": submit_result.get("status") == "accepted",
        "solved_jsonl_updated": "easy-misc-1" in (root / "solved.jsonl").read_text(encoding="utf-8", errors="replace"),
        "submissions_jsonl_updated": "easy-misc-1" in (root / "submissions.jsonl").read_text(encoding="utf-8", errors="replace"),
        "ko_writeup_created": ko.exists(),
        "en_writeup_created": en.exists(),
        "writeups_include_complete_solver_code": _e2e_writeup_has_solver(ko) and _e2e_writeup_has_solver(en),
        "stalled_writeup_absent": not stalled_writeups,
        "stalled_recorded": stalled_result.get("status") == "stalled" and "stalled-1" in (root / "stalled.jsonl").read_text(encoding="utf-8", errors="replace"),
        "metrics_claim": _number(summary.get("claimed_count")) >= 4,
        "metrics_submitted": _number(summary.get("submitted_count")) >= 1,
        "metrics_accepted": _number(summary.get("accepted_count")) >= 1,
        "metrics_writeup": _number(summary.get("writeup_ko_count")) >= 1 and _number(summary.get("writeup_en_count")) >= 1,
        "metrics_cleanup": _number(summary.get("cleanup_count")) >= 1,
        "metrics_stalled": _number(summary.get("stalled_count")) >= 1,
        "duplicate_claim_blocked": duplicate_blocked.get("status") == "blocked" and duplicate_blocked.get("reason") == "already_claimed_on_this_machine",
        "allow_duplicate_permitted": duplicate_allowed.get("status") == "claimed",
        "next_claim_skips_solved": next_claim.get("challenge_id") != "easy-misc-1",
    }
    return {"ok": all(checks.values()), "checks": checks}


def _e2e_writeup_has_solver(path: Path) -> bool:
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    expected = _e2e_solver_source().rstrip()
    return "```python" in text and expected in text and 'raise SystemExit(main())' in text


def _e2e_public(value: Any) -> Any:
    if isinstance(value, Mapping):
        allowed = {
            "status",
            "reason",
            "contest_id",
            "challenge_id",
            "name",
            "category",
            "agent",
            "challenge_count",
            "target_count",
            "canonical_count",
            "alias_count",
            "skipped_static_count",
            "claimable_count",
            "included_code_count",
            "summary_path",
            "operator_root",
            "board_path",
            "path",
            "writeup_paths",
            "files",
            "removed",
            "planned",
            "counts",
            "total_events",
            "sessions",
            "claimed_count",
            "solved_count",
            "stalled_count",
            "submitted_count",
            "accepted_count",
            "writeup_ko_count",
            "writeup_en_count",
            "cleanup_count",
            "tokens_total_observed",
            "avg_time_to_solve_sec",
            "ko",
            "en",
        }
        return {key: _e2e_public(val) for key, val in value.items() if key in allowed}
    if isinstance(value, list):
        return [_e2e_public(item) for item in value]
    return value


def _undisplay_path(value: str) -> Path:
    if value.startswith("~/"):
        return Path.home() / value[2:]
    return Path(value).expanduser()


def _is_fake_or_local_contest_id(contest_id: str) -> bool:
    lowered = str(contest_id or "").strip().lower()
    return lowered in {"fake", "local", "local-fake", "fake-ctfd"} or lowered.startswith(
        ("fake-", "fake_", "local-", "local_", "final-fake", "release-")
    )


def _ensure_metrics_files(root: Path) -> Path:
    metrics_dir = root / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    for filename in METRICS_FILES:
        path = metrics_dir / filename
        if path.exists():
            continue
        if filename.endswith(".jsonl"):
            path.write_text("", encoding="utf-8")
        elif filename.endswith(".json"):
            path.write_text("{}\n", encoding="utf-8")
        else:
            path.write_text("", encoding="utf-8")
    return metrics_dir


def _record_metrics_event(
    root: Path,
    *,
    contest_id: str,
    event: str,
    agent: str | None = None,
    challenge_id: str | None = None,
    data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    metrics_dir = _ensure_metrics_files(root)
    timestamp = utc_now()
    row = {
        "timestamp": timestamp,
        "contest_id": contest_id,
        "event": event,
        "agent": agent,
        "challenge_id": challenge_id,
        "data": dict(data or {}),
    }
    _append_jsonl(metrics_dir / "events.jsonl", row)
    if agent:
        sessions = _read_jsonl(metrics_dir / "sessions.jsonl")
        existing = next((item for item in sessions if item.get("contest_id") == contest_id and item.get("agent") == agent), None)
        if existing is None:
            _append_jsonl(metrics_dir / "sessions.jsonl", {"contest_id": contest_id, "agent": agent, "started_at": timestamp, "last_seen_at": timestamp})
        else:
            _append_jsonl(metrics_dir / "sessions.jsonl", {"contest_id": contest_id, "agent": agent, "started_at": existing.get("started_at"), "last_seen_at": timestamp})
    if challenge_id:
        _append_jsonl(metrics_dir / "challenge_metrics.jsonl", {"timestamp": timestamp, "contest_id": contest_id, "challenge_id": challenge_id, "event": event})
    if event == "tool_benchmark":
        _append_jsonl(metrics_dir / "tool_benchmarks.jsonl", row)
    return row


def _build_metrics_summary(contest_id: str, events: list[dict[str, Any]], sessions_rows: list[dict[str, Any]]) -> dict[str, Any]:
    contest_events = [row for row in events if row.get("contest_id") == contest_id]
    sessions = {
        str(row.get("agent"))
        for row in sessions_rows
        if row.get("contest_id") == contest_id and row.get("agent")
    }
    sessions.update(str(row.get("agent")) for row in contest_events if row.get("agent"))
    tokens_total = 0
    tokens_seen = False
    claim_times: dict[str, datetime] = {}
    solve_durations: list[float] = []
    writeup_ko = 0
    writeup_en = 0
    accepted_count = 0
    solved_count = 0
    artifact_attempted_count = 0
    artifact_accepted_count = 0
    artifact_rejected_count = 0
    artifact_blocked_count = 0
    for row in contest_events:
        event = str(row.get("event") or "")
        data = row.get("data") if isinstance(row.get("data"), Mapping) else {}
        challenge_id = str(row.get("challenge_id") or "")
        timestamp = _parse_timestamp(str(row.get("timestamp") or ""))
        if event == "claim" and challenge_id and timestamp:
            claim_times.setdefault(challenge_id, timestamp)
        if event == "artifact_submit_attempted":
            artifact_attempted_count += 1
        elif event == "artifact_submit_accepted":
            artifact_accepted_count += 1
            accepted_count += 1
            solved_count += 1
            if challenge_id and timestamp and challenge_id in claim_times:
                solve_durations.append((timestamp - claim_times[challenge_id]).total_seconds())
        elif event == "artifact_submit_rejected":
            artifact_rejected_count += 1
        elif event == "artifact_submit_blocked":
            artifact_blocked_count += 1
        if event == "submit" and str(data.get("status") or "") == "accepted":
            accepted_count += 1
            solved_count += 1
            if challenge_id and timestamp and challenge_id in claim_times:
                solve_durations.append((timestamp - claim_times[challenge_id]).total_seconds())
        elif event in {"accepted", "solved", "external_solved", "external_solved_recorded"}:
            solved_count += 1
            if event == "accepted":
                accepted_count += 1
            if challenge_id and timestamp and challenge_id in claim_times:
                solve_durations.append((timestamp - claim_times[challenge_id]).total_seconds())
        if event == "writeup":
            languages = data.get("languages")
            files = data.get("files")
            if isinstance(languages, list):
                writeup_ko += sum(1 for lang in languages if str(lang).lower().startswith("ko"))
                writeup_en += sum(1 for lang in languages if str(lang).lower().startswith("en"))
            elif isinstance(files, Mapping):
                writeup_ko += 1 if "ko" in files else 0
                writeup_en += 1 if "en" in files else 0
        if event == "usage_observed":
            tokens = data.get("tokens_used")
            if isinstance(tokens, (int, float)):
                tokens_total += int(tokens)
                tokens_seen = True
    return {
        "contest_id": contest_id,
        "generated_at": utc_now(),
        "total_events": len(contest_events),
        "sessions": len(sessions),
        "claimed_count": sum(1 for row in contest_events if row.get("event") == "claim"),
        "attempt_count": sum(1 for row in contest_events if row.get("event") in {"attempt_completed", "service_attempt_completed", "web_attempt_completed", "browser_attempt_completed"}),
        "solved_count": solved_count,
        "stalled_count": sum(1 for row in contest_events if row.get("event") == "stalled"),
        "submitted_count": sum(1 for row in contest_events if row.get("event") == "submit") + artifact_attempted_count,
        "accepted_count": accepted_count,
        "artifact_submitted_count": artifact_attempted_count,
        "artifact_accepted_count": artifact_accepted_count,
        "artifact_rejected_count": artifact_rejected_count,
        "artifact_blocked_count": artifact_blocked_count,
        "toolchain_checked_count": sum(1 for row in contest_events if row.get("event") == "toolchain_checked"),
        "missing_tool_observed_count": sum(1 for row in contest_events if row.get("event") == "missing_tool_observed"),
        "fallback_selected_count": sum(1 for row in contest_events if row.get("event") == "fallback_selected"),
        "writeup_ko_count": writeup_ko,
        "writeup_en_count": writeup_en,
        "cleanup_count": sum(1 for row in contest_events if row.get("event") == "cleanup"),
        "tokens_total_observed": tokens_total if tokens_seen else None,
        "avg_time_to_solve_sec": round(sum(solve_durations) / len(solve_durations), 3) if solve_durations else None,
    }


def _public_challenge_index(board: Mapping[str, Any], events: list[dict[str, Any]], root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in board.get("challenges", []):
        if not isinstance(item, Mapping):
            continue
        challenge_id = str(item.get("challenge_id") or item.get("name") or "")
        if not challenge_id:
            continue
        result[challenge_id] = {
            "challenge_id": challenge_id,
            "name": redact_text(str(item.get("name") or challenge_id)),
            "category": redact_text(str(item.get("category") or "")),
            "status": redact_text(str(item.get("status") or "todo")),
            "approaches": set(),
            "stalled_reasons": [],
        }
    for row in events:
        challenge_id = str(row.get("challenge_id") or "")
        if not challenge_id:
            continue
        item = result.setdefault(
            challenge_id,
            {
                "challenge_id": challenge_id,
                "name": challenge_id,
                "category": "",
                "status": "",
                "approaches": set(),
                "stalled_reasons": [],
            },
        )
        data = row.get("data") if isinstance(row.get("data"), Mapping) else {}
        event = str(row.get("event") or "")
        if event in {"submit", "accepted", "solved", "external_solved", "external_solved_recorded", "artifact_submit_accepted"}:
            item["status"] = "solved"
        elif event == "stalled" and item.get("status") != "solved":
            item["status"] = "stalled"
            reason = _safe_public_note(str(data.get("reason") or "stalled"))
            if reason:
                item["stalled_reasons"].append(reason)
        approach = data.get("approach") or data.get("approach_name") or data.get("method")
        if isinstance(approach, str) and approach.strip():
            item["approaches"].add(_safe_public_note(approach, limit=80))
    for row in _read_jsonl(root / "stalled.jsonl"):
        challenge_id = str(row.get("challenge_id") or "")
        if not challenge_id:
            continue
        item = result.setdefault(
            challenge_id,
            {"challenge_id": challenge_id, "name": str(row.get("name") or challenge_id), "category": "", "status": "stalled", "approaches": set(), "stalled_reasons": []},
        )
        item["status"] = "stalled"
        reason = _safe_public_note(str(row.get("reason") or "stalled"))
        if reason:
            item["stalled_reasons"].append(reason)
    return result


def _attempts_total(events: list[dict[str, Any]]) -> int | None:
    total = 0
    seen = False
    for row in events:
        event = str(row.get("event") or "")
        data = row.get("data") if isinstance(row.get("data"), Mapping) else {}
        if event in {"attempt", "attempts", "attempt_completed", "service_attempt_completed", "web_attempt_completed", "browser_attempt_completed"}:
            total += 1
            seen = True
        value = data.get("attempts_total") or data.get("attempt_count")
        if isinstance(value, (int, float)):
            total += int(value)
            seen = True
    return total if seen else None


def _public_candidates(root: Path, board: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    contest_id = str(board.get("contest_id") or "")
    for item in board.get("challenges", []):
        if not isinstance(item, Mapping):
            continue
        challenge_id = str(item.get("challenge_id") or item.get("name") or "")
        if not challenge_id:
            continue
        challenge_dir = _challenge_path(contest_id, item)
        for row in _coalesced_candidates(challenge_dir):
            public = _candidate_public_payload({**row, "challenge_id": challenge_id})
            key = (str(public.get("challenge_id") or ""), str(public.get("flag_hash") or ""))
            if not key[1] or key in seen:
                continue
            seen.add(key)
            rows.append(public)
    return rows


def _public_artifact_submissions(root: Path, contest_id: str) -> list[dict[str, Any]]:
    public: list[dict[str, Any]] = []
    for row in _read_jsonl(root / "submissions.jsonl"):
        if row.get("contest_id") != contest_id or row.get("submit_type") != "artifact_upload":
            continue
        public.append(
            {
                "challenge_id": str(row.get("challenge_id") or ""),
                "artifact_sha256": str(row.get("artifact_sha256") or ""),
                "artifact_size": _number(row.get("artifact_size")),
                "status": str(row.get("status") or ""),
                "active_status": str(row.get("active_status") or ""),
                "response_status": str(row.get("response_status") or ""),
                "submitted_at": str(row.get("submitted_at") or row.get("timestamp") or ""),
            }
        )
    return public


def _render_public_solved(contest_id: str, challenges: Mapping[str, Mapping[str, Any]], root: Path) -> str:
    solved_ids = {str(row.get("challenge_id")) for row in _read_jsonl(root / "solved.jsonl") if row.get("challenge_id")}
    solved_ids.update(cid for cid, item in challenges.items() if str(item.get("status") or "") == "solved")
    lines = [f"# Solved Public Metrics: {_md(contest_id)}", "", "Public-safe solved list. No flags, writeup bodies, or exploit bodies are included.", ""]
    if not solved_ids:
        lines.append("- No solved challenges recorded.")
        return "\n".join(lines) + "\n"
    lines.extend(["| Category | Challenge | Status |", "| --- | --- | --- |"])
    for cid in sorted(solved_ids):
        item = challenges.get(cid, {})
        lines.append(f"| {_md(str(item.get('category') or ''))} | {_md(str(item.get('name') or cid))} | solved |")
    return "\n".join(lines) + "\n"


def _render_public_stalled(contest_id: str, challenges: Mapping[str, Mapping[str, Any]], root: Path) -> str:
    stalled = [(cid, item) for cid, item in challenges.items() if str(item.get("status") or "") == "stalled"]
    lines = [f"# Stalled Public Metrics: {_md(contest_id)}", "", "Unsolved challenges are recorded as stalled metrics only. This file intentionally contains no writeup.", ""]
    if not stalled:
        lines.append("- No stalled challenges recorded.")
        return "\n".join(lines) + "\n"
    lines.extend(["| Category | Challenge | High-level blocker |", "| --- | --- | --- |"])
    for cid, item in sorted(stalled, key=lambda pair: (str(pair[1].get("category") or ""), str(pair[1].get("name") or pair[0]))):
        reasons = item.get("stalled_reasons") if isinstance(item.get("stalled_reasons"), list) else []
        blocker = _dedupe_join([str(reason) for reason in reasons]) or _memo_public_blocker(root, str(cid)) or "stalled"
        lines.append(f"| {_md(str(item.get('category') or ''))} | {_md(str(item.get('name') or cid))} | {_md(blocker)} |")
    return "\n".join(lines) + "\n"


def _render_public_approaches(contest_id: str, challenges: Mapping[str, Mapping[str, Any]], events: list[dict[str, Any]]) -> str:
    lines = [f"# Approaches Public Metrics: {_md(contest_id)}", "", "Approaches are high-level labels only. Solver, exploit, and writeup bodies are not included.", ""]
    observed: list[tuple[str, str, str]] = []
    for cid, item in challenges.items():
        approaches = item.get("approaches")
        if isinstance(approaches, set):
            for approach in sorted(approaches):
                observed.append((str(item.get("category") or ""), str(item.get("name") or cid), approach))
    if not observed:
        labels = sorted({str((row.get("data") or {}).get("category") or row.get("event") or "") for row in events if isinstance(row.get("data"), Mapping)})
        observed = [("", "contest", _safe_public_note(label, limit=80)) for label in labels if label]
    if not observed:
        lines.append("- No approach labels recorded.")
        return "\n".join(lines) + "\n"
    lines.extend(["| Category | Challenge | Approach |", "| --- | --- | --- |"])
    for category, name, approach in observed:
        lines.append(f"| {_md(category)} | {_md(name)} | {_md(approach)} |")
    return "\n".join(lines) + "\n"


def _render_public_regression(contest_id: str, summary: Mapping[str, Any]) -> str:
    lines = [
        f"# Regression Public Metrics: {_md(contest_id)}",
        "",
        f"- solved_count: {summary.get('solved_count')}",
        f"- stalled_count: {summary.get('stalled_count')}",
        f"- accepted_count: {summary.get('accepted_count')}",
        f"- artifact_submitted_count: {summary.get('artifact_submitted_count', 0)}",
        f"- artifact_accepted_count: {summary.get('artifact_accepted_count', 0)}",
        f"- artifact_rejected_count: {summary.get('artifact_rejected_count', 0)}",
        f"- artifact_blocked_count: {summary.get('artifact_blocked_count', 0)}",
        f"- writeup_ko_count: {summary.get('writeup_ko_count')}",
        f"- writeup_en_count: {summary.get('writeup_en_count')}",
        f"- cleanup_count: {summary.get('cleanup_count')}",
        f"- tokens_total_observed: {summary.get('tokens_total_observed') if summary.get('tokens_total_observed') is not None else 'unknown'}",
        f"- avg_time_to_solve_sec: {summary.get('avg_time_to_solve_sec') if summary.get('avg_time_to_solve_sec') is not None else 'unknown'}",
        f"- attempts_total: {summary.get('attempts_total') if summary.get('attempts_total') is not None else 'unknown'}",
        "",
    ]
    return "\n".join(lines)


def _memo_public_blocker(root: Path, challenge_id: str) -> str:
    board = _read_board(root, "")
    item = _find_challenge(board, challenge_id) or {"challenge_id": challenge_id, "name": challenge_id}
    challenge_dir = _challenge_path(str(board.get("contest_id") or ""), item)
    for name in ("next_steps.md", "operator_notes.md", "attempts.md"):
        path = challenge_dir / name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip().lstrip("- ").strip()
            if line and not line.startswith("#"):
                return _safe_public_note(line)
    return ""


def _safe_public_note(value: str, *, limit: int = 160) -> str:
    text = redact_text(str(value or "").replace("\n", " "))
    text = re.sub(r"(?i)\b[A-Za-z0-9_.-]*(?:token|session|cookie|secret|password|passwd|api[_-]?key|storage_state)[A-Za-z0-9_.-]*\b", "[REDACTED]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def _dedupe_join(values: Iterable[str]) -> str:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = _safe_public_note(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return "; ".join(result[:3])


def _git_value(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(["git", *args], cwd=get_paths().repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    except OSError:
        return None
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None


def _number(value: Any) -> int | float:
    return value if isinstance(value, (int, float)) else 0


def _delta(before_value: Any, after_value: Any) -> int | float | None:
    if isinstance(before_value, (int, float)) and isinstance(after_value, (int, float)):
        return after_value - before_value
    if before_value is None and isinstance(after_value, (int, float)):
        return after_value
    if isinstance(before_value, (int, float)) and after_value is None:
        return -before_value
    return None


def _md(value: str) -> str:
    return redact_text(str(value)).replace("|", "\\|")


def _fallbacks_inline(rows: Iterable[Any]) -> str:
    parts: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        suggestions = row.get("suggestions") if isinstance(row.get("suggestions"), list) else []
        ids = [str(item.get("id") or "") for item in suggestions if isinstance(item, Mapping) and item.get("id")]
        if ids:
            parts.append(f"{row.get('tool')} -> {', '.join(ids[:4])}")
        else:
            parts.append(f"{row.get('tool')} -> install/planned action")
    return "; ".join(parts) if parts else "none"


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _read_json_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _collect_code_blocks(challenge_dir: Path) -> list[dict[str, str]]:
    if not challenge_dir.exists():
        return []
    result: list[dict[str, str]] = []
    for path in sorted(challenge_dir.rglob("*")):
        if not path.is_file():
            continue
        lower = path.name.lower()
        if not (lower in {"solve.py", "solver.py", "exploit.py"} or lower.startswith(("solve", "solver", "exploit")) and path.suffix in {".py", ".sage", ".js", ".sh", ".c", ".cpp"}):
            continue
        if path.stat().st_size > 256 * 1024:
            continue
        result.append({"path": _display(path), "language": _language_for(path), "code": path.read_text(encoding="utf-8", errors="replace")})
    return result


def _render_writeup(
    lang: str,
    contest_id: str,
    item: Mapping[str, Any],
    category: str,
    challenge_dir: Path,
    solved: Mapping[str, Any],
    code_blocks: list[dict[str, str]],
) -> str:
    ko = lang.lower().startswith("ko")
    headings = {
        "title": "Writeup" if not ko else "풀이",
        "info": "Challenge Info" if not ko else "문제 정보",
        "summary": "Summary" if not ko else "요약",
        "structure": "Files / Service Structure" if not ko else "파일/서비스 구조",
        "approach": "Approach" if not ko else "접근 과정",
        "failed": "Failed Attempts" if not ko else "실패한 접근",
        "core": "Core Vulnerability / Logic" if not ko else "핵심 취약점/로직",
        "code": "Full Solver / Exploit Code" if not ko else "solver/exploit 전체 코드",
        "run": "How To Run" if not ko else "실행 방법",
        "verify": "Verification" if not ko else "검증 방법",
        "submit": "Submission Result" if not ko else "제출 결과",
        "cleanup": "Cleanup" if not ko else "cleanup 내역",
    }
    name = str(item.get("name") or item.get("challenge_id") or "")
    lines = [
        f"# [{category}] {name} {headings['title']}",
        "",
        f"## {headings['info']}",
        f"- contest_id: {contest_id}",
        f"- challenge_id: {item.get('challenge_id')}",
        f"- name: {name}",
        f"- category: {category}",
        f"- accepted_flag_hash: {solved.get('flag_hash', '')}",
        f"- accepted_artifact_sha256: {solved.get('artifact_sha256', '')}",
        f"- submit_type: {solved.get('submit_type', 'flag')}",
        "",
        f"## {headings['summary']}",
        "- TODO",
        "",
        f"## {headings['structure']}",
        f"- challenge_dir: {_display(challenge_dir)}",
        "",
        f"## {headings['approach']}",
        "- TODO",
        "",
        f"## {headings['failed']}",
        "- TODO",
        "",
        f"## {headings['core']}",
        "- TODO",
        "",
        f"## {headings['code']}",
    ]
    if code_blocks:
        for block in code_blocks:
            lines.extend(["", f"### {block['path']}", f"```{block['language']}", block["code"].rstrip(), "```"])
    else:
        lines.append("- No solver/exploit code found.")
    lines.extend(
        [
            "",
            f"## {headings['run']}",
            "- TODO",
            "",
            f"## {headings['verify']}",
            "- TODO",
            "",
            f"## {headings['submit']}",
            f"- status: {solved.get('status', 'accepted')}",
            f"- submitted_at: {solved.get('timestamp', '')}",
            "",
            f"## {headings['cleanup']}",
            "- Safe cleanup completed or not required.",
            "",
        ]
    )
    return "\n".join(lines)


def _cleanup_candidates(challenge_dir: Path) -> list[Path]:
    if not challenge_dir.exists():
        return []
    result: list[Path] = []
    for path in sorted(challenge_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if path.name in KEEP_NAMES:
            continue
        if path.is_dir() and path.name in SAFE_CLEANUP_NAMES:
            result.append(path)
            continue
        if path.is_file() and (path.suffix in SAFE_CLEANUP_SUFFIXES or path.name in {"core"}):
            result.append(path)
            continue
        if path.is_file() and path.stat().st_size > 25 * 1024 * 1024 and path.suffix.lower() in {".log", ".dump", ".dmp", ".bin"}:
            result.append(path)
    return result


def _try_lock(path: Path, payload: Mapping[str, Any]) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(_redact_object(dict(payload)), fh, indent=2, sort_keys=True)
        fh.write("\n")
    return True


def _claim_payload(contest_id: str, agent: str, item: Mapping[str, Any], *, duplicate: bool) -> dict[str, Any]:
    return {
        "contest_id": contest_id,
        "agent": agent,
        "challenge_id": item.get("challenge_id"),
        "name": item.get("name"),
        "canonical_id": item.get("canonical_id") or item.get("challenge_id"),
        "canonical_name": item.get("canonical_name") or item.get("name"),
        "aliases": _list_values(item.get("aliases")),
        "source_ids": _list_values(item.get("source_ids")),
        "artifact_sources": _list_values(item.get("artifact_sources")),
        "category": item.get("category"),
        "claimed_at": utc_now(),
        "allow_duplicate": duplicate,
    }


def _challenge_public(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "challenge_id": item.get("challenge_id"),
        "name": item.get("name"),
        "category": item.get("category", ""),
        "path": item.get("path", ""),
        "status": item.get("status", "todo"),
        "canonical_id": item.get("canonical_id") or item.get("challenge_id"),
        "canonical_name": item.get("canonical_name") or item.get("name"),
        "aliases": _list_values(item.get("aliases")),
        "artifact_sources": _list_values(item.get("artifact_sources")),
        "source_ids": _list_values(item.get("source_ids")),
        "is_static_shell": bool(item.get("is_static_shell")),
        "claimable": bool(item.get("claimable", True)),
        "solved_by_platform": bool(item.get("solved_by_platform") or item.get("platform_solved")),
        "solved_by_external": bool(item.get("solved_by_external")),
        "solved_source": item.get("solved_source") or "",
        "solved_synced_at": item.get("solved_synced_at") or "",
        "solved_aliases": _list_values(item.get("solved_aliases")),
    }


def _public_action(action: Any) -> dict[str, Any]:
    return _redact_object(action_to_dict(action))


def _interactive_discover_public(payload: Mapping[str, Any]) -> dict[str, Any]:
    details = payload.get("details") if isinstance(payload.get("details"), Mapping) else {}
    safe_details: dict[str, Any] = {}
    for key in ("endpoint", "platform", "challenge_count", "source_challenge_count", "browser_status", "status", "reason"):
        if key in details:
            safe_details[key] = details[key]
    challenges = details.get("challenges")
    if isinstance(challenges, list):
        safe_details["challenge_count"] = len(challenges)
    warnings = details.get("warnings")
    if isinstance(warnings, list):
        safe_details["warnings"] = [redact_text(str(item))[:300] for item in warnings[:20]]
    return _redact_object(
        {
            "action": payload.get("action"),
            "live": bool(payload.get("live")),
            "network": bool(payload.get("network")),
            "status": payload.get("status"),
            "details": safe_details,
        }
    )


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact_text(json.dumps(data, indent=2, sort_keys=True)) + "\n", encoding="utf-8")


def _write_json_raw(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(redact_text(json.dumps(_redact_object(dict(data)), sort_keys=True)))
        fh.write("\n")


def _append_jsonl_raw(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(dict(data), sort_keys=True, default=str))
        fh.write("\n")


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(redact_text(json.dumps(_redact_object(dict(row)), sort_keys=True)))
            fh.write("\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            loaded = json.loads(line)
            if isinstance(loaded, dict):
                rows.append(loaded)
        except json.JSONDecodeError:
            continue
    return rows


def _append_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(redact_text(text))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _redact_object(value: Any) -> Any:
    return json.loads(redact_text(json.dumps(value, sort_keys=True, default=str)))


def _int_value(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        text = str(value).strip()
        return int(text) if text else None
    except (TypeError, ValueError):
        return None


def _dedupe_strings(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = _normalize(text)
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


def _list_values(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).lower())


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip()).strip("._-")
    return slug[:120] or "item"


def _safe_filename(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9가-힣_. -]+", "", str(value or "").strip())
    text = re.sub(r"\s+", "", text)
    return text[:120] or "Challenge"


def _display(path: Path) -> str:
    try:
        return str(path.expanduser()).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _language_for(path: Path) -> str:
    return {".py": "python", ".js": "javascript", ".sh": "bash", ".c": "c", ".cpp": "cpp", ".sage": "python"}.get(path.suffix.lower(), "")


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
