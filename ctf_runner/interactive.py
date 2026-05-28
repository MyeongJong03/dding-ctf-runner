from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import shlex
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .auth import load_auth_secret, load_config_metadata
from .fake_ctfd import FakeCTFdServer, default_correct_flag, platform_config
from .file_manifest import is_sensitive_path
from .ingest import ingest_challenge, ingest_text_challenge
from .paths import get_paths
from .platform_base import action_to_dict
from .platform_ctfd import load_platform_adapter
from .redact import redact_text
from .state import utc_now
from .submit import hash_flag, load_submit_policy, should_submit


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


def sync_operator(
    contest_id: str,
    *,
    profile: str | Path,
    live: bool = False,
    download: bool = False,
    ingest: bool = False,
) -> dict[str, Any]:
    init_operator(contest_id, profile=profile)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    platform = load_platform_adapter(profile)

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
    previous_items = [dict(item) for item in board.get("challenges", []) if isinstance(item, Mapping)]
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

    board["profile_path"] = _display(Path(profile).expanduser())
    board["updated_at"] = utc_now()
    board["canonical_map"] = canonical["map"]
    board["canonical_counts"] = canonical["counts"]
    board["challenges"] = sorted(merged_challenges, key=lambda row: (int(row.get("priority") or 100), str(row.get("name") or "")))
    _apply_runtime_statuses(root, board)
    for challenge in board["challenges"]:
        if challenge.get("solved_by_external"):
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

    return {
        "status": "ok" if discover_action.status in {"ok", "planned"} else discover_action.status,
        "contest_id": contest_id,
        "challenge_count": len(source_challenges),
        "canonical_count": canonical["counts"]["canonical_count"],
        "target_count": canonical["counts"]["claimable_count"],
        "alias_count": canonical["counts"]["alias_count"],
        "skipped_static_count": canonical["counts"]["skipped_static_count"],
        "claimable_count": sum(1 for item in board["challenges"] if _claimable(root, item)),
        "canonical_map": canonical["map"],
        "warnings": sorted(set(warnings + canonical["warnings"])),
        "discover": _interactive_discover_public(discover_payload),
        "download": download_results,
        "ingest": ingest_results,
        "board_path": _display(root / "board.json"),
    }


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
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    ranked = _rank_next_targets(root, contest_id, board, category=category, allow_duplicate=allow_duplicate)
    if not ranked:
        return {
            "status": "empty",
            "contest_id": contest_id,
            "agent": agent,
            "reason": "no_ranked_target",
            "category": category or "",
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
        "first_commands": [str(row.get("command") or "") for row in command_rows[:8]],
        "next_steps": next_steps,
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
        "updated_at": utc_now(),
    }
    _save_challenge_solver_metadata(root, board, challenge_key, metadata)
    _append_starter_memos(Path(context["challenge_dir"]), starter_path=starter_path, category=effective_category, created=created)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="starter_created",
        challenge_id=challenge_key,
        data={"category": effective_category, "starter_path": _display(starter_path), "status": metadata["status"]},
    )
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_key,
        "category": effective_category,
        "starter_path": _display(starter_path),
        "created": created,
        "metadata": metadata,
    }


def prepare_target(
    contest_id: str,
    *,
    agent: str,
    challenge_id: str | None = None,
) -> dict[str, Any]:
    init_operator(contest_id)
    selected: dict[str, Any] = {}
    effective_challenge = challenge_id
    if not effective_challenge:
        selected = next_challenge(contest_id, agent=agent)
        if selected.get("status") not in {"claimed", "planned"}:
            return {
                "status": selected.get("status") or "blocked",
                "contest_id": contest_id,
                "agent": agent,
                "reason": selected.get("reason") or "no_target",
                "selection": selected,
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
    released = _release_locks_for_item(root, agent=None, item=item)
    _write_board(root, board)
    _write_board_md(root, board)
    _record_metrics_event(
        root,
        contest_id=contest_id,
        event="external_solved",
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

    summary_public = {
        **summary,
        "schema": "interactive_metrics_public_snapshot_v1",
        "public_safe": True,
        "source": "local_operator_metrics",
        "contest_ended": bool(contest_ended),
        "snapshot_generated_at": utc_now(),
        "challenge_count": len(challenge_index),
        "attempts_total": attempts_total,
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
    text = f"""You are an autonomous interactive Codex CTF solver for contest {contest_id}, agent {agent}.

Work from ~/CTF. Use ctfctl interactive commands as your coordination surface.

Loop policy:
- Do not solve one challenge and stop. Continue next/claim -> read target pack -> solve -> verify -> submit -> writeup -> cleanup -> next challenge until the contest ends, the user stops you, or no useful work remains.
- Do not split into controller/solver roles. This Codex session is the solver.
- Keep user-facing progress compact unless the user asks for detail.
- Local terminal output may include flags, solver output, and exploit output when needed for solving and verification.
- Do not publish or upload flags, writeups, exploits, tokens, cookies, sessions, browser storage, private keys, or auth material to public services, public repositories, public pastes, issue trackers, or external writeup locations during the contest.
- If the user asks what you are doing, answer from ctfctl interactive brief or the current target pack without stopping the loop.

Coordination:
- Prefer target preparation with: ctfctl interactive prepare-target --contest-id {contest_id} --agent {agent} --json.
- The prepare-target result claims or selects a challenge, writes target_pack_path, triage_summary_path, and starter_path. Read the target pack, triage summary, and starter before manual analysis.
- If you manually claim with ctfctl interactive claim, immediately run ctfctl interactive prepare-target --contest-id {contest_id} --agent {agent} --challenge-id <id> --json.
- If prepare-target is unavailable, run ctfctl interactive target-pack, then ctfctl interactive triage, then ctfctl interactive starter for the same challenge.
- Same-machine duplicate claims are blocked by default. Use --allow-duplicate only when the user explicitly wants duplicate solving.
- If stuck, update memory/evidence/attempts/next_steps, run ctfctl interactive stalled with a compact reason, then run ctfctl interactive next again.
- Maintain memory.md, evidence.md, attempts.md, next_steps.md, and operator_notes.md for each challenge using ctfctl interactive memo.

Submission and writeups:
- Submit only high-confidence candidates through ctfctl interactive submit with --confirm and a flag file.
- For wasm/file artifact challenges, first save official metadata with ctfctl interactive submit-config, then use ctfctl interactive upload-submit --artifact <path> --confirm.
- If accepted, write Korean and English writeups with ctfctl interactive writeup --languages ko,en --include-code.
- Writeups are local-only during the contest and accepted-only. Never write a challenge writeup for unsolved/stalled work.
- If solver/exploit code exists, include the complete code in the writeup.

After each challenge:
- Run safe cleanup with ctfctl interactive cleanup --safe.
- Claim the next eligible challenge and continue.
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
    for dirname in ("claims", "memos", "writeups"):
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
        submit_metadata = canonical.get("platform_submission") if isinstance(canonical.get("platform_submission"), Mapping) else {}

        for source in group:
            source_id = str(source.get("challenge_id") or source.get("name") or "").strip()
            if source_id:
                source_ids.append(source_id)
                canonical_map[source_id] = str(canonical["challenge_id"])
            if source.get("slug"):
                canonical_map[str(source["slug"])] = str(canonical["challenge_id"])
            platform_solved = platform_solved or bool(source.get("platform_solved"))
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
        if submit_metadata:
            canonical["platform_submission"] = dict(submit_metadata)
        if platform_solved:
            canonical["status"] = "external_solved"
            canonical["solved_by_external"] = True
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
        "platform_status": platform_status,
        "platform_submission": platform_submission,
        "canonical_id": challenge_id,
        "canonical_name": canonical_name,
        "is_static_shell": is_static_shell,
        "is_static_alias": is_static_shell,
        "claimable": not is_static_shell,
        "solved_by_external": False,
        "tags": list(item.get("tags") or []),
        "priority": 100,
        "status": "external_solved" if platform_solved else "skipped" if is_static_shell else "todo",
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


def _source_platform_solved(item: Mapping[str, Any], *, platform_status: str, platform_submission: Mapping[str, Any]) -> bool:
    solved = item.get("solved")
    if solved is None:
        solved = item.get("solved_by_me", item.get("completed"))
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
    if item.get("platform_solved") or item_status == "external_solved":
        merged["status"] = "external_solved"
        merged["solved_by_external"] = True
    elif previous_status in {"solved", "external_solved", "stalled", "claimed"}:
        merged["status"] = previous_status
        if previous_status == "external_solved":
            merged["solved_by_external"] = True
    for key in ("claimed_by", "claimed_at", "solved_at", "flag_hash", "artifact_sha256", "stalled_reason"):
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
    normalized["solved_by_external"] = bool(normalized.get("solved_by_external", False))
    normalized.setdefault("priority", 100)
    normalized.setdefault("status", "skipped" if normalized.get("is_static_shell") else "todo")
    normalized["claimable"] = _claimable_source(normalized)
    return normalized


def _challenge_text_for_ingest(challenge: Mapping[str, Any]) -> str:
    return redact_text(str(challenge.get("statement") or "").strip())


def _apply_runtime_statuses(root: Path, board: dict[str, Any]) -> None:
    solved_ids = {_normalize(str(row.get("challenge_id"))) for row in _read_jsonl(root / "solved.jsonl") if row.get("challenge_id")}
    external = (
        {_normalize(line.strip()) for line in (root / "external_solved.txt").read_text(encoding="utf-8").splitlines() if line.strip()}
        if (root / "external_solved.txt").exists()
        else set()
    )
    stalled = {_normalize(str(row.get("challenge_id"))) for row in _read_jsonl(root / "stalled.jsonl") if row.get("challenge_id")}
    claimed = {_normalize(value) for value in _claimed_ids(root)}
    for item in board.get("challenges", []):
        cid = str(item.get("challenge_id") or "")
        keys = _challenge_keys(item)
        item["claimable"] = _claimable_source(item)
        if keys & solved_ids:
            item["status"] = "solved"
            item["solved_by_external"] = False
        elif keys & external:
            item["status"] = "external_solved"
            item["solved_by_external"] = True
        elif item.get("platform_solved"):
            item["status"] = "external_solved"
            item["solved_by_external"] = True
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


def _claimable_source(item: Mapping[str, Any]) -> bool:
    if item.get("is_alias") or item.get("is_static_alias") or item.get("is_static_shell") or item.get("is_artifact_source") or item.get("artifact_source"):
        return False
    return bool(item.get("claimable", True))


def _claimable(root: Path, item: Mapping[str, Any]) -> bool:
    return _challenge_status(root, item) == "todo" and _claimable_source(item)


def _challenge_status(root: Path, item: Mapping[str, Any]) -> str:
    status = str(item.get("status") or "todo")
    if status == "external_solved":
        return "solved"
    if status in {"solved", "claimed", "stalled", "skipped"}:
        return status
    return "todo"


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
    retry_stalled: list[tuple[dict[str, Any], str]] = []
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
        elif status == "stalled" and _stalled_has_clear_next_step(contest_id, item):
            retry_stalled.append((item, status))
        elif status == "claimed" and allow_duplicate:
            duplicate_claimed.append((item, status))

    selected_pool = fresh or retry_stalled or duplicate_claimed
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
    category_guess = _category_guess(item, candidate_dirs, scan_paths=scan_paths, has_remote=bool(remote_endpoints))
    top_files = _top_interesting_files(candidate_dirs, manifest_paths=manifest_paths, scan_paths=scan_paths)
    return {
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
        "category_guess": category_guess,
        "top_files": top_files,
    }


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
        for match in re.finditer(r"(?i)\b(?:nc|ncat|netcat)\s+([A-Za-z0-9_.-]+)\s+([0-9]{2,5})", safe):
            endpoints.append(f"nc {match.group(1)} {match.group(2)}")
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
    rows.append(_run_triage_command(["find", ".", "-maxdepth", "4", "-type", "f"], cwd=cwd, timeout=5))
    if primary:
        rows.append(_run_triage_command(["file", *[str(path) for path in primary[:12]]], cwd=cwd, timeout=8))

    if category == "web":
        rows.extend(
            [
                _run_triage_command(["rg", "-n", r"route|app\.|router\.|urlpatterns|FastAPI|express|fetch|axios|XMLHttpRequest|<form", "."], cwd=cwd, timeout=8),
                _run_triage_command(["rg", "-n", r"auth|login|session|jwt|cookie|upload|render|template|sql|sqlite|eval|exec|ssrf|open\(|path", "."], cwd=cwd, timeout=8),
            ]
        )
    elif category == "pwn":
        target = primary[0] if primary else None
        if target:
            rows.extend(
                [
                    _run_triage_command(["checksec", f"--file={target}"], cwd=cwd, timeout=8),
                    _run_triage_command(["readelf", "-h", str(target)], cwd=cwd, timeout=8),
                    _run_triage_command(["readelf", "-s", str(target)], cwd=cwd, timeout=8),
                    _run_triage_command(["strings", "-a", "-n", "4", str(target)], cwd=cwd, timeout=8),
                ]
            )
    elif category == "rev":
        target = primary[0] if primary else None
        if target:
            rows.extend(
                [
                    _run_triage_command(["readelf", "-h", str(target)], cwd=cwd, timeout=8),
                    _run_triage_command(["objdump", "-f", str(target)], cwd=cwd, timeout=8),
                    _run_triage_command(["strings", "-a", "-n", "4", str(target)], cwd=cwd, timeout=8),
                ]
            )
        rows.append(_run_triage_command(["rg", "-n", r"check|verify|flag|key|decrypt|xor|base64|password|serial", "."], cwd=cwd, timeout=8))
    elif category == "crypto":
        rows.append(_run_triage_command(["rg", "-n", r"RSA|ECC|ECDSA|AES|CBC|CTR|GCM|modulus|cipher|decrypt|encrypt|random|seed|nonce|curve|sage|Crypto", "."], cwd=cwd, timeout=8))
    elif category == "forensics/misc":
        target = primary[0] if primary else None
        if target:
            rows.extend(
                [
                    _run_triage_command(["exiftool", str(target)], cwd=cwd, timeout=8),
                    _run_triage_command(["binwalk", str(target)], cwd=cwd, timeout=12),
                    _run_triage_command(["xxd", "-l", "256", str(target)], cwd=cwd, timeout=8),
                    _run_triage_command(["strings", "-a", "-n", "5", str(target)], cwd=cwd, timeout=8),
                ]
            )
    elif category == "osint":
        rows.append(_run_triage_command(["rg", "-n", r"https?://|domain|username|handle|coord|latitude|longitude|image|photo|email|@", "."], cwd=cwd, timeout=8))
    elif category == "ai/ml":
        rows.extend(
            [
                _run_triage_command(["find", ".", "-maxdepth", "5", "-type", "f", "(", "-name", "*.pt", "-o", "-name", "*.pth", "-o", "-name", "*.onnx", "-o", "-name", "*.pkl", "-o", "-name", "*.safetensors", "-o", "-name", "*.json", ")"], cwd=cwd, timeout=8),
                _run_triage_command(["rg", "-n", r"torch|tensorflow|sklearn|transformers|onnx|pickle|prompt|system|model|dataset|label", "."], cwd=cwd, timeout=8),
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
    if context.get("remote_endpoints"):
        findings.append(_finding("remote", "Remote endpoints in local metadata", "; ".join(str(value) for value in context["remote_endpoints"][:6])))

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
    if not context.get("remote_endpoints") and category in {"web", "pwn"}:
        steps.append("Find or record service connection info before remote testing.")
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
        lines.append(f"- `{row.get('command')}` status={_md(status)}{reason}")
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


def _save_challenge_triage_metadata(root: Path, board: dict[str, Any], challenge_id: str, metadata: Mapping[str, Any]) -> None:
    _save_challenge_local_metadata(root, board, challenge_id, "challenge_triage_metadata", "triage_metadata", metadata)


def _save_challenge_solver_metadata(root: Path, board: dict[str, Any], challenge_id: str, metadata: Mapping[str, Any]) -> None:
    _save_challenge_local_metadata(root, board, challenge_id, "challenge_solver_metadata", "solver_metadata", metadata)


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
PRIMARY_FILE = Path({json.dumps(data["primary_file"])}) if {json.dumps(bool(data["primary_file"]))} else None

'''


def _starter_web_source(data: Mapping[str, Any]) -> str:
    return _starter_header(data) + '''import re
import sys

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
    for endpoint in REMOTE_ENDPOINTS:
        if endpoint.startswith(("http://", "https://")):
            return endpoint.rstrip("/")
    return ""


def main() -> int:
    if requests is None:
        print("Install requests or port this skeleton to urllib.", file=sys.stderr)
        return 2
    session = requests.Session()
    base_url = candidate_base_url()
    if not base_url:
        print("TODO: set base_url from challenge statement or local service.", file=sys.stderr)
        return 1

    # TODO: map route/auth state from TOP_FILES and replace this probe.
    response = session.get(base_url, timeout=10)
    print(response.status_code)
    match = FLAG_RE.search(response.text)
    if match:
        print(match.group(0))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _starter_pwn_source(data: Mapping[str, Any]) -> str:
    return _starter_header(data) + '''from pwn import *  # type: ignore


context.log_level = "info"
if PRIMARY_FILE and PRIMARY_FILE.exists():
    elf = ELF(str(PRIMARY_FILE), checksec=False)
    context.binary = elf
else:
    elf = None


def start():
    if args.REMOTE:
        # TODO: replace with host/port from REMOTE_ENDPOINTS.
        host = args.HOST or "127.0.0.1"
        port = int(args.PORT or 31337)
        return remote(host, port)
    if not PRIMARY_FILE:
        raise SystemExit("Primary binary missing; inspect TOP_FILES.")
    return process([str(PRIMARY_FILE)])


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
    completed = subprocess.run(argv, cwd=CHALLENGE_DIR, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
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
        "## Remote",
    ]
    if context["remote_endpoints"]:
        lines.extend(f"- {_md(endpoint)}" for endpoint in context["remote_endpoints"])
    else:
        lines.append("- none detected")
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
        lines.append(f"- {key}: {_md('; '.join(playbook[key]))}")
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
            "- Local terminal output may include raw flags during solving; do not public paste, upload, commit, or publish flags, writeups, exploits, auth material, cookies, tokens, sessions, browser storage, or private keys during the contest.",
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
    commands.extend(playbook["first_commands"])
    category = str(playbook.get("category") or "")
    if category in {"pwn", "rev"}:
        first_binary = _first_top_file(context, categories={"binary", "shared_library"})
        if first_binary:
            commands.append(f"file {shlex.quote(first_binary)}")
            if category == "pwn":
                commands.append(f"checksec --file={shlex.quote(first_binary)} || true")
            commands.append(f"strings -a -n 4 {shlex.quote(first_binary)} | sed -n '1,120p'")
    elif category == "web":
        commands.append("rg -n \"route|app\\.|router\\.|render|template|session|jwt|cookie|upload|fetch|request|sql|eval|exec\" .")
    elif category == "crypto":
        commands.append("rg -n \"RSA|AES|ECC|ECDSA|CBC|CTR|GCM|modulus|cipher|decrypt|encrypt|random|seed|nonce\" .")
    elif category == "forensics/misc":
        commands.append("find raw handout extracted -maxdepth 3 -type f -print 2>/dev/null | xargs -r file")
    elif category == "osint":
        commands.append("rg -n \"https?://|@|coord|lat|lon|username|handle|domain\" .")
    elif category == "ai/ml":
        commands.append("find . -maxdepth 4 -type f \\( -name '*.ipynb' -o -name '*.pt' -o -name '*.pth' -o -name '*.onnx' -o -name '*.pkl' -o -name '*.safetensors' -o -name '*.json' \\) | sort")
    return _dedupe_strings(commands)[:14]


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
            "first_commands": ["file ./* raw/* handout/* extracted/**/* 2>/dev/null", "checksec --file ./chall 2>/dev/null || true", "python3 - <<'PY'\nfrom pwn import *\nprint('pwntools ok')\nPY"],
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
        "Do not paste raw auth, browser storage, cookies, tokens, sessions, private keys, or private artifacts into public services.",
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
        elif event in {"accepted", "solved", "external_solved"}:
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
        "solved_count": solved_count,
        "stalled_count": sum(1 for row in contest_events if row.get("event") == "stalled"),
        "submitted_count": sum(1 for row in contest_events if row.get("event") == "submit") + artifact_attempted_count,
        "accepted_count": accepted_count,
        "artifact_submitted_count": artifact_attempted_count,
        "artifact_accepted_count": artifact_accepted_count,
        "artifact_rejected_count": artifact_rejected_count,
        "artifact_blocked_count": artifact_blocked_count,
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
        if event in {"submit", "accepted", "solved", "external_solved", "artifact_submit_accepted"}:
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
        if event in {"attempt", "attempts"}:
            total += 1
            seen = True
        value = data.get("attempts_total") or data.get("attempt_count")
        if isinstance(value, (int, float)):
            total += int(value)
            seen = True
    return total if seen else None


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
        "solved_by_external": bool(item.get("solved_by_external")),
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


def _append_jsonl(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(redact_text(json.dumps(_redact_object(dict(data)), sort_keys=True)))
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
