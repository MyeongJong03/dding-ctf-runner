from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
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
    existing = {str(item.get("challenge_id")): dict(item) for item in board.get("challenges", []) if item.get("challenge_id")}
    for item in canonical["challenges"]:
        previous = existing.get(item["challenge_id"], {})
        merged = {**previous, **item}
        merged.setdefault("status", previous.get("status") or "todo")
        merged["path"] = _challenge_path(contest_id, merged).as_posix()
        existing[item["challenge_id"]] = merged
        _ensure_challenge_memos(_challenge_path(contest_id, merged))

    board["profile_path"] = _display(Path(profile).expanduser())
    board["updated_at"] = utc_now()
    board["challenges"] = sorted(existing.values(), key=lambda row: (int(row.get("priority") or 100), str(row.get("name") or "")))
    _apply_runtime_statuses(root, board)
    _write_board(root, board)
    _write_board_md(root, board)

    download_results: list[dict[str, Any]] = []
    ingest_results: list[dict[str, Any]] = []
    if live and (download or ingest):
        for challenge in board["challenges"]:
            if challenge.get("is_alias") or challenge.get("is_static_alias"):
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
        "challenge_count": len(board["challenges"]),
        "target_count": sum(1 for item in board["challenges"] if not item.get("is_alias") and not item.get("is_static_alias")),
        "alias_count": sum(1 for item in board["challenges"] if item.get("is_alias") or item.get("is_static_alias")),
        "canonical_map": canonical["map"],
        "warnings": sorted(set(warnings + canonical["warnings"])),
        "discover": discover_payload,
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
    return {
        "status": "ok",
        "contest_id": contest_id,
        "operator_root": _display(root),
        "counts": {key: len(value) for key, value in buckets.items()},
        "challenges": buckets,
    }


def claim_challenge(
    contest_id: str,
    *,
    agent: str,
    challenge: str | None = None,
    allow_duplicate: bool = False,
) -> dict[str, Any]:
    init_operator(contest_id)
    root = operator_root(contest_id)
    board = _read_board(root, contest_id)
    _apply_runtime_statuses(root, board)
    if challenge:
        wanted = _normalize(challenge)
        item = next((row for row in board.get("challenges", []) if wanted in _challenge_keys(row)), None)
        if item is None:
            return {"status": "empty", "contest_id": contest_id, "reason": "challenge_not_found"}
        status = _challenge_status(root, item)
        if status in {"solved", "stalled", "skipped"}:
            return {"status": "empty", "contest_id": contest_id, "reason": f"challenge_{status}", "challenge_id": item.get("challenge_id")}
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
    line = str(item.get("challenge_id") or item.get("name") or challenge)
    existing = {row.strip() for row in (root / "external_solved.txt").read_text(encoding="utf-8").splitlines() if row.strip()}
    if line not in existing:
        _append_text(root / "external_solved.txt", line + "\n")
    item["status"] = "external_solved"
    released = _release_locks(root, agent=None, challenge=challenge)
    _write_board(root, board)
    _write_board_md(root, board)
    _record_metrics_event(root, contest_id=contest_id, event="external_solved", challenge_id=str(item.get("challenge_id") or challenge), data={"released_count": released})
    return {"status": "ok", "contest_id": contest_id, "challenge_id": item.get("challenge_id"), "released_count": released}


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
        _release_locks(root, agent=None, challenge=str(item.get("challenge_id") or challenge_id))
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
            _release_locks(root, agent=None, challenge=challenge_key)
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
- Do not solve one challenge and stop. Continue claim -> solve -> verify -> submit -> writeup -> cleanup -> next challenge until the contest ends, the user stops you, or no claimable work remains.
- Do not split into controller/solver roles. This Codex session is the solver.
- Keep user-facing progress compact unless the user asks for detail.
- Local terminal output may include flags, solver output, and exploit output when needed for solving and verification.
- Do not publish or upload flags, writeups, exploits, tokens, cookies, sessions, browser storage, private keys, or auth material to public services, public repositories, public pastes, issue trackers, or external writeup locations during the contest.

Coordination:
- Claim with: ctfctl interactive claim --contest-id {contest_id} --agent {agent} --json.
- Same-machine duplicate claims are blocked by default. Use --allow-duplicate only when the user explicitly wants duplicate solving.
- If stuck, update self memos and run ctfctl interactive stalled with a compact reason.
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
        if item.get("is_static_alias"):
            notes.append("static alias")
        if item.get("is_alias"):
            notes.append(f"alias of {item.get('canonical_id')}")
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
    canonical_by_key: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for item in raw:
        base = _canonical_name(str(item.get("name") or item.get("challenge_id") or ""))
        key = _normalize(base)
        existing = canonical_by_key.get(key)
        is_static = _is_static_alias(item)
        if existing is None or (existing.get("is_static_alias") and not is_static):
            canonical = dict(item)
            canonical["canonical_id"] = canonical.get("challenge_id")
            canonical["is_alias"] = False
            canonical["is_static_alias"] = is_static
            canonical["aliases"] = []
            canonical_by_key[key] = canonical
            existing = canonical
        if item.get("challenge_id") != existing.get("challenge_id"):
            alias = dict(item)
            alias["canonical_id"] = existing.get("challenge_id")
            alias["is_alias"] = True
            alias["is_static_alias"] = True if is_static else bool(alias.get("is_static_alias"))
            alias["status"] = "skipped"
            existing.setdefault("aliases", []).append(alias.get("challenge_id"))
            warnings.append(f"alias:{alias.get('challenge_id')}->{existing.get('challenge_id')}")
            canonical_by_key[_normalize(str(alias.get("challenge_id")))] = alias
    result = list(canonical_by_key.values())
    return {"challenges": result, "map": {str(item.get("challenge_id")): str(item.get("canonical_id") or item.get("challenge_id")) for item in result}, "warnings": warnings}


def _challenge_from_source(item: Mapping[str, Any]) -> dict[str, Any]:
    challenge_id = str(item.get("challenge_id") or item.get("id") or item.get("slug") or item.get("name") or "").strip()
    name = str(item.get("name") or challenge_id).strip()
    metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
    return {
        "challenge_id": challenge_id,
        "name": name,
        "category": str(item.get("category") or metadata.get("category") or ""),
        "points": item.get("points") or item.get("value"),
        "solves": item.get("solves"),
        "statement": redact_text(str(item.get("statement") or item.get("description") or metadata.get("statement") or "")),
        "has_files": bool(item.get("has_files") or item.get("file_count") or item.get("_attachments_private")),
        "tags": list(item.get("tags") or []),
        "priority": 100,
        "status": "todo",
    }


def _canonical_name(value: str) -> str:
    lowered = value.strip()
    lowered = re.sub(r"[-_\s]*static$", "", lowered, flags=re.IGNORECASE)
    known = {
        "birdhouse": "Birdhouse",
        "myfavoriteinstructions": "My Favorite Instructions",
        "favoriteinstructions": "My Favorite Instructions",
        "stork": "Stork",
        "twobirdtwocan": "2bird2can",
        "2bird2can": "2bird2can",
        "waybirdmachine": "Waybird Machine",
        "livectf": "LiveCTF",
        "livectfphase1": "LiveCTF",
        "favorite": "Favorite",
    }
    compact = _normalize(lowered)
    if compact in known:
        return known[compact]
    return re.sub(r"[_-]+", " ", lowered).strip().title()


def _is_static_alias(item: Mapping[str, Any]) -> bool:
    ident = str(item.get("challenge_id") or item.get("name") or "").lower()
    statement = str(item.get("statement") or "").strip().lower()
    if ident.endswith("-static") or ident in {"favorite-static", "favoriteinstructions", "twobirdtwocan", "waybird-machine", "stork"}:
        return True
    if len(statement) < 80 and any(token in statement for token in ("favicon", ".css", "stylesheet")):
        return True
    return False


def _challenge_text_for_ingest(challenge: Mapping[str, Any]) -> str:
    return redact_text(str(challenge.get("statement") or "").strip())


def _apply_runtime_statuses(root: Path, board: dict[str, Any]) -> None:
    solved_ids = {str(row.get("challenge_id")) for row in _read_jsonl(root / "solved.jsonl") if row.get("challenge_id")}
    external = {line.strip() for line in (root / "external_solved.txt").read_text(encoding="utf-8").splitlines() if line.strip()} if (root / "external_solved.txt").exists() else set()
    stalled = {str(row.get("challenge_id")) for row in _read_jsonl(root / "stalled.jsonl") if row.get("challenge_id")}
    claimed = _claimed_ids(root)
    for item in board.get("challenges", []):
        cid = str(item.get("challenge_id") or "")
        if cid in solved_ids:
            item["status"] = "solved"
        elif cid in external or str(item.get("name") or "") in external:
            item["status"] = "external_solved"
        elif cid in stalled:
            item["status"] = "stalled"
        elif cid in claimed:
            item["status"] = "claimed"
        elif item.get("is_alias") or item.get("is_static_alias"):
            item["status"] = "skipped"
        elif item.get("status") in {"solved", "external_solved", "stalled", "claimed", "skipped"}:
            continue
        else:
            item["status"] = "todo"


def _claimable(root: Path, item: Mapping[str, Any]) -> bool:
    return _challenge_status(root, item) == "todo" and not item.get("is_alias") and not item.get("is_static_alias")


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
    for path in (root / "claims").glob("*.lock"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        if agent and str(data.get("agent")) != agent:
            continue
        if challenge and _normalize(challenge) not in {_normalize(str(data.get("challenge_id") or "")), _normalize(str(data.get("name") or ""))}:
            continue
        _unlink(path)
        count += 1
    return count


def _find_challenge(board: Mapping[str, Any], challenge: str) -> dict[str, Any] | None:
    wanted = _normalize(challenge)
    for item in board.get("challenges", []):
        if wanted in _challenge_keys(item):
            return item
    return None


def _challenge_keys(item: Mapping[str, Any]) -> set[str]:
    keys = {_normalize(str(item.get("challenge_id") or "")), _normalize(str(item.get("name") or "")), _normalize(str(item.get("canonical_id") or ""))}
    keys.update(_normalize(str(alias)) for alias in item.get("aliases") or [])
    return {key for key in keys if key}


def _challenge_path(contest_id: str, item: Mapping[str, Any]) -> Path:
    category = _safe_slug(str(item.get("category") or "misc"))
    name = _safe_slug(str(item.get("name") or item.get("challenge_id") or "challenge"))
    return get_paths().contests_root / _safe_slug(contest_id) / category / name


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
            "alias_count",
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
    }


def _public_action(action: Any) -> dict[str, Any]:
    return _redact_object(action_to_dict(action))


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact_text(json.dumps(data, indent=2, sort_keys=True)) + "\n", encoding="utf-8")


def _append_jsonl(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(redact_text(json.dumps(_redact_object(dict(data)), sort_keys=True)))
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
