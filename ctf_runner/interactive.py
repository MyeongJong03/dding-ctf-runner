from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

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


def upload_submit(contest_id: str, *, challenge_id: str, artifact: str | Path, confirm: bool) -> dict[str, Any]:
    path = Path(artifact).expanduser()
    digest = _sha256_file(path) if path.exists() else ""
    payload = {
        "status": "blocked",
        "reason": "official_upload_endpoint_metadata_missing",
        "contest_id": contest_id,
        "challenge_id": challenge_id,
        "artifact": {
            "path": _display(path),
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
            "sha256": digest,
        },
        "confirm": bool(confirm),
    }
    return payload


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
    for row in contest_events:
        event = str(row.get("event") or "")
        data = row.get("data") if isinstance(row.get("data"), Mapping) else {}
        challenge_id = str(row.get("challenge_id") or "")
        timestamp = _parse_timestamp(str(row.get("timestamp") or ""))
        if event == "claim" and challenge_id and timestamp:
            claim_times.setdefault(challenge_id, timestamp)
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
        "submitted_count": sum(1 for row in contest_events if row.get("event") == "submit"),
        "accepted_count": accepted_count,
        "writeup_ko_count": writeup_ko,
        "writeup_en_count": writeup_en,
        "cleanup_count": sum(1 for row in contest_events if row.get("event") == "cleanup"),
        "tokens_total_observed": tokens_total if tokens_seen else None,
        "avg_time_to_solve_sec": round(sum(solve_durations) / len(solve_durations), 3) if solve_durations else None,
    }


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
