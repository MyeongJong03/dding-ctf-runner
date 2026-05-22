from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from .artifact_archive import archive_artifacts, collect_artifacts
from .paths import get_paths
from .redact import redact_text
from .state import connect, get_challenge, init_db, list_submissions, utc_now


POSTSOLVE_FILES = (
    "solve_summary.md",
    "writeup_draft.md",
    "skill_candidate.md",
    "artifacts_manifest.json",
    "timeline.jsonl",
    "postsolve_summary.json",
)


def generate_postsolve(
    contest_id: str,
    challenge_id: str,
    *,
    state: Mapping[str, Any] | None = None,
    result: Mapping[str, Any] | None = None,
    output_dir: str | Path | None = None,
    db_path: str | Path | None = None,
    require_solved: bool = True,
) -> dict[str, Any]:
    challenge_state = dict(state or {})
    if not challenge_state:
        challenge_state = get_challenge(challenge_id, db_path) or {}
    if not challenge_state:
        challenge_state = {"id": challenge_id, "contest_id": contest_id, "status": "unknown"}
    challenge_status = str(challenge_state.get("status") or "").lower()
    if require_solved and challenge_status != "solved":
        return {
            "status": "blocked",
            "reason": "challenge_not_solved",
            "contest_id": contest_id,
            "challenge_id": challenge_id,
            "challenge_status": challenge_status or "unknown",
        }

    result = result or _result_from_state(challenge_id, db_path=db_path)
    challenge_dir = Path(output_dir).expanduser().resolve() if output_dir else _default_challenge_dir(challenge_id, challenge_state, contest_id)
    postsolve_dir = challenge_dir / "postsolve"
    postsolve_dir.mkdir(parents=True, exist_ok=True)

    artifact_manifest = collect_artifacts(challenge_dir, _run_state(challenge_state, result))
    submit = _submit_summary(result)
    flag_hash = submit.get("flag_hash") or _first_flag_hash(result) or _first_submission_hash(challenge_id, db_path=db_path)
    worker_id = str(result.get("worker_id") or submit.get("worker_id") or submit.get("record", {}).get("worker_id") or "")
    timeline = _timeline_events(challenge_id, challenge_state, result, worker_id=worker_id)

    written: dict[str, str] = {}
    backups: dict[str, str] = {}

    solve_summary = _render_solve_summary(
        contest_id=contest_id,
        challenge_id=challenge_id,
        state=challenge_state,
        result=result,
        artifact_manifest=artifact_manifest,
        flag_hash=flag_hash,
        worker_id=worker_id,
    )
    write_result = _write_versioned(postsolve_dir / "solve_summary.md", solve_summary)
    written["solve_summary"] = _display_path(write_result["path"])
    if write_result.get("backup"):
        backups["solve_summary"] = _display_path(write_result["backup"])

    writeup = _render_writeup_draft(
        contest_id=contest_id,
        challenge_id=challenge_id,
        state=challenge_state,
        result=result,
        artifact_manifest=artifact_manifest,
        flag_hash=flag_hash,
    )
    write_result = _write_versioned(postsolve_dir / "writeup_draft.md", writeup)
    written["writeup_draft"] = _display_path(write_result["path"])
    if write_result.get("backup"):
        backups["writeup_draft"] = _display_path(write_result["backup"])

    skill_candidate = _render_skill_candidate(contest_id, challenge_id, challenge_state, result)
    write_result = _write_versioned(postsolve_dir / "skill_candidate.md", skill_candidate)
    written["skill_candidate"] = _display_path(write_result["path"])
    if write_result.get("backup"):
        backups["skill_candidate"] = _display_path(write_result["backup"])

    write_result = _write_json_versioned(postsolve_dir / "artifacts_manifest.json", artifact_manifest)
    written["artifacts_manifest"] = _display_path(write_result["path"])
    if write_result.get("backup"):
        backups["artifacts_manifest"] = _display_path(write_result["backup"])

    timeline_text = "".join(redact_text(json.dumps(event, sort_keys=True)) + "\n" for event in timeline)
    write_result = _write_versioned(postsolve_dir / "timeline.jsonl", timeline_text)
    written["timeline"] = _display_path(write_result["path"])
    if write_result.get("backup"):
        backups["timeline"] = _display_path(write_result["backup"])

    summary = {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_id,
        "challenge_status": challenge_status,
        "postsolve_dir": _display_path(postsolve_dir),
        "files": written,
        "path": written.get("solve_summary", ""),
        "backups": backups,
        "flag_hash": flag_hash or "",
        "raw_flag_present": bool(_flag_like("\n".join([solve_summary, writeup, skill_candidate, timeline_text]))),
        "artifact_counts": artifact_manifest.get("counts", {}),
        "public_upload": "forbidden_during_contest",
    }
    write_result = _write_json_versioned(postsolve_dir / "postsolve_summary.json", summary)
    summary["files"]["postsolve_summary"] = _display_path(write_result["path"])
    if write_result.get("backup"):
        summary["backups"]["postsolve_summary"] = _display_path(write_result["backup"])
    return _redact_object(summary)


def write_solve_summary(
    challenge_id: str,
    state: Mapping[str, Any] | None,
    result: Mapping[str, Any] | None,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    state = state or {}
    metadata = _metadata(state.get("metadata"))
    contest_id = str(state.get("contest_id") or metadata.get("contest_id") or "manual")
    generated = generate_postsolve(
        contest_id,
        challenge_id,
        state=state,
        result=result,
        output_dir=output_dir,
        require_solved=False,
    )
    return {
        "status": generated.get("status"),
        "path": (generated.get("files") or {}).get("solve_summary", ""),
        "postsolve_dir": generated.get("postsolve_dir", ""),
        "files": generated.get("files", {}),
        "flag_hash": generated.get("flag_hash", ""),
        "raw_flag_present": bool(generated.get("raw_flag_present")),
    }


def postsolve_status(
    contest_id: str,
    challenge_id: str,
    *,
    state: Mapping[str, Any] | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    challenge_state = dict(state or {})
    if not challenge_state:
        challenge_state = get_challenge(challenge_id, db_path) or {}
    challenge_dir = _default_challenge_dir(challenge_id, challenge_state, contest_id)
    postsolve_dir = challenge_dir / "postsolve"
    files = {name: _file_status(postsolve_dir / name) for name in POSTSOLVE_FILES}
    return {
        "status": "ok",
        "contest_id": contest_id,
        "challenge_id": challenge_id,
        "challenge_status": str(challenge_state.get("status") or "unknown"),
        "postsolve_dir": _display_path(postsolve_dir),
        "generated": all(item["exists"] for item in files.values()),
        "files": files,
    }


def archive_postsolve(
    contest_id: str,
    challenge_id: str,
    *,
    state: Mapping[str, Any] | None = None,
    db_path: str | Path | None = None,
    include_large: bool = False,
) -> dict[str, Any]:
    challenge_state = dict(state or {})
    if not challenge_state:
        challenge_state = get_challenge(challenge_id, db_path) or {}
    challenge_dir = _default_challenge_dir(challenge_id, challenge_state, contest_id)
    destination = challenge_dir / "postsolve" / "archive"
    result = archive_artifacts(challenge_dir, destination, include_large=include_large)
    return {
        "status": result.get("status"),
        "contest_id": contest_id,
        "challenge_id": challenge_id,
        "archive_dir": result.get("archive_dir"),
        "manifest_path": result.get("manifest_path"),
        "copied_count": result.get("copied_count"),
        "metadata_only_count": ((result.get("source_manifest") or {}).get("counts") or {}).get("metadata_only", 0),
        "skipped_count": ((result.get("source_manifest") or {}).get("counts") or {}).get("skipped", 0),
    }


def skill_candidates_for_contest(
    contest_id: str,
    *,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    challenge_dirs = _challenge_dirs_for_contest(contest_id, db_path=db_path)
    candidates = []
    for challenge_id, challenge_dir in challenge_dirs:
        path = challenge_dir / "postsolve" / "skill_candidate.md"
        if path.exists():
            candidates.append({"challenge_id": challenge_id, "path": _display_path(path), "size": path.stat().st_size})
    return {"status": "ok", "contest_id": contest_id, "count": len(candidates), "candidates": candidates}


def batch_generate_postsolve(
    contest_id: str,
    *,
    status: str = "solved",
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    rows = _challenge_rows_for_contest(contest_id, status=status, db_path=db_path)
    results = []
    for row in rows:
        challenge_id = str(row.get("id") or row.get("challenge_id") or "")
        if not challenge_id:
            continue
        results.append(generate_postsolve(contest_id, challenge_id, state=row, db_path=db_path, require_solved=(status == "solved")))
    return {"status": "ok", "contest_id": contest_id, "requested_status": status, "count": len(results), "results": results}


def _render_solve_summary(
    *,
    contest_id: str,
    challenge_id: str,
    state: Mapping[str, Any],
    result: Mapping[str, Any],
    artifact_manifest: Mapping[str, Any],
    flag_hash: str,
    worker_id: str,
) -> str:
    submit = _submit_summary(result)
    solver = _solver_result(result)
    lines = [
        "# Solve Summary",
        "",
        "## Challenge",
        f"- contest_id: {contest_id}",
        f"- id: {challenge_id}",
        f"- name: {redact_text(str(state.get('name') or ''))}",
        f"- category: {redact_text(str(state.get('category') or ''))}",
        f"- points: {state.get('points') if state.get('points') is not None else ''}",
        f"- status: {redact_text(str(state.get('status') or result.get('status') or 'unknown'))}",
        "",
        "## Worker",
        f"- worker_id: {redact_text(worker_id)}",
        f"- run_mode: {redact_text(str(result.get('run_mode') or ''))}",
        f"- target_kind: {redact_text(str(result.get('target_kind') or ''))}",
        "",
        "## Solve Source",
        f"- source: {redact_text(str((solver.get('confidence_context') or {}).get('source') or 'unknown'))}",
        f"- local_verified: {bool((solver.get('confidence_context') or {}).get('local_verified'))}",
        f"- summary: {redact_text(str(solver.get('summary') or result.get('summary') or ''))}",
        "",
        "## Files Used",
        *_file_lines(artifact_manifest),
        "",
        "## Submit Result",
        f"- status: {redact_text(str(submit.get('status') or result.get('submit_plan_status') or 'unknown'))}",
        f"- confidence: {redact_text(str(submit.get('confidence') or ''))}",
        f"- flag_hash: {redact_text(flag_hash or '')}",
        "- raw_flag: [REDACTED_FLAG]",
        "",
    ]
    return _safe_text("\n".join(lines))


def _render_writeup_draft(
    *,
    contest_id: str,
    challenge_id: str,
    state: Mapping[str, Any],
    result: Mapping[str, Any],
    artifact_manifest: Mapping[str, Any],
    flag_hash: str,
) -> str:
    solver = _solver_result(result)
    facts = solver.get("facts") or []
    attempts = solver.get("attempts") or []
    next_ideas = solver.get("next_ideas") or []
    lines = [
        "# Writeup Draft",
        "",
        "> Local-only draft. Do not publish or push during the contest. Raw flags are intentionally omitted.",
        "",
        "## Problem Summary",
        f"- contest_id: {contest_id}",
        f"- challenge_id: {challenge_id}",
        f"- name: {redact_text(str(state.get('name') or ''))}",
        f"- category: {redact_text(str(state.get('category') or ''))}",
        "",
        "## Approach",
        *_bullet_lines(facts, fallback="No detailed facts were recorded by the solver."),
        "",
        "## Core Idea",
        f"- {redact_text(str(solver.get('summary') or 'Review solver summary and local exploit artifacts.'))}",
        "",
        "## Commands Summary",
        *_bullet_lines(attempts, fallback="No command transcript was preserved; reconstruct from local scripts and shell-safe notes."),
        "",
        "## Exploit / Script References",
        *_path_reference_lines(artifact_manifest),
        "",
        "## Verification",
        f"- submit_status: {redact_text(str((_submit_summary(result)).get('status') or result.get('submit_plan_status') or 'unknown'))}",
        f"- flag_hash: {redact_text(flag_hash or '')}",
        "- flag: [REDACTED_FLAG]",
        "",
        "## Follow-up",
        *_bullet_lines(next_ideas, fallback="Review artifacts and convert this local draft into any required organizer format after the contest."),
        "",
    ]
    return _safe_text("\n".join(lines))


def _render_skill_candidate(contest_id: str, challenge_id: str, state: Mapping[str, Any], result: Mapping[str, Any]) -> str:
    solver = _solver_result(result)
    category = redact_text(str(state.get("category") or "unknown"))
    summary = redact_text(str(solver.get("summary") or ""))
    lines = [
        "# Skill Candidate",
        "",
        "## pattern title",
        f"- {category} pattern from {redact_text(str(state.get('name') or challenge_id))}",
        "",
        "## category",
        f"- {category}",
        "",
        "## trigger signs",
        *_bullet_lines((solver.get("facts") or [])[:5], fallback="Local solve produced a reusable-looking pattern; review artifacts manually."),
        "",
        "## solution sketch",
        f"- {summary or 'Summarize the reusable solve path after review.'}",
        "",
        "## reusable snippet",
        "```text",
        "Review local exploit/script artifacts and add a minimal sanitized snippet after the contest.",
        "```",
        "",
        "## avoid/false positives",
        "- Do not add challenge-specific constants, raw flags, credentials, cookies, tokens, or private URLs.",
        "- Confirm the pattern appears in more than one challenge before promoting it.",
        "",
        "## source challenge id",
        f"- contest_id: {contest_id}",
        f"- challenge_id: {challenge_id}",
        "",
    ]
    return _safe_text("\n".join(lines))


def _timeline_events(challenge_id: str, state: Mapping[str, Any], result: Mapping[str, Any], *, worker_id: str) -> list[dict[str, Any]]:
    now = utc_now()
    return [
        {
            "timestamp": now,
            "event_type": "postsolve_generate_started",
            "challenge_id": challenge_id,
            "worker_id": worker_id,
            "status": state.get("status") or result.get("status") or "unknown",
            "details": {"raw_flag_policy": "hash_only"},
        },
        {
            "timestamp": now,
            "event_type": "solver_summary",
            "challenge_id": challenge_id,
            "worker_id": worker_id,
            "status": (_solver_result(result)).get("status") or result.get("status") or "unknown",
            "details": {"summary": (_solver_result(result)).get("summary") or ""},
        },
        {
            "timestamp": now,
            "event_type": "submit_summary",
            "challenge_id": challenge_id,
            "worker_id": worker_id,
            "status": (_submit_summary(result)).get("status") or result.get("submit_plan_status") or "unknown",
            "details": {"flag_hash": (_submit_summary(result)).get("flag_hash") or _first_flag_hash(result) or ""},
        },
        {
            "timestamp": now,
            "event_type": "postsolve_generate_completed",
            "challenge_id": challenge_id,
            "worker_id": worker_id,
            "status": "ok",
            "details": {"files": list(POSTSOLVE_FILES)},
        },
    ]


def _result_from_state(challenge_id: str, *, db_path: str | Path | None) -> dict[str, Any]:
    submissions = list_submissions(challenge_id, db_path)
    submit_plans = []
    for item in submissions:
        submit_plans.append(
            {
                "status": item.get("status"),
                "confidence": item.get("confidence"),
                "flag_hash": item.get("flag_hash"),
                "worker_id": item.get("worker_id"),
            }
        )
    return {"status": "solved" if any(str(item.get("status")) == "accepted" for item in submissions) else "unknown", "submit_plans": submit_plans}


def _run_state(state: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "challenge_id": state.get("id") or state.get("challenge_id"),
        "contest_id": state.get("contest_id"),
        "status": state.get("status") or result.get("status"),
        "worker_id": result.get("worker_id"),
        "run_mode": result.get("run_mode"),
        "target_kind": result.get("target_kind"),
    }


def _default_challenge_dir(challenge_id: str, state: Mapping[str, Any], contest_id: str | None = None) -> Path:
    metadata = _metadata(state.get("metadata"))
    if metadata.get("challenge_dir"):
        return _expand_display_path(str(metadata["challenge_dir"])).resolve()
    contest = str(contest_id or state.get("contest_id") or metadata.get("contest_id") or "manual")
    return (get_paths().contests_root / _safe_slug(contest) / _safe_slug(challenge_id)).resolve()


def _submit_summary(result: Mapping[str, Any]) -> dict[str, Any]:
    for item in result.get("submit_plans") or []:
        if isinstance(item, Mapping) and str(item.get("status") or "").lower() == "accepted":
            return dict(item)
    for item in result.get("submit_plans") or []:
        if isinstance(item, Mapping):
            return dict(item)
    return {}


def _solver_result(result: Mapping[str, Any]) -> dict[str, Any]:
    solver = result.get("solver_result") if isinstance(result.get("solver_result"), Mapping) else {}
    return dict(solver)


def _first_flag_hash(result: Mapping[str, Any]) -> str:
    for item in (_solver_result(result)).get("flag_candidates") or []:
        if isinstance(item, Mapping) and item.get("flag_hash"):
            return str(item["flag_hash"])
    return ""


def _first_submission_hash(challenge_id: str, *, db_path: str | Path | None) -> str:
    for item in list_submissions(challenge_id, db_path):
        if item.get("flag_hash"):
            return str(item["flag_hash"])
    return ""


def _file_lines(artifact_manifest: Mapping[str, Any]) -> list[str]:
    files = []
    for section in ("exploits", "raw_attachments", "extracted", "logs"):
        for item in artifact_manifest.get(section) or []:
            if isinstance(item, Mapping):
                files.append(item)
    if not files:
        return ["- manifest: no local artifacts recorded"]
    lines = []
    for item in files[:12]:
        path = redact_text(str(item.get("path") or ""))
        digest = redact_text(str(item.get("sha256") or ""))
        size = item.get("size")
        line = f"- {path}"
        if size is not None:
            line += f" size={size}"
        if digest:
            line += f" sha256={digest}"
        lines.append(line)
    return lines


def _path_reference_lines(artifact_manifest: Mapping[str, Any]) -> list[str]:
    refs = []
    for section in ("exploits", "raw_attachments", "extracted"):
        for item in artifact_manifest.get(section) or []:
            if isinstance(item, Mapping):
                refs.append(f"- {redact_text(str(item.get('path') or ''))}")
    return refs[:12] or ["- No exploit or attachment path references were recorded."]


def _bullet_lines(items: Any, *, fallback: str) -> list[str]:
    if not isinstance(items, list) or not items:
        return [f"- {redact_text(fallback)}"]
    return [f"- {redact_text(str(item))}" for item in items[:12] if str(item).strip()] or [f"- {redact_text(fallback)}"]


def _challenge_rows_for_contest(contest_id: str, *, status: str, db_path: str | Path | None) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM challenges
            WHERE contest_id=? AND status=?
            ORDER BY updated_at DESC, id ASC
            """,
            (contest_id, status),
        ).fetchall()
    return [dict(row) for row in rows]


def _challenge_dirs_for_contest(contest_id: str, *, db_path: str | Path | None) -> list[tuple[str, Path]]:
    rows = _challenge_rows_for_contest(contest_id, status="solved", db_path=db_path)
    if rows:
        return [(str(row.get("id") or ""), _default_challenge_dir(str(row.get("id") or ""), row, contest_id)) for row in rows]
    base = get_paths().contests_root / _safe_slug(contest_id)
    if not base.exists():
        return []
    return [(path.name, path) for path in sorted(base.iterdir()) if path.is_dir()]


def _file_status(path: Path) -> dict[str, Any]:
    return {"path": _display_path(path), "exists": path.exists(), "size": path.stat().st_size if path.exists() else 0}


def _write_versioned(path: Path, content: str) -> dict[str, Path | None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = _backup_existing(path)
    path.write_text(_safe_text(content), encoding="utf-8")
    return {"path": path, "backup": backup}


def _write_json_versioned(path: Path, data: Mapping[str, Any]) -> dict[str, Path | None]:
    return _write_versioned(path, redact_text(json.dumps(_redact_object(dict(data)), indent=2, sort_keys=True)) + "\n")


def _backup_existing(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = utc_now().replace(":", "").replace("+", "Z").replace(".", "_")
    backup = path.with_name(f"{path.name}.bak.{stamp}")
    index = 1
    while backup.exists():
        backup = path.with_name(f"{path.name}.bak.{stamp}.{index}")
        index += 1
    path.rename(backup)
    return backup


def _safe_text(text: str) -> str:
    return redact_text(text).rstrip() + "\n"


def _metadata(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and value.strip():
        try:
            loaded = json.loads(value)
            return dict(loaded) if isinstance(loaded, Mapping) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip()).strip("._-")
    return slug[:120] or "unknown"


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _expand_display_path(raw: str) -> Path:
    return Path(raw.replace("~/", str(Path.home()) + "/", 1)).expanduser()


def _flag_like(text: str) -> str | None:
    match = re.search(r"\b[A-Za-z0-9_]{2,32}\{[^{}\s]{4,256}\}", text)
    return match.group(0) if match else None


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
