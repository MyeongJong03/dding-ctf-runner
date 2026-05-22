from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any, Mapping

from .paths import get_paths, repo_root
from .redact import redact_text
from .state import connect, init_db, utc_now


CONTROL_FIELDS = (
    "contest_id",
    "profile_path",
    "run_mode",
    "armed",
    "armed_at",
    "disarmed_at",
    "operator_confirmation",
    "allow_live_submit",
    "allow_instance_start",
    "max_workers",
    "max_parallel_codex",
    "notes",
)


def contest_root(contest_id: str, *, state_root: str | Path | None = None) -> Path:
    root = Path(state_root).expanduser() if state_root else get_paths().state_root
    return root / "contests" / _safe_slug(contest_id)


def control_paths(contest_id: str, *, state_root: str | Path | None = None) -> dict[str, str]:
    root = contest_root(contest_id, state_root=state_root)
    return {
        "root": _display_path(root),
        "control_json": _display_path(root / "control.json"),
        "arm_lock": _display_path(root / "arm.lock"),
        "disarm_log": _display_path(root / "disarm.log"),
        "worker_commands": _display_path(root / "worker_commands.sh"),
    }


def load_control(contest_id: str, *, state_root: str | Path | None = None) -> dict[str, Any]:
    contest_id = _require_contest_id(contest_id)
    path = contest_root(contest_id, state_root=state_root) / "control.json"
    if not path.exists():
        return _default_control(contest_id)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        loaded = {}
    if not isinstance(loaded, Mapping):
        loaded = {}
    control = _default_control(contest_id)
    for key in CONTROL_FIELDS:
        if key in loaded:
            control[key] = loaded[key]
    control["contest_id"] = contest_id
    control["profile_path"] = _display_profile_path(control.get("profile_path"))
    control["run_mode"] = _normalize_run_mode(control.get("run_mode"))
    control["armed"] = bool(control.get("armed")) and _arm_lock_active(contest_id, state_root=state_root)
    control["allow_live_submit"] = bool(control.get("allow_live_submit"))
    control["allow_instance_start"] = bool(control.get("allow_instance_start"))
    control["max_workers"] = _coerce_positive_int(control.get("max_workers"), 5)
    control["max_parallel_codex"] = _coerce_positive_int(control.get("max_parallel_codex"), 2)
    control["notes"] = redact_text(str(control.get("notes") or ""))
    return control


def arm_contest(
    contest_id: str,
    *,
    profile_path: str | Path,
    confirm_competition: bool,
    allow_live_submit: bool = False,
    allow_instance_start: bool = False,
    max_workers: int = 5,
    max_parallel_codex: int = 2,
    notes: str = "",
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    contest_id = _require_contest_id(contest_id)
    if not confirm_competition:
        return {
            "status": "blocked",
            "reason": "confirm_competition_required",
            "required_flags": ["--confirm-competition"],
            "control": load_control(contest_id, state_root=state_root),
            "paths": control_paths(contest_id, state_root=state_root),
        }
    root = contest_root(contest_id, state_root=state_root)
    root.mkdir(parents=True, exist_ok=True)
    now = utc_now()
    control = _default_control(contest_id)
    control.update(
        {
            "profile_path": _display_profile_path(profile_path),
            "run_mode": "competition",
            "armed": True,
            "armed_at": now,
            "disarmed_at": None,
            "operator_confirmation": "confirm-competition",
            "allow_live_submit": bool(allow_live_submit),
            "allow_instance_start": bool(allow_instance_start),
            "max_workers": _coerce_positive_int(max_workers, 5),
            "max_parallel_codex": _coerce_positive_int(max_parallel_codex, 2),
            "notes": redact_text(str(notes or "")),
        }
    )
    _write_json(root / "control.json", control)
    _write_json(
        root / "arm.lock",
        {
            "contest_id": contest_id,
            "armed_at": now,
            "profile_path": control["profile_path"],
            "allow_live_submit": control["allow_live_submit"],
            "allow_instance_start": control["allow_instance_start"],
        },
    )
    commands = worker_commands(contest_id, state_root=state_root)
    _write_worker_commands(root / "worker_commands.sh", commands.get("commands", []))
    return {"status": "armed", "control": control, "paths": control_paths(contest_id, state_root=state_root)}


def record_prestart(
    contest_id: str,
    *,
    profile_path: str | Path,
    run_mode: str,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    contest_id = _require_contest_id(contest_id)
    root = contest_root(contest_id, state_root=state_root)
    root.mkdir(parents=True, exist_ok=True)
    control = load_control(contest_id, state_root=state_root)
    control["profile_path"] = _display_profile_path(profile_path)
    if not control.get("armed"):
        control["run_mode"] = _normalize_run_mode(run_mode)
        control["armed"] = False
        control["allow_live_submit"] = False
        control["allow_instance_start"] = False
    _write_json(root / "control.json", control)
    commands = worker_commands(contest_id, state_root=state_root)
    _write_worker_commands(root / "worker_commands.sh", commands.get("commands", []))
    return control


def disarm_contest(
    contest_id: str,
    *,
    stop_workers: bool = False,
    cleanup_resources: bool = False,
    stop_docker_pool: bool = False,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    contest_id = _require_contest_id(contest_id)
    root = contest_root(contest_id, state_root=state_root)
    root.mkdir(parents=True, exist_ok=True)
    previous = load_control(contest_id, state_root=state_root)
    now = utc_now()
    control = dict(previous)
    control.update(
        {
            "run_mode": "rehearsal",
            "armed": False,
            "disarmed_at": now,
            "allow_live_submit": False,
            "allow_instance_start": False,
        }
    )
    _write_json(root / "control.json", control)
    try:
        (root / "arm.lock").unlink()
    except FileNotFoundError:
        pass
    with (root / "disarm.log").open("a", encoding="utf-8") as fh:
        fh.write(redact_text(json.dumps({"contest_id": contest_id, "disarmed_at": now, "previously_armed": bool(previous.get("armed"))}, sort_keys=True)))
        fh.write("\n")
    commands = worker_commands(contest_id, state_root=state_root)
    _write_worker_commands(root / "worker_commands.sh", commands.get("commands", []))
    worker_stop_result: dict[str, Any] | None = None
    warnings: list[str] = []
    if stop_workers:
        from .worker_supervisor import stop_workers as supervisor_stop_workers

        worker_stop_result = supervisor_stop_workers(contest_id, state_root=state_root)
    else:
        from .worker_supervisor import supervisor_summary

        summary = supervisor_summary(contest_id, state_root=state_root)
        if int(summary.get("running_worker_count") or 0) > 0:
            warnings.append("workers still running; rerun disarm with --stop-workers or use ctfctl contest stop-workers")
    resource_cleanup: dict[str, Any] | None = None
    from .contest_resources import cleanup_contest_resources, contest_resource_summary

    if cleanup_resources:
        resource_cleanup = cleanup_contest_resources(contest_id, state_root=state_root)
    else:
        resources = contest_resource_summary(contest_id, state_root=state_root)
        if int(resources.get("active_tunnel_count") or 0) > 0 or int(resources.get("active_callback_count") or 0) > 0:
            warnings.append("active callback/tunnel resources remain; rerun disarm with --cleanup-resources")
        elif int(resources.get("stale_resource_count") or 0) > 0:
            warnings.append("stale callback/tunnel resources remain; rerun disarm with --cleanup-resources")
    docker_cleanup: dict[str, Any] | None = None
    from .docker_pool import cleanup_containers, pool_status

    if stop_docker_pool:
        docker_cleanup = cleanup_containers(contest_id, state_root=state_root)
    else:
        docker_status = pool_status(contest_id, state_root=state_root)
        if int(docker_status.get("active_container_count") or 0) > 0:
            warnings.append("active docker pool containers remain; rerun disarm with --stop-docker-pool")
    return {
        "status": "disarmed",
        "control": control,
        "paths": control_paths(contest_id, state_root=state_root),
        "suggestion": "run ctfctl postsolve batch --contest-id <contest> --status solved --json; do not push public writeups during contest",
        "worker_stop": worker_stop_result,
        "resource_cleanup": resource_cleanup,
        "docker_cleanup": docker_cleanup,
        "warnings": warnings,
        "warning": "; ".join(warnings),
    }


def contest_status(
    contest_id: str,
    *,
    db_path: str | Path | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    contest_id = _require_contest_id(contest_id)
    control = load_control(contest_id, state_root=state_root)
    counts = _state_counts(contest_id, db_path=db_path)
    from .worker_supervisor import supervisor_summary

    worker_supervisor = supervisor_summary(contest_id, state_root=state_root)
    from .contest_resources import contest_resource_summary

    resource_summary = contest_resource_summary(contest_id, state_root=state_root)
    from .docker_pool import pool_status

    docker_status = pool_status(contest_id, state_root=state_root)
    docker_warnings = []
    if int(docker_status.get("active_container_count") or 0) == 0 and _pwn_rev_challenge_count(contest_id, db_path=db_path) > 0:
        docker_warnings.append("docker_pool_not_started")
    return {
        "status": "ok",
        "contest_id": contest_id,
        "armed": bool(control.get("armed")),
        "run_mode": control.get("run_mode"),
        "profile_path": control.get("profile_path"),
        "allow_live_submit": bool(control.get("allow_live_submit")),
        "allow_instance_start": bool(control.get("allow_instance_start")),
        "max_workers": int(control.get("max_workers") or 0),
        "max_parallel_codex": int(control.get("max_parallel_codex") or 0),
        "armed_at": control.get("armed_at"),
        "disarmed_at": control.get("disarmed_at"),
        "paths": control_paths(contest_id, state_root=state_root),
        "challenge_counts": counts["challenge_counts"],
        "submit_counts": counts["submit_counts"],
        "worker_counts": counts["worker_counts"],
        "active_claim_count": counts["active_claim_count"],
        "solved_count": counts["solved_count"],
        "postsolve_generated_count": counts["postsolve_generated_count"],
        "skill_candidate_count": counts["skill_candidate_count"],
        "archive_count": counts["archive_count"],
        "running_worker_count": worker_supervisor["running_worker_count"],
        "stopped_worker_count": worker_supervisor["stopped_worker_count"],
        "worker_errors": worker_supervisor["worker_errors"],
        "last_worker_event": worker_supervisor["last_worker_event"],
        "logs_path": worker_supervisor["logs_path"],
        "active_callback_count": resource_summary["active_callback_count"],
        "active_tunnel_count": resource_summary["active_tunnel_count"],
        "stale_resource_count": resource_summary["stale_resource_count"],
        "last_callback_hit_at": resource_summary["last_callback_hit_at"],
        "resource_warnings": resource_summary["resource_warnings"],
        "active_docker_container_count": int(docker_status.get("active_container_count") or 0),
        "docker_pool": docker_status,
        "docker_warnings": docker_warnings,
    }


def contest_guard_flags(
    contest_id: str | None,
    *,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    if not contest_id:
        return {
            "contest_id": "",
            "contest_armed": False,
            "allow_live_submit": False,
            "allow_instance_start": False,
            "profile_path": "",
        }
    control = load_control(contest_id, state_root=state_root)
    return {
        "contest_id": contest_id,
        "contest_armed": bool(control.get("armed")),
        "allow_live_submit": bool(control.get("allow_live_submit")),
        "allow_instance_start": bool(control.get("allow_instance_start")),
        "profile_path": control.get("profile_path") or "",
    }


def worker_commands(
    contest_id: str,
    *,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    contest_id = _require_contest_id(contest_id)
    control = load_control(contest_id, state_root=state_root)
    armed = bool(control.get("armed"))
    max_workers = min(_coerce_positive_int(control.get("max_workers"), 5), 5)
    max_parallel_codex = _coerce_positive_int(control.get("max_parallel_codex"), 2)
    env_parts = [f"CTF_CONTEST_ID={shlex.quote(contest_id)}"]
    if armed:
        env_parts.append("CTF_RUN_MODE=competition")
    commands: list[str] = []
    repo = repo_root()
    for index in range(1, max_workers + 1):
        wrapper = f"./scripts/ctf-worker-{index}"
        commands.append(f"cd {shlex.quote(str(repo))} && {' '.join(env_parts)} {wrapper}")
    return {
        "status": "ok",
        "contest_id": contest_id,
        "armed": armed,
        "run_mode_exported": "competition" if armed else None,
        "max_workers": max_workers,
        "max_parallel_codex": max_parallel_codex,
        "guidance": f"Start at most {max_parallel_codex} Codex worker terminals at a time.",
        "commands": commands,
        "paths": control_paths(contest_id, state_root=state_root),
    }


def start_workers_dry_run(contest_id: str, *, state_root: str | Path | None = None) -> dict[str, Any]:
    from .worker_supervisor import start_workers

    return start_workers(contest_id, apply=False, state_root=state_root)


def profile_path_from_control(contest_id: str | None, *, state_root: str | Path | None = None) -> str:
    if not contest_id:
        return ""
    control = load_control(contest_id, state_root=state_root)
    return str(control.get("profile_path") or "")


def _state_counts(contest_id: str, *, db_path: str | Path | None) -> dict[str, Any]:
    path = Path(db_path).expanduser() if db_path else get_paths().db_path
    if not path.exists():
        return {
            "challenge_counts": {},
            "submit_counts": {},
            "worker_counts": {},
            "active_claim_count": 0,
            "solved_count": 0,
            "postsolve_generated_count": 0,
            "skill_candidate_count": 0,
            "archive_count": 0,
            "db_exists": False,
        }
    init_db(path)
    with connect(path) as conn:
        challenge_counts = {
            row["status"]: row["count"]
            for row in conn.execute(
                "SELECT status, COUNT(*) AS count FROM challenges WHERE contest_id=? GROUP BY status",
                (contest_id,),
            ).fetchall()
        }
        submit_counts = {
            row["status"]: row["count"]
            for row in conn.execute(
                """
                SELECT s.status, COUNT(*) AS count
                FROM submissions s
                JOIN challenges c ON c.id = s.challenge_id
                WHERE c.contest_id=?
                GROUP BY s.status
                """,
                (contest_id,),
            ).fetchall()
        }
        worker_counts = {
            row["status"]: row["count"]
            for row in conn.execute("SELECT status, COUNT(*) AS count FROM workers GROUP BY status").fetchall()
        }
        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM claims cl
            JOIN challenges c ON c.id = cl.challenge_id
            WHERE c.contest_id=? AND cl.state='active'
            """,
            (contest_id,),
        ).fetchone()
        challenge_rows = [dict(item) for item in conn.execute("SELECT id, metadata FROM challenges WHERE contest_id=?", (contest_id,)).fetchall()]
    postsolve_counts = _postsolve_counts(contest_id, challenge_rows)
    return {
        "challenge_counts": challenge_counts,
        "submit_counts": submit_counts,
        "worker_counts": worker_counts,
        "active_claim_count": int(row["count"] if row else 0),
        "solved_count": int(challenge_counts.get("solved") or 0),
        **postsolve_counts,
        "db_exists": True,
    }


def _postsolve_counts(contest_id: str, challenge_rows: list[dict[str, Any]]) -> dict[str, int]:
    postsolve_generated = 0
    skill_candidates = 0
    archives = 0
    for row in challenge_rows:
        challenge_id = str(row.get("id") or "")
        challenge_dir = _challenge_dir_from_row(contest_id, challenge_id, row)
        postsolve_dir = challenge_dir / "postsolve"
        if (postsolve_dir / "postsolve_summary.json").exists():
            postsolve_generated += 1
        if (postsolve_dir / "skill_candidate.md").exists():
            skill_candidates += 1
        if (postsolve_dir / "archive").exists() or any(postsolve_dir.glob("archive.v*")):
            archives += 1
    return {
        "postsolve_generated_count": postsolve_generated,
        "skill_candidate_count": skill_candidates,
        "archive_count": archives,
    }


def _pwn_rev_challenge_count(contest_id: str, *, db_path: str | Path | None) -> int:
    path = Path(db_path).expanduser() if db_path else get_paths().db_path
    if not path.exists():
        return 0
    init_db(path)
    with connect(path) as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM challenges
            WHERE contest_id=? AND lower(COALESCE(category, '')) IN ('pwn', 'rev', 'reverse', 'reverse engineering', 'reversing', 'binary', 'pwn/rev')
            """,
            (contest_id,),
        ).fetchone()
    return int(row["count"] if row else 0)


def _challenge_dir_from_row(contest_id: str, challenge_id: str, row: Mapping[str, Any]) -> Path:
    metadata = {}
    raw = row.get("metadata")
    if isinstance(raw, str) and raw.strip():
        try:
            loaded = json.loads(raw)
            metadata = loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError:
            metadata = {}
    if metadata.get("challenge_dir"):
        return Path(str(metadata["challenge_dir"]).replace("~/", str(Path.home()) + "/", 1)).expanduser()
    return get_paths().contests_root / _safe_slug(contest_id) / _safe_slug(challenge_id)


def _default_control(contest_id: str) -> dict[str, Any]:
    return {
        "contest_id": contest_id,
        "profile_path": "",
        "run_mode": "setup",
        "armed": False,
        "armed_at": None,
        "disarmed_at": None,
        "operator_confirmation": "",
        "allow_live_submit": False,
        "allow_instance_start": False,
        "max_workers": 5,
        "max_parallel_codex": 2,
        "notes": "",
    }


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    if path.name == "control.json":
        payload = {key: data.get(key) for key in CONTROL_FIELDS if key in data}
    else:
        payload = dict(data)
    tmp.write_text(redact_text(json.dumps(payload, indent=2, sort_keys=True)) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _write_worker_commands(path: Path, commands: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    lines.extend(commands)
    lines.append("")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(redact_text("\n".join(lines)), encoding="utf-8")
    os.replace(tmp, path)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def _arm_lock_active(contest_id: str, *, state_root: str | Path | None) -> bool:
    return (contest_root(contest_id, state_root=state_root) / "arm.lock").exists()


def _require_contest_id(contest_id: str) -> str:
    value = str(contest_id or "").strip()
    if not value:
        raise ValueError("contest_id is required")
    return _safe_slug(value)


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "")).strip("._-")
    if not slug:
        raise ValueError("contest_id is required")
    return slug[:120]


def _normalize_run_mode(value: Any) -> str:
    raw = str(value or "setup").strip().lower()
    return raw if raw in {"setup", "rehearsal", "competition"} else "setup"


def _coerce_positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _display_profile_path(path: str | Path | None) -> str:
    if path in (None, ""):
        return ""
    return _display_path(Path(path).expanduser())


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)
