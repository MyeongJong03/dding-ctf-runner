from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from .contest_control import contest_root, load_control
from .fake_ctfd import FakeCTFdServer, platform_config
from .ingest import ingest_challenge
from .multi_worker import _duplicate_claim_count, _submission_counts
from .paths import get_paths, repo_root
from .platform_base import action_to_dict
from .platform_ctfd import CTFdPlatform
from .redact import redact_text
from .state import init_db, list_status, update_challenge_ingested, upsert_platform_challenges, utc_now


SUPERVISOR_EVENT_FILE = "supervisor_events.jsonl"
SAFE_ENV_KEYS = {"CTF_RUN_MODE", "CTF_CONTEST_ID"}
SENSITIVE_ARG_HINTS = ("token", "cookie", "auth", "secret", "password", "storage_state", "storage-state")


def workers_root(contest_id: str, *, state_root: str | Path | None = None) -> Path:
    return contest_root(contest_id, state_root=state_root) / "workers"


def start_workers(
    contest_id: str,
    *,
    apply: bool = False,
    workers: int | None = None,
    solver: str = "mock",
    max_iterations: int | None = None,
    max_parallel_codex: int | None = None,
    sleep_sec: float = 2.0,
    stop_when_empty: bool = True,
    allow_codex_call: bool = False,
    postsolve: bool | None = None,
    live_submit: bool | None = None,
    confirm_submit: bool | None = None,
    platform_config_path: str | Path | None = None,
    db_path: str | Path | None = None,
    contests_root: str | Path | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    control = load_control(contest_id, state_root=state_root)
    armed = bool(control.get("armed"))
    fake_local = _is_fake_or_local_contest(contest_id)
    if apply and not armed and not fake_local:
        return {
            "status": "blocked",
            "reason": "contest_not_armed",
            "contest_id": contest_id,
            "armed": False,
            "launched": False,
            "required_flags": ["ctfctl contest arm --confirm-competition"],
        }
    count = _bounded_int(workers if workers is not None else control.get("max_workers"), default=5, minimum=1, maximum=10)
    solver = solver if solver in {"mock", "codex"} else "mock"
    control_run_mode = str(control.get("run_mode") or "setup")
    run_mode = "competition" if armed else ("rehearsal" if control_run_mode == "rehearsal" else "setup")
    max_parallel = _bounded_int(max_parallel_codex if max_parallel_codex is not None else control.get("max_parallel_codex"), default=2, minimum=1, maximum=count)
    profile_path = str(platform_config_path or control.get("profile_path") or "")
    live_submit_default = bool(run_mode == "competition" and armed and bool(control.get("allow_live_submit")))
    live_submit_requested = live_submit_default if live_submit is None else bool(live_submit)
    live_submit_enabled = bool(live_submit_requested and (fake_local or (armed and bool(control.get("allow_live_submit")))))
    confirm_submit_enabled = bool(confirm_submit) if confirm_submit is not None else live_submit_enabled
    command_items: list[dict[str, Any]] = []
    for index in range(1, count + 1):
        worker_id = f"worker-{index}"
        command = build_worker_loop_command(
            contest_id,
            worker_id,
            run_mode=run_mode,
            solver=solver,
            max_iterations=max_iterations,
            sleep_sec=sleep_sec,
            stop_when_empty=stop_when_empty,
            allow_codex_call=allow_codex_call,
            postsolve=postsolve,
            live_submit=live_submit_enabled,
            confirm_submit=confirm_submit_enabled,
            platform_config_path=profile_path,
            db_path=db_path,
            contests_root=contests_root,
            state_root=state_root,
        )
        item: dict[str, Any] = {
            "worker_id": worker_id,
            "command_redacted": command["command_redacted"],
            "env": command["env_public"],
            "mode": run_mode,
            "solver": solver,
            "live_submit": command["live_submit"],
            "confirm_submit": command["confirm_submit"],
            "postsolve": command["postsolve"],
            "max_iterations": command["max_iterations"],
            "log_path": _display_path(_worker_paths(contest_id, worker_id, state_root=state_root)["log"]),
        }
        if apply:
            started = start_worker_process(
                contest_id,
                worker_id,
                command["argv"],
                env=command["env"],
                metadata={
                    "mode": run_mode,
                    "solver": solver,
                    "max_iterations": command["max_iterations"],
                    "max_parallel_codex": max_parallel,
                    "live_submit": command["live_submit"],
                    "confirm_submit": command["confirm_submit"],
                    "postsolve": command["postsolve"],
                    "profile_path": profile_path,
                },
                state_root=state_root,
                cwd=repo_root(),
            )
            item.update(started)
        command_items.append(item)
    status = "started" if apply else "dry_run"
    payload = {
        "status": status,
        "contest_id": contest_id,
        "armed": armed,
        "run_mode": run_mode,
        "launched": bool(apply),
        "worker_count": count,
        "solver": solver,
        "max_parallel_codex": max_parallel,
        "live_submit_default": live_submit_default,
        "live_submit_requested": live_submit_requested,
        "live_submit_effective": live_submit_enabled,
        "confirm_submit_effective": confirm_submit_enabled,
        "workers": command_items,
        "paths": {"workers_root": _display_path(workers_root(contest_id, state_root=state_root))},
    }
    _write_event(contest_id, "start_workers", status, {"apply": apply, "workers": count, "solver": solver}, state_root=state_root)
    return _redact_object(payload)


def build_worker_loop_command(
    contest_id: str,
    worker_id: str,
    *,
    run_mode: str,
    solver: str,
    max_iterations: int | None,
    sleep_sec: float,
    stop_when_empty: bool,
    allow_codex_call: bool,
    postsolve: bool | None,
    live_submit: bool,
    confirm_submit: bool,
    platform_config_path: str | Path | None = None,
    db_path: str | Path | None = None,
    contests_root: str | Path | None = None,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    iterations = _default_max_iterations(max_iterations, run_mode)
    postsolve_enabled = bool(postsolve) if postsolve is not None else run_mode == "competition"
    argv = [sys.executable, "-m", "ctf_runner"]
    if db_path:
        argv.extend(["--db", str(Path(db_path).expanduser())])
    argv.extend(
        [
            "worker",
            "loop",
            "--worker-id",
            worker_id,
            "--solver",
            solver,
            "--mode",
            run_mode,
            "--contest-id",
            contest_id,
            "--max-iterations",
            str(iterations),
            "--sleep-sec",
            str(float(sleep_sec)),
            "--json",
        ]
    )
    if stop_when_empty:
        argv.append("--stop-when-empty")
    if allow_codex_call and solver == "codex":
        argv.append("--allow-codex-call")
    if run_mode == "competition":
        argv.append("--confirm-competition")
    if live_submit:
        argv.append("--live-submit")
    if confirm_submit:
        argv.append("--confirm-submit")
    if postsolve_enabled:
        argv.append("--postsolve")
    else:
        argv.append("--no-postsolve")
    if platform_config_path:
        argv.extend(["--platform-config", str(Path(platform_config_path).expanduser())])
    if contests_root:
        argv.extend(["--contests-root", str(Path(contests_root).expanduser())])
    if state_root:
        argv.extend(["--state-root", str(Path(state_root).expanduser())])
    env = {"CTF_RUN_MODE": run_mode, "CTF_CONTEST_ID": contest_id}
    return {
        "argv": argv,
        "command_redacted": _command_string(argv),
        "env": env,
        "env_public": dict(env),
        "max_iterations": iterations,
        "postsolve": postsolve_enabled,
        "live_submit": bool(live_submit),
        "confirm_submit": bool(confirm_submit),
    }


def start_worker_process(
    contest_id: str,
    worker_id: str,
    argv: list[str],
    *,
    env: Mapping[str, str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    state_root: str | Path | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    worker_id = _safe_worker_id(worker_id)
    paths = _worker_paths(contest_id, worker_id, state_root=state_root)
    paths["root"].mkdir(parents=True, exist_ok=True)
    existing = _status_for_worker(contest_id, worker_id, state_root=state_root)
    if existing.get("alive"):
        return {
            "status": "already_running",
            "pid": existing.get("pid"),
            "alive": True,
            "started": False,
            "log_path": existing.get("log_path"),
        }
    safe_env = {key: str(value) for key, value in (env or {}).items() if key in SAFE_ENV_KEYS}
    process_env = os.environ.copy()
    process_env.update(safe_env)
    started_at = utc_now()
    log_fh = paths["log"].open("ab")
    try:
        process = subprocess.Popen(
            argv,
            cwd=str(Path(cwd).expanduser()) if cwd else str(repo_root()),
            env=process_env,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log_fh.close()
    paths["pid"].write_text(str(process.pid), encoding="utf-8")
    command_record = {
        "worker_id": worker_id,
        "contest_id": contest_id,
        "argv": [_redact_arg(arg) for arg in argv],
        "command_redacted": _command_string(argv),
        "env": safe_env,
        "cwd": _display_path(Path(cwd).expanduser()) if cwd else _display_path(repo_root()),
        "created_at": started_at,
        "metadata": _redact_object(dict(metadata or {})),
    }
    _write_json(paths["command"], command_record)
    status = {
        "status": "running",
        "pid": process.pid,
        "worker_id": worker_id,
        "contest_id": contest_id,
        "started_at": started_at,
        "alive": True,
        "stale": False,
        "command_redacted": command_record["command_redacted"],
        "mode": (metadata or {}).get("mode"),
        "solver": (metadata or {}).get("solver"),
        "max_iterations": (metadata or {}).get("max_iterations"),
        "max_parallel_codex": (metadata or {}).get("max_parallel_codex"),
        "live_submit": bool((metadata or {}).get("live_submit")),
        "postsolve": bool((metadata or {}).get("postsolve")),
        "log_path": _display_path(paths["log"]),
    }
    _write_json(paths["status"], status)
    _write_event(contest_id, "worker_started", "running", {"worker_id": worker_id, "pid": process.pid}, state_root=state_root)
    return {
        "status": "started",
        "pid": process.pid,
        "alive": True,
        "started": True,
        "log_path": _display_path(paths["log"]),
    }


def stop_workers(
    contest_id: str,
    *,
    timeout_sec: float = 5.0,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    items = []
    for worker_id in _known_worker_ids(contest_id, state_root=state_root):
        items.append(stop_worker(contest_id, worker_id, timeout_sec=timeout_sec, state_root=state_root))
    status = "ok" if all(item.get("status") in {"stopped", "not_running", "stale", "exited"} for item in items) else "partial"
    _write_event(contest_id, "stop_workers", status, {"workers": len(items)}, state_root=state_root)
    return {"status": status, "contest_id": contest_id, "workers": items}


def stop_worker(
    contest_id: str,
    worker_id: str,
    *,
    timeout_sec: float = 5.0,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    worker_id = _safe_worker_id(worker_id)
    paths = _worker_paths(contest_id, worker_id, state_root=state_root)
    status = _status_for_worker(contest_id, worker_id, state_root=state_root)
    pid = _coerce_pid(status.get("pid"))
    if not pid:
        _mark_stopped(paths, worker_id, contest_id, "not_running", state_root=state_root)
        return {"status": "not_running", "worker_id": worker_id, "alive": False}
    if not _pid_alive(pid):
        current_status = str(status.get("status") or "")
        ended_status = current_status if current_status in {"exited", "stopped"} else ("exited" if current_status == "running" else "stale")
        _mark_stopped(paths, worker_id, contest_id, ended_status, state_root=state_root)
        return {"status": ended_status, "worker_id": worker_id, "pid": pid, "alive": False}
    _terminate_pid(pid, signal.SIGTERM)
    deadline = time.monotonic() + max(0.1, float(timeout_sec))
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            _mark_stopped(paths, worker_id, contest_id, "stopped", state_root=state_root)
            return {"status": "stopped", "worker_id": worker_id, "pid": pid, "alive": False}
        time.sleep(0.05)
    if _pid_alive(pid):
        _terminate_pid(pid, signal.SIGKILL)
    _mark_stopped(paths, worker_id, contest_id, "stopped", state_root=state_root)
    return {"status": "stopped", "worker_id": worker_id, "pid": pid, "alive": False, "forced": True}


def restart_worker(
    contest_id: str,
    worker_id: str,
    *,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    worker_id = _safe_worker_id(worker_id)
    paths = _worker_paths(contest_id, worker_id, state_root=state_root)
    command = _read_json(paths["command"])
    argv = command.get("argv") if isinstance(command, dict) else None
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return {"status": "blocked", "reason": "missing_worker_command", "worker_id": worker_id}
    stop = stop_worker(contest_id, worker_id, state_root=state_root)
    metadata = command.get("metadata") if isinstance(command.get("metadata"), dict) else {}
    started = start_worker_process(
        contest_id,
        worker_id,
        argv,
        env=command.get("env") if isinstance(command.get("env"), dict) else {},
        metadata=metadata,
        state_root=state_root,
        cwd=_expand_display_path(str(command.get("cwd") or repo_root())),
    )
    return {"status": "restarted", "worker_id": worker_id, "stop": stop, "start": started}


def worker_status(
    contest_id: str,
    *,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    workers = [_status_for_worker(contest_id, worker_id, state_root=state_root) for worker_id in _known_worker_ids(contest_id, state_root=state_root)]
    running = sum(1 for item in workers if item.get("alive"))
    stopped = sum(1 for item in workers if not item.get("alive"))
    errors = [item for item in workers if str(item.get("status") or "") in {"error", "failed"}]
    return {
        "status": "ok",
        "contest_id": contest_id,
        "running_worker_count": running,
        "stopped_worker_count": stopped,
        "worker_errors": len(errors),
        "workers": workers,
        "last_worker_event": _last_event(contest_id, state_root=state_root),
        "paths": {"workers_root": _display_path(workers_root(contest_id, state_root=state_root))},
    }


def supervisor_summary(contest_id: str, *, state_root: str | Path | None = None) -> dict[str, Any]:
    status = worker_status(contest_id, state_root=state_root)
    return {
        "running_worker_count": status["running_worker_count"],
        "stopped_worker_count": status["stopped_worker_count"],
        "worker_errors": status["worker_errors"],
        "last_worker_event": status["last_worker_event"],
        "logs_path": status["paths"]["workers_root"],
    }


def worker_logs(
    contest_id: str,
    worker_id: str,
    *,
    tail: int = 50,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    worker_id = _safe_worker_id(worker_id)
    path = _worker_paths(contest_id, worker_id, state_root=state_root)["log"]
    if not path.exists():
        return {"status": "missing", "contest_id": contest_id, "worker_id": worker_id, "lines": [], "log_path": _display_path(path)}
    lines = _tail_lines(path, max(1, min(int(tail), 1000)))
    return {
        "status": "ok",
        "contest_id": contest_id,
        "worker_id": worker_id,
        "tail": len(lines),
        "lines": [redact_text(line.rstrip("\n")) for line in lines],
        "log_path": _display_path(path),
    }


def run_supervisor_smoke(
    *,
    workers: int = 3,
    solver: str = "mock",
    fake_ctfd: bool = True,
    timeout_sec: float = 30.0,
    state_root: str | Path | None = None,
) -> dict[str, Any]:
    if not fake_ctfd:
        raise ValueError("supervisor-smoke currently supports only --fake-ctfd")
    count = _bounded_int(workers, default=3, minimum=1, maximum=10)
    run_root = _smoke_run_root()
    contests_root = run_root / "contests"
    database = run_root / "queue.sqlite3"
    telemetry_path = run_root / "events.jsonl"
    config_path = run_root / "platform.json"
    init_db(database)
    started = time.monotonic()
    contest_id = "local-fake"
    with FakeCTFdServer() as server:
        config = platform_config(server.base_url, contests_root)
        config["name"] = "local-fake"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(redact_text(json.dumps(config, indent=2, sort_keys=True)) + "\n", encoding="utf-8")
        platform = CTFdPlatform(config=config)
        discover = platform.discover_challenges(live=True)
        discover_payload = action_to_dict(discover)
        challenges = (discover_payload.get("details") or {}).get("challenges", []) if discover.status == "ok" else []
        state_save = upsert_platform_challenges(challenges, contest_id=contest_id, db_path=database)
        ingest_results = _download_and_ingest_all(platform, challenges, contest_id, database)
        start = start_workers(
            contest_id,
            apply=True,
            workers=count,
            solver=solver,
            max_iterations=1,
            sleep_sec=0.05,
            stop_when_empty=True,
            allow_codex_call=(solver == "codex"),
            postsolve=True,
            live_submit=True,
            confirm_submit=True,
            platform_config_path=config_path,
            db_path=database,
            contests_root=contests_root,
            state_root=state_root,
        )
        waited = _wait_for_workers(contest_id, timeout_sec=timeout_sec, state_root=state_root)
        stop = stop_workers(contest_id, state_root=state_root)
        queue = list_status(database)
        submission_counts = _submission_counts(database)
        duplicate_claims = _duplicate_claim_count(database)
        rendered = json.dumps(
            {
                "start": start,
                "waited": waited,
                "queue": queue,
                "submission_counts": submission_counts,
                "duplicate_claims": duplicate_claims,
            },
            sort_keys=True,
        )
        raw_leak_detected = any(flag in rendered for flag in server.correct_flags)
        summary = {
            "status": "ok" if waited.get("complete") and duplicate_claims == 0 and not raw_leak_detected else "error",
            "contest_id": contest_id,
            "run_root": _display_path(run_root),
            "db_path": _display_path(database),
            "workers_requested": count,
            "solver": solver,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "discover": {
                "status": discover_payload.get("status"),
                "challenge_count": (discover_payload.get("details") or {}).get("challenge_count"),
                "state_save": state_save,
            },
            "ingest_count": len(ingest_results),
            "start": start,
            "waited": waited,
            "stop": stop,
            "queue": queue,
            "submission_counts": submission_counts,
            "duplicate_claims": duplicate_claims,
            "raw_leak_detected": raw_leak_detected,
            "fake_ctfd": {
                "bind_host": "127.0.0.1",
                "challenge_count": len(server.fixtures),
                "request_count": len(server.request_log),
                "submission_counts": _counts(item["status"] for item in server.submission_log),
            },
        }
        return _redact_object(summary)


def _download_and_ingest_all(platform: CTFdPlatform, challenges: list[dict[str, Any]], contest_id: str, database: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in challenges:
        challenge_id = str(item.get("challenge_id") or item.get("id") or "").strip()
        if not challenge_id:
            continue
        download = platform.download_attachments(challenge_id, live=True)
        payload = action_to_dict(download)
        if download.status not in {"ok", "no_attachments"}:
            results.append({"challenge_id": challenge_id, "download": payload, "ingest": {"status": "skipped"}})
            continue
        ingest = ingest_challenge(
            challenge_id,
            input_paths=[download.details["fs_dest_dir"]],
            contest_id=contest_id,
            category=str(item.get("category") or ""),
            name=str(item.get("name") or challenge_id),
            output_root=platform.downloads_root,
        )
        state_save = update_challenge_ingested(challenge_id, ingest, db_path=database)
        results.append({"challenge_id": challenge_id, "download": payload, "ingest": {"status": ingest.get("status")}, "state_save": state_save})
    return results


def _wait_for_workers(contest_id: str, *, timeout_sec: float, state_root: str | Path | None) -> dict[str, Any]:
    deadline = time.monotonic() + max(1.0, float(timeout_sec))
    last = worker_status(contest_id, state_root=state_root)
    while time.monotonic() < deadline:
        last = worker_status(contest_id, state_root=state_root)
        if int(last.get("running_worker_count") or 0) == 0:
            return {"status": "ok", "complete": True, "worker_status": last}
        time.sleep(0.1)
    return {"status": "timeout", "complete": False, "worker_status": last}


def _status_for_worker(contest_id: str, worker_id: str, *, state_root: str | Path | None = None) -> dict[str, Any]:
    paths = _worker_paths(contest_id, worker_id, state_root=state_root)
    status = _read_json(paths["status"])
    if not status:
        pid = _coerce_pid(paths["pid"].read_text(encoding="utf-8").strip()) if paths["pid"].exists() else None
        status = {"status": "unknown" if pid else "missing", "pid": pid, "worker_id": worker_id, "contest_id": contest_id}
    pid = _coerce_pid(status.get("pid"))
    alive = bool(pid and _pid_alive(pid))
    status["alive"] = alive
    status["stale"] = bool(pid and not alive and status.get("status") in {"unknown", "missing"})
    if pid and not alive and status.get("status") == "running":
        status["status"] = "exited"
        _write_json(paths["status"], status)
    elif status["stale"]:
        status["status"] = "stale"
        _write_json(paths["status"], status)
    status["log_path"] = _display_path(paths["log"])
    return _redact_object(status)


def _known_worker_ids(contest_id: str, *, state_root: str | Path | None) -> list[str]:
    root = workers_root(contest_id, state_root=state_root)
    ids: set[str] = set()
    if root.exists():
        for path in root.glob("worker-*.status.json"):
            ids.add(path.name.removesuffix(".status.json"))
        for path in root.glob("worker-*.pid"):
            ids.add(path.name.removesuffix(".pid"))
    return sorted(ids, key=_worker_sort_key)


def _worker_paths(contest_id: str, worker_id: str, *, state_root: str | Path | None = None) -> dict[str, Path]:
    root = workers_root(contest_id, state_root=state_root)
    worker_id = _safe_worker_id(worker_id)
    return {
        "root": root,
        "pid": root / f"{worker_id}.pid",
        "status": root / f"{worker_id}.status.json",
        "log": root / f"{worker_id}.log",
        "command": root / f"{worker_id}.command.json",
        "events": root / SUPERVISOR_EVENT_FILE,
    }


def _write_event(contest_id: str, event_type: str, status: str, details: Mapping[str, Any], *, state_root: str | Path | None = None) -> None:
    path = workers_root(contest_id, state_root=state_root) / SUPERVISOR_EVENT_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "time": utc_now(),
        "event_type": event_type,
        "status": status,
        "details": _redact_object(dict(details)),
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_redact_object(payload), sort_keys=True))
        fh.write("\n")


def _last_event(contest_id: str, *, state_root: str | Path | None = None) -> dict[str, Any] | None:
    path = workers_root(contest_id, state_root=state_root) / SUPERVISOR_EVENT_FILE
    if not path.exists():
        return None
    try:
        lines = [line for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except OSError:
        return None
    if not lines:
        return None
    try:
        loaded = json.loads(lines[-1])
    except json.JSONDecodeError:
        return {"status": "unreadable"}
    return _redact_object(loaded)


def _mark_stopped(paths: dict[str, Path], worker_id: str, contest_id: str, status: str, *, state_root: str | Path | None) -> None:
    current = _read_json(paths["status"])
    current.update({"status": status, "alive": False, "stale": status == "stale", "stopped_at": utc_now(), "worker_id": worker_id, "contest_id": contest_id})
    _write_json(paths["status"], current)
    _write_event(contest_id, "worker_stopped", status, {"worker_id": worker_id}, state_root=state_root)


def _terminate_pid(pid: int, sig: signal.Signals) -> None:
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        return
    except OSError:
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    stat_path = Path("/proc") / str(pid) / "stat"
    try:
        parts = stat_path.read_text(encoding="utf-8", errors="replace").split()
        if len(parts) > 2 and parts[2] == "Z":
            return False
    except OSError:
        pass
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _coerce_pid(value: Any) -> int | None:
    try:
        pid = int(value)
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(_redact_object(dict(data)), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _tail_lines(path: Path, count: int) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[-count:]
    except OSError:
        return []


def _command_string(argv: list[str]) -> str:
    return redact_text(" ".join(_shell_quote(_redact_arg(arg)) for arg in argv))


def _redact_arg(value: Any) -> str:
    text = str(value)
    lowered = text.lower()
    if any(hint in lowered for hint in SENSITIVE_ARG_HINTS):
        return redact_text(text)
    return redact_text(text)


def _shell_quote(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _safe_worker_id(value: str) -> str:
    worker_id = str(value or "").strip()
    if not re.fullmatch(r"worker-[0-9]+", worker_id):
        raise ValueError("worker_id must look like worker-N")
    return worker_id


def _worker_sort_key(worker_id: str) -> tuple[int, str]:
    match = re.search(r"(\d+)$", worker_id)
    return (int(match.group(1)) if match else 0, worker_id)


def _is_fake_or_local_contest(contest_id: str) -> bool:
    lowered = str(contest_id or "").strip().lower()
    return lowered in {"fake", "fake_ctfd", "local", "localhost", "mock", "local-fake"} or lowered.startswith(("fake_", "fake-", "final-fake", "local_", "local-"))


def _default_max_iterations(value: int | None, run_mode: str) -> int:
    if value is not None:
        return max(0, int(value))
    return 0 if run_mode == "competition" else 1


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value) if value is not None else default
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def _smoke_run_root() -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    root = get_paths().state_root / "supervisor-smoke" / f"{stamp}-{int(time.time() * 1000) % 1000:03d}"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _expand_display_path(value: str) -> Path:
    if value.startswith("~/"):
        return Path.home() / value[2:]
    return Path(value).expanduser()


def _display_path(path: Path) -> str:
    try:
        return str(path.expanduser().resolve()).replace(str(Path.home()), "~", 1)
    except OSError:
        return str(path).replace(str(Path.home()), "~", 1)


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, Path):
        return _display_path(value)
    if isinstance(value, str):
        return redact_text(value)
    return value


def _counts(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts
