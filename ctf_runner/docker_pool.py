from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .paths import get_paths, is_under_mnt_c
from .redact import redact_text
from .state import utc_now


DEFAULT_IMAGE = "ctf-pwn:latest"
POOL_LABEL = "dding.ctf-runner"
CONTEST_LABEL = "dding.contest_id"
WORKER_LABEL = "dding.worker_id"
DOCKER_DESKTOP_CLI = Path("/mnt/wsl/docker-desktop/cli-tools/usr/bin/docker")
_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SENSITIVE_ARG_MARKERS = ("token", "cookie", "auth", "secret", "password", "storage_state", "storage-state", "private_key")
_Runner = Callable[..., subprocess.CompletedProcess[str]]


def container_name(contest_id: str, worker_id: str | None = None) -> str:
    """Return the persistent pool container name.

    The two-argument form is the Phase 13 interface. A one-argument call is
    kept for older tests/scripts and maps to the pre-Phase-13 worker-only name.
    """
    if worker_id is None:
        worker = _safe_slug(contest_id, "worker_id")
        return f"ctf-runner-{worker}"
    contest = _safe_slug(contest_id, "contest_id")
    worker = _safe_slug(worker_id, "worker_id")
    return f"ctf-runner-{contest}-{worker}"


def docker_pool_root(contest_id: str, *, state_root: str | Path | None = None) -> Path:
    root = Path(state_root).expanduser() if state_root else get_paths().state_root
    return root / "contests" / _safe_slug(contest_id, "contest_id") / "docker"


def default_workspace(contest_id: str, worker_id: str) -> Path:
    return get_paths().docker_workspace_root / _safe_slug(contest_id, "contest_id") / _safe_slug(worker_id, "worker_id")


def build_start_command(
    contest_id: str,
    worker_id: str,
    *,
    image: str = DEFAULT_IMAGE,
    workspace: str | Path | None = None,
    readonly_mounts: Sequence[tuple[str | Path, str]] | None = None,
) -> list[str]:
    name = container_name(contest_id, worker_id)
    workspace_path = _workspace_path(contest_id, worker_id, workspace)
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--label",
        f"{POOL_LABEL}=1",
        "--label",
        f"{CONTEST_LABEL}={_safe_slug(contest_id, 'contest_id')}",
        "--label",
        f"{WORKER_LABEL}={_safe_slug(worker_id, 'worker_id')}",
        "-v",
        f"{workspace_path}:/workspace",
        "-w",
        "/workspace",
    ]
    for host, target in readonly_mounts or ():
        host_path = Path(host).expanduser().resolve()
        if not str(target).startswith("/"):
            raise ValueError("readonly mount target must be an absolute container path")
        cmd.extend(["-v", f"{host_path}:{target}:ro"])
    cmd.extend([str(image or DEFAULT_IMAGE), "sleep", "infinity"])
    _assert_no_secret_env(cmd)
    return cmd


def build_exec_command(contest_id: str, worker_id: str, command: str) -> list[str]:
    cmd = ["docker", "exec", container_name(contest_id, worker_id), "bash", "-lc", str(command)]
    _assert_no_secret_env(cmd)
    return cmd


def build_stop_command(contest_id: str, worker_id: str) -> list[str]:
    return ["docker", "rm", "-f", container_name(contest_id, worker_id)]


def start_container(
    contest_id: str,
    worker_id: str,
    image: str = DEFAULT_IMAGE,
    workspace: str | Path | None = None,
    *,
    readonly_mounts: Sequence[tuple[str | Path, str]] | None = None,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    contest_id = _safe_slug(contest_id, "contest_id")
    worker_id = _safe_slug(worker_id, "worker_id")
    name = container_name(contest_id, worker_id)
    workspace_path = _workspace_path(contest_id, worker_id, workspace)
    workspace_path.mkdir(parents=True, exist_ok=True)
    existing = status_container(contest_id, worker_id, state_root=state_root, runner=runner)
    if existing.get("status") == "running":
        return {
            "status": "already_running",
            "contest_id": contest_id,
            "worker_id": worker_id,
            "container_name": name,
            "workspace": _display_path(workspace_path),
            "state": existing.get("state"),
        }
    if existing.get("status") in {"created", "exited", "dead"}:
        _run_docker(build_stop_command(contest_id, worker_id), timeout=timeout, runner=runner)
    command = build_start_command(
        contest_id,
        worker_id,
        image=image,
        workspace=workspace_path,
        readonly_mounts=readonly_mounts,
    )
    started_at = utc_now()
    result = _run_docker(command, timeout=timeout, runner=runner)
    status = "running" if result["returncode"] == 0 else "error"
    state = _merge_worker_state(
        contest_id,
        worker_id,
        state_root=state_root,
        update={
            "container_name": name,
            "worker_id": worker_id,
            "contest_id": contest_id,
            "image": str(image or DEFAULT_IMAGE),
            "workspace": _display_path(workspace_path),
            "status": status,
            "started_at": started_at if status == "running" else None,
            "stopped_at": None,
            "last_exec_at": None,
            "exec_count": 0,
            "average_exec_ms": 0.0,
        },
    )
    payload = {
        "status": status,
        "contest_id": contest_id,
        "worker_id": worker_id,
        "container_name": name,
        "image": str(image or DEFAULT_IMAGE),
        "workspace": _display_path(workspace_path),
        "workspace_warning": "workspace_under_mnt_c" if is_under_mnt_c(workspace_path) else "",
        "command_redacted": _command_string(command),
        "returncode": result["returncode"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "state": state,
    }
    _write_worker_status(contest_id, worker_id, state, state_root=state_root)
    _write_event(contest_id, "container_start", status, payload, state_root=state_root)
    return _redact_object(payload)


def exec_in_container(
    contest_id: str,
    worker_id: str,
    command: str,
    timeout: float = 120.0,
    *,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
) -> dict[str, Any]:
    contest_id = _safe_slug(contest_id, "contest_id")
    worker_id = _safe_slug(worker_id, "worker_id")
    docker_cmd = build_exec_command(contest_id, worker_id, command)
    start = time.perf_counter()
    result = _run_docker(docker_cmd, timeout=timeout, runner=runner)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    status = "ok" if result["returncode"] == 0 else "error"
    previous = _worker_state(contest_id, worker_id, state_root=state_root)
    previous_count = int(previous.get("exec_count") or 0)
    previous_avg = float(previous.get("average_exec_ms") or 0.0)
    exec_count = previous_count + 1
    average = round(((previous_avg * previous_count) + elapsed_ms) / exec_count, 2)
    state = _merge_worker_state(
        contest_id,
        worker_id,
        state_root=state_root,
        update={
            "container_name": container_name(contest_id, worker_id),
            "worker_id": worker_id,
            "contest_id": contest_id,
            "image": previous.get("image") or DEFAULT_IMAGE,
            "workspace": previous.get("workspace") or _display_path(default_workspace(contest_id, worker_id)),
            "status": "running" if status == "ok" else str(previous.get("status") or "unknown"),
            "last_exec_at": utc_now(),
            "exec_count": exec_count,
            "average_exec_ms": average,
        },
    )
    payload = {
        "status": status,
        "contest_id": contest_id,
        "worker_id": worker_id,
        "container_name": container_name(contest_id, worker_id),
        "command_redacted": _command_string(docker_cmd),
        "returncode": result["returncode"],
        "elapsed_ms": elapsed_ms,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "exec_count": exec_count,
        "average_exec_ms": average,
    }
    _write_worker_status(contest_id, worker_id, state, state_root=state_root)
    _append_exec_log(contest_id, worker_id, payload, state_root=state_root)
    _write_event(contest_id, "container_exec", status, payload, state_root=state_root)
    return _redact_object(payload)


def stop_container(
    contest_id: str,
    worker_id: str | None = None,
    *,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
    timeout: float = 20.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    if worker_id is None:
        legacy_worker = _safe_slug(contest_id, "worker_id")
        cmd = ["docker", "rm", "-f", container_name(legacy_worker)]
        if dry_run:
            return {"planned": True, "container": container_name(legacy_worker), "cmd": cmd}
        result = _run_docker(cmd, timeout=timeout, runner=runner)
        return {"planned": False, "container": container_name(legacy_worker), **result}

    contest_id = _safe_slug(contest_id, "contest_id")
    worker_id = _safe_slug(worker_id, "worker_id")
    cmd = build_stop_command(contest_id, worker_id)
    result = _run_docker(cmd, timeout=timeout, runner=runner)
    not_found = result["returncode"] != 0 and _looks_missing(result["stderr"])
    status = "not_running" if not_found else ("stopped" if result["returncode"] == 0 else "error")
    previous = _worker_state(contest_id, worker_id, state_root=state_root)
    state = _merge_worker_state(
        contest_id,
        worker_id,
        state_root=state_root,
        update={
            "container_name": container_name(contest_id, worker_id),
            "worker_id": worker_id,
            "contest_id": contest_id,
            "image": previous.get("image") or DEFAULT_IMAGE,
            "workspace": previous.get("workspace") or _display_path(default_workspace(contest_id, worker_id)),
            "status": status,
            "stopped_at": utc_now() if status in {"stopped", "not_running"} else previous.get("stopped_at"),
        },
    )
    payload = {
        "status": status,
        "contest_id": contest_id,
        "worker_id": worker_id,
        "container_name": container_name(contest_id, worker_id),
        "command_redacted": _command_string(cmd),
        "returncode": result["returncode"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "state": state,
    }
    _write_worker_status(contest_id, worker_id, state, state_root=state_root)
    _write_event(contest_id, "container_stop", status, payload, state_root=state_root)
    return _redact_object(payload)


def status_container(
    contest_id: str,
    worker_id: str,
    *,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    contest_id = _safe_slug(contest_id, "contest_id")
    worker_id = _safe_slug(worker_id, "worker_id")
    name = container_name(contest_id, worker_id)
    result = _run_docker(["docker", "inspect", name], timeout=timeout, runner=runner)
    previous = _worker_state(contest_id, worker_id, state_root=state_root)
    if result["returncode"] != 0:
        reason = _docker_failure_reason(result)
        status = "missing" if _looks_missing(result["stderr"]) else "unreachable"
        state = _merge_worker_state(
            contest_id,
            worker_id,
            state_root=state_root,
            update={
                "container_name": name,
                "worker_id": worker_id,
                "contest_id": contest_id,
                "image": previous.get("image") or DEFAULT_IMAGE,
                "workspace": previous.get("workspace") or _display_path(default_workspace(contest_id, worker_id)),
                "status": status,
            },
        )
        _write_worker_status(contest_id, worker_id, state, state_root=state_root)
        return _redact_object(
            {
                "status": status,
                "reason": reason,
                "contest_id": contest_id,
                "worker_id": worker_id,
                "container_name": name,
                "returncode": result["returncode"],
                "stderr": result["stderr"],
                "state": state,
            }
        )

    inspect = _parse_inspect(result["stdout"])
    status = str((inspect.get("State") or {}).get("Status") or "unknown")
    image = str((inspect.get("Config") or {}).get("Image") or previous.get("image") or DEFAULT_IMAGE)
    state = _merge_worker_state(
        contest_id,
        worker_id,
        state_root=state_root,
        update={
            "container_name": name,
            "worker_id": worker_id,
            "contest_id": contest_id,
            "image": image,
            "workspace": previous.get("workspace") or _display_path(default_workspace(contest_id, worker_id)),
            "status": status,
            "stopped_at": None if status == "running" else previous.get("stopped_at"),
        },
    )
    _write_worker_status(contest_id, worker_id, state, state_root=state_root)
    _write_event(contest_id, "container_status", status, {"worker_id": worker_id, "status": status}, state_root=state_root)
    return _redact_object(
        {
            "status": status,
            "contest_id": contest_id,
            "worker_id": worker_id,
            "container_name": name,
            "image": image,
            "state": state,
        }
    )


def cleanup_containers(
    contest_id: str,
    *,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
) -> dict[str, Any]:
    contest_id = _safe_slug(contest_id, "contest_id")
    workers = set(_known_workers(contest_id, state_root=state_root))
    for name in _list_docker_names(contest_id=contest_id, runner=runner):
        worker_id = _worker_from_name(contest_id, name)
        if worker_id:
            workers.add(worker_id)
    results = [stop_container(contest_id, worker_id, state_root=state_root, runner=runner) for worker_id in sorted(workers, key=_worker_sort_key)]
    status = "ok" if all(item.get("status") in {"stopped", "not_running", "missing"} for item in results) else "partial"
    payload = {"status": status, "contest_id": contest_id, "stopped_count": sum(item.get("status") == "stopped" for item in results), "containers": results}
    _write_event(contest_id, "container_cleanup", status, {"count": len(results), "stopped": payload["stopped_count"]}, state_root=state_root)
    return _redact_object(payload)


def start_pool(
    contest_id: str,
    workers: int,
    *,
    image: str = DEFAULT_IMAGE,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
) -> dict[str, Any]:
    count = _bounded_workers(workers)
    env = docker_environment(runner=runner)
    if not env.get("reachable"):
        return {"status": "skipped", "reason": env.get("classification") or env.get("reason"), "docker": env, "contest_id": _safe_slug(contest_id, "contest_id")}
    results = [start_container(contest_id, f"worker-{index}", image=image, state_root=state_root, runner=runner) for index in range(1, count + 1)]
    ok = all(item.get("status") in {"running", "already_running"} for item in results)
    return {
        "status": "ok" if ok else "partial",
        "contest_id": _safe_slug(contest_id, "contest_id"),
        "worker_count": count,
        "image": image,
        "workers": results,
        "paths": {"docker_root": _display_path(docker_pool_root(contest_id, state_root=state_root))},
    }


def pool_status(
    contest_id: str,
    *,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
) -> dict[str, Any]:
    contest_id = _safe_slug(contest_id, "contest_id")
    workers = set(_known_workers(contest_id, state_root=state_root))
    for name in _list_docker_names(contest_id=contest_id, runner=runner):
        worker_id = _worker_from_name(contest_id, name)
        if worker_id:
            workers.add(worker_id)
    items = [status_container(contest_id, worker_id, state_root=state_root, runner=runner) for worker_id in sorted(workers, key=_worker_sort_key)]
    active = sum(str(item.get("status") or "") == "running" for item in items)
    return {
        "status": "ok",
        "contest_id": contest_id,
        "active_container_count": active,
        "known_container_count": len(items),
        "containers": items,
        "paths": {"docker_root": _display_path(docker_pool_root(contest_id, state_root=state_root))},
    }


def pool_smoke(
    contest_id: str,
    workers: int,
    *,
    image: str = DEFAULT_IMAGE,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
) -> dict[str, Any]:
    env = docker_environment(runner=runner)
    if not env.get("reachable"):
        return {"status": "skipped", "reason": env.get("classification") or env.get("reason"), "docker": env, "contest_id": _safe_slug(contest_id, "contest_id")}
    start = start_pool(contest_id, workers, image=image, state_root=state_root, runner=runner)
    if start.get("status") not in {"ok", "partial"}:
        return {"status": "error", "contest_id": _safe_slug(contest_id, "contest_id"), "start": start}
    execs = [exec_in_container(contest_id, f"worker-{index}", "true", timeout=20, state_root=state_root, runner=runner) for index in range(1, _bounded_workers(workers) + 1)]
    workspace_checks = [
        _workspace_mount_check(contest_id, f"worker-{index}", state_root=state_root, runner=runner)
        for index in range(1, _bounded_workers(workers) + 1)
    ]
    ok = start.get("status") == "ok" and all(item.get("status") == "ok" for item in execs) and all(item.get("status") == "ok" for item in workspace_checks)
    return {
        "status": "ok" if ok else "error",
        "contest_id": _safe_slug(contest_id, "contest_id"),
        "worker_count": _bounded_workers(workers),
        "image": image,
        "start": start,
        "exec": execs,
        "workspace_mount": workspace_checks,
        "pool_status": pool_status(contest_id, state_root=state_root, runner=runner),
    }


def benchmark(
    *,
    image: str = DEFAULT_IMAGE,
    iterations: int = 5,
    state_root: str | Path | None = None,
    runner: _Runner | None = None,
) -> dict[str, Any]:
    env = docker_environment(runner=runner)
    count = max(1, min(int(iterations), 20))
    if not env.get("reachable"):
        return {"status": "skipped", "reason": env.get("classification") or env.get("reason"), "docker": env, "image": image, "iterations": count}

    one_shot = _timed_runs([["docker", "run", "--rm", image, "true"] for _ in range(count)], runner=runner, timeout=30)
    one_shot_linux_amd64 = _timed_runs([["docker", "run", "--platform", "linux/amd64", "--rm", image, "true"] for _ in range(count)], runner=runner, timeout=30)
    bench_contest = f"benchmark-{os.getpid()}"
    bench_worker = f"worker-{int(time.time() * 1000) % 100000}"
    start = start_container(bench_contest, bench_worker, image=image, workspace=_benchmark_workspace(state_root), state_root=state_root, runner=runner)
    exec_runs: list[dict[str, Any]] = []
    try:
        if start.get("status") in {"running", "already_running"}:
            exec_runs = _timed_runs([build_exec_command(bench_contest, bench_worker, "true") for _ in range(count)], runner=runner, timeout=20)
    finally:
        stop_container(bench_contest, bench_worker, state_root=state_root, runner=runner)
    one_shot_avg = _average_ms(one_shot)
    persistent_avg = _average_ms(exec_runs)
    platform_avg = _average_ms(one_shot_linux_amd64)
    status = "ok" if one_shot and all(item["ok"] for item in one_shot) and exec_runs and all(item["ok"] for item in exec_runs) else "partial"
    return {
        "status": status,
        "image": image,
        "iterations": count,
        "one_shot": {"runs": one_shot, "average_ms": one_shot_avg},
        "one_shot_linux_amd64": {"runs": one_shot_linux_amd64, "average_ms": platform_avg},
        "persistent_exec": {"runs": exec_runs, "average_ms": persistent_avg, "container_start": _redact_object(start)},
        "speedup_ratio": _speedup_ratio(one_shot_avg, persistent_avg),
    }


def docker_environment(*, runner: _Runner | None = None) -> dict[str, Any]:
    context = "codex_sandbox" if _looks_codex_sandbox() else "wsl_terminal" if _is_wsl() else "local"
    if not shutil.which("docker") and runner is None:
        reason = "docker_desktop_integration_missing" if _docker_desktop_cli_available() else "docker_cli_missing"
        classification = _docker_classification(reason, context)
        return {
            "found": False,
            "reachable": False,
            "reason": reason,
            "classification": classification,
            "base_reason": reason,
            "execution_context": context,
            "diagnostic_hint": _docker_diagnostic_hint(reason, context),
            "docker_desktop_cli": _docker_desktop_cli_payload(),
        }
    result = _run_docker(["docker", "info", "--format", "{{json .ServerVersion}}"], timeout=5, runner=runner)
    if result["returncode"] == 0:
        return {
            "found": True,
            "reachable": True,
            "version": result["stdout"].strip().strip('"'),
            "reason": "ok",
            "classification": "ok",
            "execution_context": context,
            "diagnostic_hint": "ok",
            "docker_desktop_cli": _docker_desktop_cli_payload(),
        }
    reason = _docker_failure_reason(result)
    classification = _docker_classification(reason, context)
    return {
        "found": True,
        "reachable": False,
        "reason": reason,
        "classification": classification,
        "base_reason": reason,
        "execution_context": context,
        "diagnostic_hint": _docker_diagnostic_hint(reason, context),
        "docker_desktop_cli": _docker_desktop_cli_payload(),
        "stderr": result["stderr"],
    }


def image_exists(image: str = DEFAULT_IMAGE, *, runner: _Runner | None = None) -> dict[str, Any]:
    env = docker_environment(runner=runner)
    if not env.get("reachable"):
        return {"image": image, "exists": False, "checked": False, "reason": env.get("classification") or env.get("reason"), "docker": env}
    result = _run_docker(["docker", "image", "inspect", image], timeout=10, runner=runner)
    return {
        "image": image,
        "exists": result["returncode"] == 0,
        "checked": True,
        "reason": "ok" if result["returncode"] == 0 else "docker_image_missing",
        "stderr": result["stderr"] if result["returncode"] != 0 else "",
    }


def pool_readiness(*, image: str = DEFAULT_IMAGE, runner: _Runner | None = None) -> dict[str, Any]:
    env = docker_environment(runner=runner)
    image_status = image_exists(image, runner=runner) if env.get("reachable") else {"image": image, "exists": False, "checked": False, "reason": env.get("classification") or env.get("reason")}
    active = active_container_count(runner=runner) if env.get("reachable") else {"status": "skipped", "active_container_count": 0, "reason": env.get("classification") or env.get("reason")}
    return {
        "status": "ready" if env.get("reachable") and image_status.get("exists") else "not_ready",
        "docker": env,
        "image": image_status,
        "active_container_count": int(active.get("active_container_count") or 0),
        "active_container_count_status": active.get("status"),
    }


def active_container_count(*, contest_id: str | None = None, runner: _Runner | None = None) -> dict[str, Any]:
    names = _list_docker_names(contest_id=contest_id, runner=runner)
    return {"status": "ok", "contest_id": contest_id or "", "active_container_count": len(names), "container_names": names}


def start_persistent_container(worker_id: str, workspace: str | Path, dry_run: bool = False) -> dict[str, Any]:
    name = container_name(worker_id)
    workspace_path = Path(workspace).expanduser().resolve()
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "-v",
        f"{workspace_path}:/workspace",
        "-w",
        "/workspace",
        DEFAULT_IMAGE,
        "sleep",
        "infinity",
    ]
    if dry_run:
        return {"planned": True, "container": name, "cmd": cmd}
    workspace_path.mkdir(parents=True, exist_ok=True)
    result = _run_docker(cmd, timeout=30)
    return {"planned": False, "container": name, **result}


def _timed_runs(commands: list[list[str]], *, runner: _Runner | None, timeout: float) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for cmd in commands:
        started = time.perf_counter()
        result = _run_docker(cmd, timeout=timeout, runner=runner)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        runs.append({"ok": result["returncode"] == 0, "returncode": result["returncode"], "elapsed_ms": elapsed_ms, "stderr": result["stderr"]})
    return runs


def _run_docker(cmd: list[str], *, timeout: float, runner: _Runner | None = None) -> dict[str, Any]:
    try:
        proc = (runner or subprocess.run)(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {"returncode": int(proc.returncode), "stdout": _bounded(redact_text(proc.stdout or "")), "stderr": _bounded(redact_text(proc.stderr or ""))}
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": "docker_cli_missing"}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {"returncode": 124, "stdout": _bounded(redact_text(stdout)), "stderr": _bounded(redact_text(stderr or "docker command timed out"))}
    except Exception as exc:  # noqa: BLE001 - Docker state commands should summarize failures.
        return {"returncode": 1, "stdout": "", "stderr": _bounded(redact_text(f"{type(exc).__name__}: {exc}"))}


def _parse_inspect(stdout: str) -> dict[str, Any]:
    try:
        loaded = json.loads(stdout)
    except json.JSONDecodeError:
        return {}
    if isinstance(loaded, list) and loaded and isinstance(loaded[0], dict):
        return loaded[0]
    return loaded if isinstance(loaded, dict) else {}


def _list_docker_names(*, contest_id: str | None = None, runner: _Runner | None = None) -> list[str]:
    cmd = ["docker", "ps", "--filter", f"label={POOL_LABEL}=1"]
    if contest_id:
        cmd.extend(["--filter", f"label={CONTEST_LABEL}={_safe_slug(contest_id, 'contest_id')}"])
    cmd.extend(["--format", "{{.Names}}"])
    result = _run_docker(cmd, timeout=10, runner=runner)
    if result["returncode"] != 0:
        return []
    return sorted({line.strip() for line in result["stdout"].splitlines() if line.strip()})


def _workspace_mount_check(
    contest_id: str,
    worker_id: str,
    *,
    state_root: str | Path | None,
    runner: _Runner | None,
) -> dict[str, Any]:
    marker = ".ctf-pool-smoke"
    command = f"test -d /workspace && printf pool-smoke > /workspace/{marker} && test -s /workspace/{marker}"
    exec_result = exec_in_container(contest_id, worker_id, command, timeout=20, state_root=state_root, runner=runner)
    state = _worker_state(_safe_slug(contest_id, "contest_id"), _safe_slug(worker_id, "worker_id"), state_root=state_root)
    workspace = Path(str(state.get("workspace") or default_workspace(contest_id, worker_id))).expanduser()
    host_marker = workspace / marker
    host_seen = host_marker.exists() if runner is None else exec_result.get("status") == "ok"
    if runner is None:
        try:
            host_marker.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
    status = "ok" if exec_result.get("status") == "ok" and host_seen else "error"
    return _redact_object(
        {
            "status": status,
            "contest_id": _safe_slug(contest_id, "contest_id"),
            "worker_id": _safe_slug(worker_id, "worker_id"),
            "container_exec_status": exec_result.get("status"),
            "host_marker_seen": bool(host_seen),
            "workspace": _display_path(workspace),
        }
    )


def _worker_from_name(contest_id: str, name: str) -> str:
    prefix = f"ctf-runner-{_safe_slug(contest_id, 'contest_id')}-"
    if name.startswith(prefix):
        return _safe_slug(name[len(prefix) :], "worker_id")
    return ""


def _worker_state(contest_id: str, worker_id: str, *, state_root: str | Path | None) -> dict[str, Any]:
    data = _read_containers(contest_id, state_root=state_root)
    containers = data.get("containers") if isinstance(data.get("containers"), dict) else {}
    item = containers.get(worker_id) if isinstance(containers, dict) else {}
    return dict(item) if isinstance(item, dict) else {}


def _merge_worker_state(contest_id: str, worker_id: str, *, state_root: str | Path | None, update: dict[str, Any]) -> dict[str, Any]:
    current = _worker_state(contest_id, worker_id, state_root=state_root)
    merged = _default_state(contest_id, worker_id)
    merged.update(current)
    for key, value in update.items():
        merged[key] = value
    _write_containers(contest_id, worker_id, merged, state_root=state_root)
    return merged


def _default_state(contest_id: str, worker_id: str) -> dict[str, Any]:
    return {
        "container_name": container_name(contest_id, worker_id),
        "worker_id": worker_id,
        "contest_id": contest_id,
        "image": DEFAULT_IMAGE,
        "workspace": _display_path(default_workspace(contest_id, worker_id)),
        "status": "unknown",
        "started_at": None,
        "stopped_at": None,
        "last_exec_at": None,
        "exec_count": 0,
        "average_exec_ms": 0.0,
    }


def _read_containers(contest_id: str, *, state_root: str | Path | None) -> dict[str, Any]:
    path = docker_pool_root(contest_id, state_root=state_root) / "containers.json"
    if not path.exists():
        return {"contest_id": _safe_slug(contest_id, "contest_id"), "containers": {}}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"contest_id": _safe_slug(contest_id, "contest_id"), "containers": {}}
    return loaded if isinstance(loaded, dict) else {"contest_id": _safe_slug(contest_id, "contest_id"), "containers": {}}


def _write_containers(contest_id: str, worker_id: str, state: dict[str, Any], *, state_root: str | Path | None) -> None:
    root = docker_pool_root(contest_id, state_root=state_root)
    root.mkdir(parents=True, exist_ok=True)
    data = _read_containers(contest_id, state_root=state_root)
    containers = data.get("containers") if isinstance(data.get("containers"), dict) else {}
    containers[worker_id] = _redact_object(state)
    data = {"contest_id": _safe_slug(contest_id, "contest_id"), "containers": containers}
    _write_json(root / "containers.json", data)


def _write_worker_status(contest_id: str, worker_id: str, state: dict[str, Any], *, state_root: str | Path | None) -> None:
    _write_json(docker_pool_root(contest_id, state_root=state_root) / f"{worker_id}.status.json", state)


def _write_event(contest_id: str, event_type: str, status: str, details: dict[str, Any], *, state_root: str | Path | None) -> None:
    path = docker_pool_root(contest_id, state_root=state_root) / "docker_events.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"time": utc_now(), "event_type": event_type, "status": status, "details": _redact_object(details)}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_redact_object(payload), sort_keys=True))
        fh.write("\n")


def _append_exec_log(contest_id: str, worker_id: str, payload: dict[str, Any], *, state_root: str | Path | None) -> None:
    path = docker_pool_root(contest_id, state_root=state_root) / f"{worker_id}.exec.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {"time": utc_now(), **_redact_object(payload)}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True))
        fh.write("\n")


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(redact_text(json.dumps(_redact_object(data), indent=2, sort_keys=True)) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _known_workers(contest_id: str, *, state_root: str | Path | None) -> list[str]:
    data = _read_containers(contest_id, state_root=state_root)
    containers = data.get("containers") if isinstance(data.get("containers"), dict) else {}
    return sorted([_safe_slug(key, "worker_id") for key in containers], key=_worker_sort_key)


def _workspace_path(contest_id: str, worker_id: str, workspace: str | Path | None) -> Path:
    return (Path(workspace).expanduser() if workspace else default_workspace(contest_id, worker_id)).resolve()


def _benchmark_workspace(state_root: str | Path | None) -> Path:
    root = Path(state_root).expanduser() if state_root else get_paths().state_root
    return root / "docker-benchmark-workspace"


def _docker_classification(reason: str, context: str) -> str:
    return "codex_sandbox_docker_unreachable" if context == "codex_sandbox" and reason != "ok" else reason


def _docker_desktop_cli_available() -> bool:
    return _is_wsl() and DOCKER_DESKTOP_CLI.exists()


def _docker_desktop_cli_payload() -> dict[str, Any]:
    exists = _docker_desktop_cli_available()
    return {
        "path": str(DOCKER_DESKTOP_CLI),
        "exists": exists,
        "symlink_hint": f"sudo ln -sf {DOCKER_DESKTOP_CLI} /usr/local/bin/docker" if exists else "",
    }


def _docker_diagnostic_hint(reason: str, context: str) -> str:
    if context == "codex_sandbox" and reason != "ok":
        return f"{reason}; re-check Docker from a normal WSL terminal because this Codex context may not expose Docker."
    if reason == "docker_desktop_integration_missing":
        return "Docker Desktop CLI exists under /mnt/wsl, but docker is not on PATH; enable WSL Integration or add a symlink fallback."
    if reason == "docker_cli_missing":
        return "docker command is not on PATH; install Docker CLI or enable Docker Desktop WSL Integration."
    if reason == "docker_socket_permission":
        return "docker CLI exists but the current user cannot access the Docker socket."
    if reason == "docker_daemon_unreachable":
        return "docker CLI exists but the daemon is unreachable; start Docker Desktop or the Linux Docker service."
    return "ok"


def _docker_failure_reason(result: dict[str, Any]) -> str:
    text = f"{result.get('stderr') or ''} {result.get('stdout') or ''}".lower()
    if int(result.get("returncode") or 0) == 127 or "docker_cli_missing" in text:
        return "docker_cli_missing"
    if "wsl integration" in text or "docker desktop" in text and "integration" in text:
        return "docker_desktop_integration_missing"
    if "permission denied" in text or "got permission denied" in text or "connect: permission denied" in text:
        return "docker_socket_permission"
    return "docker_daemon_unreachable"


def _looks_missing(stderr: str) -> bool:
    text = str(stderr or "").lower()
    return "no such object" in text or "no such container" in text or "not found" in text


def _looks_codex_sandbox() -> bool:
    return bool(os.environ.get("CODEX_THREAD_ID") or os.environ.get("CODEX_CI") or os.environ.get("CODEX_SANDBOX"))


def _is_wsl() -> bool:
    return bool(os.environ.get("WSL_DISTRO_NAME")) or "microsoft" in os.uname().release.lower()


def _assert_no_secret_env(cmd: list[str]) -> None:
    forbidden = {"-e", "--env", "--env-file"}
    if any(arg in forbidden or arg.startswith("--env=") for arg in cmd):
        raise ValueError("docker pool commands must not pass environment variables")


def _safe_slug(value: str, label: str) -> str:
    raw = str(value or "").strip()
    if not raw or not _SLUG_RE.match(raw):
        raise ValueError(f"{label} contains unsupported characters")
    return raw[:80]


def _bounded_workers(workers: int) -> int:
    try:
        parsed = int(workers)
    except (TypeError, ValueError):
        parsed = 1
    return max(1, min(parsed, 20))


def _average_ms(runs: list[dict[str, Any]]) -> float:
    values = [float(item.get("elapsed_ms") or 0.0) for item in runs if item.get("ok")]
    return round(sum(values) / len(values), 2) if values else 0.0


def _speedup_ratio(one_shot_avg: float, persistent_avg: float) -> float:
    if persistent_avg <= 0:
        return 0.0
    return round(one_shot_avg / persistent_avg, 2)


def _bounded(text: str, limit: int = 8000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n[truncated]\n"


def _command_string(cmd: list[str]) -> str:
    safe_parts = []
    for item in cmd:
        lowered = str(item).lower()
        if any(marker in lowered for marker in _SENSITIVE_ARG_MARKERS):
            safe_parts.append("[REDACTED]")
        else:
            safe_parts.append(redact_text(str(item)))
    return " ".join(_shell_quote(part) for part in safe_parts)


def _shell_quote(value: str) -> str:
    import shlex

    return shlex.quote(value)


def _display_path(path: Path) -> str:
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)


def _worker_sort_key(worker_id: str) -> tuple[int, str]:
    match = re.search(r"(\d+)$", worker_id)
    return (int(match.group(1)) if match else 10_000, worker_id)


def _redact_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_object(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
