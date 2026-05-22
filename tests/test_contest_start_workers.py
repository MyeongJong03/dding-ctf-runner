from __future__ import annotations

import contextlib
import io
import json
import sys
import time
from pathlib import Path

from ctf_runner.cli import main
from ctf_runner.worker_supervisor import start_worker_process, worker_status, workers_root


def test_start_workers_dry_run_does_not_start(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))
    result, code = _run_json(
        [
            "--db",
            str(tmp_path / "queue.sqlite3"),
            "contest",
            "start-workers",
            "--contest-id",
            "local-fake",
            "--dry-run",
            "--workers",
            "2",
            "--json",
        ]
    )

    assert code == 0
    assert result["status"] == "dry_run"
    assert result["launched"] is False
    assert not list(workers_root("local-fake", state_root=tmp_path / "state").glob("*.pid"))


def test_start_workers_apply_starts_fake_worker(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))
    result, code = _run_json(
        [
            "--db",
            str(tmp_path / "queue.sqlite3"),
            "contest",
            "start-workers",
            "--contest-id",
            "local-fake",
            "--apply",
            "--workers",
            "1",
            "--solver",
            "mock",
            "--max-iterations",
            "1",
            "--stop-when-empty",
            "--json",
        ]
    )
    assert code == 0
    assert result["status"] == "started"
    assert result["launched"] is True
    assert result["workers"][0]["pid"]

    deadline = time.monotonic() + 5
    status = worker_status("local-fake", state_root=tmp_path / "state")
    while status["running_worker_count"] and time.monotonic() < deadline:
        time.sleep(0.05)
        status = worker_status("local-fake", state_root=tmp_path / "state")
    assert status["running_worker_count"] == 0


def test_real_platform_unarmed_start_blocked(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "state"))

    result, code = _run_json(
        [
            "contest",
            "start-workers",
            "--contest-id",
            "real-platform",
            "--apply",
            "--workers",
            "1",
            "--json",
        ]
    )

    assert code == 1
    assert result["status"] == "blocked"
    assert result["reason"] == "contest_not_armed"


def test_disarm_stop_workers_stops_process(monkeypatch, tmp_path: Path):
    state_root = tmp_path / "state"
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(state_root))
    start_worker_process(
        "example",
        "worker-1",
        [sys.executable, "-c", "import time; time.sleep(30)"],
        env={"CTF_RUN_MODE": "setup", "CTF_CONTEST_ID": "example"},
        metadata={"mode": "setup", "solver": "mock"},
        state_root=state_root,
    )

    result, code = _run_json(["contest", "disarm", "--contest-id", "example", "--stop-workers", "--json"])

    assert code == 0
    assert result["status"] == "disarmed"
    assert result["worker_stop"]["status"] == "ok"
    assert worker_status("example", state_root=state_root)["running_worker_count"] == 0


def _run_json(argv: list[str]) -> tuple[dict, int]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = main(argv)
    raw = stdout.getvalue()
    return json.loads(raw), code
