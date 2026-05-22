from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from ctf_runner.worker_supervisor import (
    start_worker_process,
    stop_worker,
    worker_logs,
    worker_status,
    workers_root,
)


def test_start_status_stop_process(tmp_path: Path):
    state_root = tmp_path / "state"
    result = start_worker_process(
        "local-fake",
        "worker-1",
        [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(30)"],
        env={"CTF_RUN_MODE": "setup", "CTF_CONTEST_ID": "local-fake"},
        metadata={"mode": "setup", "solver": "mock", "max_iterations": 1},
        state_root=state_root,
    )
    try:
        assert result["status"] == "started"
        status = worker_status("local-fake", state_root=state_root)
        assert status["running_worker_count"] == 1
        assert status["workers"][0]["alive"] is True
    finally:
        stopped = stop_worker("local-fake", "worker-1", state_root=state_root)
    assert stopped["status"] in {"stopped", "exited"}
    assert worker_status("local-fake", state_root=state_root)["running_worker_count"] == 0


def test_stale_pid_detection(tmp_path: Path):
    root = workers_root("local-fake", state_root=tmp_path / "state")
    root.mkdir(parents=True)
    (root / "worker-9.pid").write_text("999999999", encoding="utf-8")

    status = worker_status("local-fake", state_root=tmp_path / "state")

    worker = next(item for item in status["workers"] if item["worker_id"] == "worker-9")
    assert worker["alive"] is False
    assert worker["stale"] is True
    assert worker["status"] == "stale"


def test_command_redaction_and_safe_env(tmp_path: Path):
    state_root = tmp_path / "state"
    result = start_worker_process(
        "local-fake",
        "worker-1",
        [sys.executable, "-c", "import time; time.sleep(30)", "--token=dummy-token-value"],
        env={"CTF_RUN_MODE": "setup", "CTF_CONTEST_ID": "local-fake", "API_TOKEN": "dummy-token-value"},
        metadata={"mode": "setup", "solver": "mock", "profile_path": tmp_path / "profile.yaml"},
        state_root=state_root,
    )
    try:
        assert result["status"] == "started"
        command_path = workers_root("local-fake", state_root=state_root) / "worker-1.command.json"
        command = json.loads(command_path.read_text(encoding="utf-8"))
        rendered = json.dumps(command)
        assert "dummy-token-value" not in rendered
        assert "API_TOKEN" not in rendered
        assert command["env"] == {"CTF_CONTEST_ID": "local-fake", "CTF_RUN_MODE": "setup"}
    finally:
        stop_worker("local-fake", "worker-1", state_root=state_root)


def test_logs_tail_redacts_flag_like_values(tmp_path: Path):
    root = workers_root("local-fake", state_root=tmp_path / "state")
    root.mkdir(parents=True)
    (root / "worker-1.log").write_text("ok\n" + "DDING" + "{secret_value}\n", encoding="utf-8")

    logs = worker_logs("local-fake", "worker-1", tail=5, state_root=tmp_path / "state")

    assert logs["status"] == "ok"
    assert "[REDACTED]" in "\n".join(logs["lines"])
    assert "secret_value" not in "\n".join(logs["lines"])
