from __future__ import annotations

from pathlib import Path

from ctf_runner import docker_pool
from ctf_runner.contest_control import contest_status, disarm_contest
from ctf_runner.state import add_manual_challenge, init_db


def test_contest_status_includes_docker_pool_count(monkeypatch, tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    init_db(db)
    add_manual_challenge("pwn-1", "Pwn One", "pwn", contest_id="example", db_path=db)
    monkeypatch.setattr(
        docker_pool,
        "pool_status",
        lambda contest_id, state_root=None: {
            "status": "ok",
            "contest_id": contest_id,
            "active_container_count": 2,
            "containers": [],
        },
    )

    status = contest_status("example", db_path=db, state_root=tmp_path / "state")

    assert status["active_docker_container_count"] == 2
    assert status["docker_pool"]["active_container_count"] == 2
    assert "docker_pool_not_started" not in status["docker_warnings"]


def test_contest_status_warns_for_pwn_rev_without_pool(monkeypatch, tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    init_db(db)
    add_manual_challenge("rev-1", "Rev One", "rev", contest_id="example", db_path=db)
    monkeypatch.setattr(
        docker_pool,
        "pool_status",
        lambda contest_id, state_root=None: {
            "status": "ok",
            "contest_id": contest_id,
            "active_container_count": 0,
            "containers": [],
        },
    )

    status = contest_status("example", db_path=db, state_root=tmp_path / "state")

    assert "docker_pool_not_started" in status["docker_warnings"]


def test_disarm_warns_or_stops_active_docker_pool(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        docker_pool,
        "pool_status",
        lambda contest_id, state_root=None: {
            "status": "ok",
            "contest_id": contest_id,
            "active_container_count": 1,
            "containers": [{"worker_id": "worker-1", "status": "running"}],
        },
    )
    monkeypatch.setattr(
        docker_pool,
        "cleanup_containers",
        lambda contest_id, state_root=None: {"status": "ok", "contest_id": contest_id, "stopped_count": 1},
    )

    warn = disarm_contest("example", state_root=tmp_path / "state")
    stopped = disarm_contest("example", stop_docker_pool=True, state_root=tmp_path / "state")

    assert "active docker pool containers remain" in warn["warning"]
    assert stopped["docker_cleanup"]["stopped_count"] == 1
