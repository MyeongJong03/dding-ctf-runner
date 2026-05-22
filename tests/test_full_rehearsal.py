from __future__ import annotations

import json
from pathlib import Path

from ctf_runner import full_rehearsal


def test_mock_full_rehearsal_acceptance_and_reports(monkeypatch, tmp_path: Path):
    _patch_external_checks(monkeypatch, tmp_path)

    result = full_rehearsal.run_full_rehearsal(
        contest_id="final-fake-test",
        workers=5,
        solver="mock",
        run_release_check=True,
    )

    assert result["status"] == "ok"
    assert result["counts"]["discovered"] >= 5
    assert result["counts"]["ingested"] >= 5
    assert result["counts"]["solved"] >= 4
    assert result["counts"]["stalled"] >= 1
    assert result["counts"]["duplicate_claims"] == 0
    assert result["counts"]["duplicate_submissions"] == 0
    assert result["counts"]["active_worker_count"] == 0
    assert result["counts"]["active_tunnel_count"] == 0
    assert result["counts"]["active_docker_pool_count"] == 0
    assert result["counts"]["raw_leak_detected"] is False
    assert result["raw_leak_detected"] is False
    assert all(result["acceptance"].values())
    assert result["challenge_failure_summary"]
    assert all("candidate_count" in item for item in result["challenge_failure_summary"])

    report = tmp_path / "runner-state" / "contests" / "final-fake-test" / "rehearsal_report.json"
    summary = tmp_path / "runner-state" / "contests" / "final-fake-test" / "rehearsal_summary.md"
    assert report.exists()
    assert summary.exists()
    loaded = json.loads(report.read_text(encoding="utf-8"))
    assert loaded["status"] == "ok"
    assert "challenge_failure_summary" in loaded


def test_mock_full_rehearsal_cleanup_leaves_no_active_resources(monkeypatch, tmp_path: Path):
    _patch_external_checks(monkeypatch, tmp_path)

    result = full_rehearsal.run_full_rehearsal(
        contest_id="final-fake-cleanup",
        workers=5,
        solver="mock",
        run_release_check=True,
    )

    assert result["final"]["worker_status"]["running_worker_count"] == 0
    assert result["final"]["resources"]["active_tunnel_count"] == 0
    assert result["final"]["resources"]["active_callback_count"] == 0
    assert result["final"]["docker_pool"]["active_container_count"] == 0
    assert result["counts"]["active_worker_count"] == 0
    assert result["counts"]["active_tunnel_count"] == 0
    assert result["counts"]["active_callback_count"] == 0
    assert result["counts"]["active_docker_pool_count"] == 0
    assert result["acceptance"]["active_tunnels_zero"] is True
    assert result["acceptance"]["active_docker_pool_zero"] is True


def _patch_external_checks(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CTF_RUNNER_STATE_ROOT", str(tmp_path / "runner-state"))
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    monkeypatch.setenv("CTF_DOCKER_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setattr(
        full_rehearsal,
        "collect_preflight",
        lambda deep=True: {
            "risk": {"High": [], "Medium": ["global_long_agents"], "Low": [], "Info": []},
            "docker": {"classification": "ok", "reachable": True},
            "docker_pool": {"status": "ready", "active_container_count": 0},
            "ctf_pwn_image": {"exists": True, "checked": True},
            "preferred_tunnel_provider": "cloudflared",
            "public_provider_installed": True,
        },
    )
    monkeypatch.setattr(
        full_rehearsal,
        "start_pool",
        lambda contest_id, workers, state_root=None: {
            "status": "ok",
            "contest_id": contest_id,
            "worker_count": workers,
            "workers": [],
        },
    )
    monkeypatch.setattr(
        full_rehearsal,
        "cleanup_containers",
        lambda contest_id, state_root=None: {"status": "ok", "contest_id": contest_id, "stopped_count": 0, "containers": []},
    )
    monkeypatch.setattr(
        full_rehearsal,
        "pool_status",
        lambda contest_id, state_root=None: {
            "status": "ok",
            "contest_id": contest_id,
            "active_container_count": 0,
            "known_container_count": 0,
            "containers": [],
        },
    )
    monkeypatch.setattr(
        full_rehearsal,
        "run_callback_public_smoke",
        lambda **kwargs: {
            "status": "ok",
            "provider": "cloudflared",
            "listener": {"status": "stopped", "hit_count": 1},
            "tunnel": {"status": "stopped", "public_url": ""},
        },
    )
    monkeypatch.setattr(
        full_rehearsal,
        "_run_release_check",
        lambda: {"status": "ok", "returncode": 0, "output_tail": []},
    )
