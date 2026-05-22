from pathlib import Path

from ctf_runner.state import add_manual_challenge, get_challenge_state, init_db, list_submissions
from ctf_runner.worker_loop import MOCK_SOLVED_MARKER, MOCK_STALLED_MARKER, run_worker_once


def _brief(root: Path, challenge_id: str, text: str) -> Path:
    path = root / "manual" / challenge_id / "brief.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_mock_worker_solved_path_plans_submit_and_telemetry(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    state_root = tmp_path / "state"
    telemetry = tmp_path / "events.jsonl"
    init_db(db)
    add_manual_challenge("mock-solved", "Mock Solved", "misc", db_path=db)
    _brief(contests, "mock-solved", f"# Brief\n{MOCK_SOLVED_MARKER}\n")

    result = run_worker_once(
        "worker-test",
        solver="mock",
        live_submit=True,
        db_path=db,
        contests_root=contests,
        state_root=state_root,
        telemetry_path=telemetry,
    )

    raw_candidate = "DDING" + "{" + "mock_solver_verified_value" + "}"
    assert result["status"] == "submit_planned"
    assert result["live_submit_called"] is False
    assert raw_candidate not in repr(result)
    assert result["submit_plans"][0]["status"] == "planned"
    assert get_challenge_state("mock-solved", db)["status"] == "submit_planned"
    rows = list_submissions("mock-solved", db)
    assert rows[0]["status"] == "planned"
    assert raw_candidate not in repr(rows)
    telemetry_text = telemetry.read_text(encoding="utf-8")
    assert "submit_planned" in telemetry_text
    assert raw_candidate not in telemetry_text


def test_mock_worker_stalled_path_writes_handoff(tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    state_root = tmp_path / "state"
    init_db(db)
    add_manual_challenge("mock-stalled", "Mock Stalled", "misc", db_path=db)
    _brief(contests, "mock-stalled", f"# Brief\n{MOCK_STALLED_MARKER}\n")

    result = run_worker_once(
        "worker-test",
        solver="mock",
        db_path=db,
        contests_root=contests,
        state_root=state_root,
        telemetry_path=tmp_path / "events.jsonl",
    )

    assert result["status"] == "stalled"
    assert get_challenge_state("mock-stalled", db)["status"] == "stalled"
    handoff = (state_root / "handoffs" / "handoff.jsonl").read_text(encoding="utf-8")
    assert "mock-stalled" in handoff
    assert "flag_hashes" in handoff
