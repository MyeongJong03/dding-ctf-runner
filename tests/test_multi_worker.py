import json
from pathlib import Path

from ctf_runner.fake_ctfd import default_correct_flag, fake_decoy_flag
from ctf_runner.multi_worker import run_local_e2e
from ctf_runner.state import get_challenge_state, list_submissions
from ctf_runner.submit import should_submit


def test_mock_multi_worker_local_e2e_solves_and_stalls_without_duplicates(tmp_path: Path):
    result = run_local_e2e(workers=5, solver="mock", fake_ctfd=True, run_root=tmp_path / "run")

    assert result["status"] == "ok"
    assert result["expected_met"] is True
    assert result["total_challenges"] == 5
    assert result["solved"] == 4
    assert result["stalled"] == 1
    assert result["accepted_submissions"] == 4
    assert result["blocked_submissions"] == 1
    assert result["fake_like_blocks"] == 1
    assert result["duplicate_claims"] == 0
    assert result["handoff_count"] == 1
    assert result["postsolve_summary_count"] == 4
    assert result["raw_leak_detected"] is False

    claimed = [item["challenge_id"] for item in result["worker_results"]]
    assert len(claimed) == 5
    assert len(set(claimed)) == 5
    assert result["queue"]["active_claims"] == []

    db = _expand(result["db_path"])
    assert get_challenge_state("stalled-1", db)["status"] == "stalled"
    duplicate_plans = [
        plan
        for item in result["worker_results"]
        if item["challenge_id"] == "duplicate-decoy-1"
        for plan in item["submit_plans"]
    ]
    assert any(plan["reason"] == "fake_likely" and plan["status"] == "blocked" for plan in duplicate_plans)
    assert any(plan["status"] == "accepted" for plan in duplicate_plans)

    previous = list_submissions("easy-misc-1", db)
    duplicate_decision = should_submit(
        default_correct_flag(),
        previous_submissions=previous,
        challenge_state={"challenge_id": "easy-misc-1", "status": "queued", "solved": False},
        context={"source": "exploit_output", "local_verified": True},
    )
    already_solved = should_submit(
        default_correct_flag(),
        previous_submissions=previous,
        challenge_state={"challenge_id": "easy-misc-1", "status": "solved", "solved": True},
        context={"source": "exploit_output", "local_verified": True},
    )
    assert duplicate_decision["reason"] == "duplicate"
    assert already_solved["reason"] == "already_solved"

    rendered = json.dumps(result, sort_keys=True)
    assert default_correct_flag() not in rendered
    assert fake_decoy_flag() not in rendered


def test_mock_three_worker_local_e2e_expected_met_scales_to_worker_count(tmp_path: Path):
    result = run_local_e2e(workers=3, solver="mock", fake_ctfd=True, run_root=tmp_path / "run")

    assert result["status"] == "ok"
    assert result["expected_met"] is True
    assert result["workers_requested"] == 3
    assert result["solved"] + result["stalled"] + result["submit_planned"] + result["errors"] >= 3
    assert result["duplicate_claims"] == 0
    assert result["raw_leak_detected"] is False


def _expand(path: str) -> Path:
    return Path(path.replace("~/", str(Path.home()) + "/", 1)).expanduser()
