import json
import subprocess
from pathlib import Path

from ctf_runner.fake_ctfd import CHALLENGE_ID, FakeCTFdServer, platform_config
from ctf_runner.state import add_manual_challenge, get_challenge_state, init_db, list_submissions
from ctf_runner.worker_loop import MOCK_SOLVED_MARKER, run_worker_once


def test_worker_live_submit_to_local_fake_ctfd_marks_solved(tmp_path: Path):
    candidate = "DDING" + "{" + "mock_solver_verified_value" + "}"
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    state_root = tmp_path / "state"
    telemetry = tmp_path / "events.jsonl"
    config_path = tmp_path / "platform.json"

    with FakeCTFdServer(correct_flag=candidate) as server:
        config_path.write_text(json.dumps(platform_config(server.base_url, contests)), encoding="utf-8")
        init_db(db)
        add_manual_challenge(CHALLENGE_ID, "Local Codex Smoke", "misc", contest_id="fake_ctfd", db_path=db)
        _brief(contests, CHALLENGE_ID, f"# Brief\n{MOCK_SOLVED_MARKER}\n")

        result = run_worker_once(
            "worker-test",
            solver="mock",
            live_submit=True,
            confirm_submit=True,
            platform_config=config_path,
            db_path=db,
            state_root=state_root,
            telemetry_path=telemetry,
        )

        assert result["status"] == "solved"
        assert result["live_submit_called"] is True
        assert result["submit_plan_status"] == "accepted"
        assert result["state_after"] == "solved"
        assert result["postsolve_summary"]["status"] == "ok"
        assert get_challenge_state(CHALLENGE_ID, db)["status"] == "solved"
        assert list_submissions(CHALLENGE_ID, db)[0]["status"] == "accepted"
        assert result["submit_plans"][0]["platform"] == "fake_ctfd"
        assert result["submit_plans"][0]["source"] == "exploit_output"
        assert result["submit_plans"][0]["local_verified"] is True
        assert result["submit_plans"][0]["fake_likely"] is False

        summary_path = Path(result["postsolve_summary"]["path"].replace("~/", str(Path.home()) + "/", 1))
        assert summary_path.exists()
        combined = json.dumps(result, sort_keys=True) + telemetry.read_text(encoding="utf-8") + summary_path.read_text(encoding="utf-8")
        combined += repr(list_submissions(CHALLENGE_ID, db))
        assert candidate not in combined
        assert result["submit_plans"][0]["flag_hash"] in combined


def test_worker_live_submit_requires_confirm_before_post(tmp_path: Path):
    candidate = "DDING" + "{" + "mock_solver_verified_value" + "}"
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    config_path = tmp_path / "platform.json"

    with FakeCTFdServer(correct_flag=candidate) as server:
        config_path.write_text(json.dumps(platform_config(server.base_url, contests)), encoding="utf-8")
        init_db(db)
        add_manual_challenge(CHALLENGE_ID, "Local Codex Smoke", "misc", contest_id="fake_ctfd", db_path=db)
        _brief(contests, CHALLENGE_ID, f"# Brief\n{MOCK_SOLVED_MARKER}\n")

        result = run_worker_once(
            "worker-test",
            solver="mock",
            live_submit=True,
            confirm_submit=False,
            platform_config=config_path,
            db_path=db,
            state_root=tmp_path / "state",
            telemetry_path=tmp_path / "events.jsonl",
        )

        assert result["status"] == "submit_planned"
        assert result["live_submit_called"] is False
        assert get_challenge_state(CHALLENGE_ID, db)["status"] == "submit_planned"
        assert not any("/api/v1/challenges/attempt" in item for item in server.request_log)
        assert candidate not in json.dumps(result, sort_keys=True)


def test_fake_ctfd_local_file_evidence_overrides_solver_fake_context(monkeypatch, tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    config_path = tmp_path / "platform.json"

    with FakeCTFdServer() as server:
        config_path.write_text(json.dumps(platform_config(server.base_url, contests)), encoding="utf-8")
        init_db(db)
        add_manual_challenge(CHALLENGE_ID, "Local Codex Smoke", "misc", contest_id="fake_ctfd", db_path=db)
        _brief(contests, CHALLENGE_ID, "# Brief\n- raw/local-codex-smoke-note.txt [text]\n")

        def fake_run(*args, **kwargs):
            output = "\n".join(
                [
                    "STATUS: solved",
                    "SUMMARY: read from local fake CTFd note.txt",
                    "SOURCE: file_read",
                    "LOCAL_VERIFIED: true",
                    "FAKE_LIKE: true",
                    "EVIDENCE: note.txt sha256=local",
                    f"FLAG_CANDIDATE: {server.correct_flag}",
                    "",
                ]
            )
            return subprocess.CompletedProcess(args[0], 0, stdout=output, stderr="")

        monkeypatch.setattr("ctf_runner.worker_loop.subprocess.run", fake_run)

        result = run_worker_once(
            "worker-test",
            solver="codex",
            allow_codex_call=True,
            live_submit=True,
            confirm_submit=True,
            platform_config=config_path,
            db_path=db,
            state_root=tmp_path / "state",
            telemetry_path=tmp_path / "events.jsonl",
        )

        assert result["status"] == "solved"
        assert result["submit_plans"][0]["fake_likely"] is False
        assert result["submit_plans"][0]["platform"] == "fake_ctfd"
        assert server.correct_flag not in json.dumps(result, sort_keys=True)


def _brief(root: Path, challenge_id: str, text: str) -> Path:
    path = root / "fake_ctfd" / challenge_id / "brief.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
