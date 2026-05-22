import subprocess
from pathlib import Path

from ctf_runner.state import add_manual_challenge, get_challenge_state, init_db
from ctf_runner.worker_loop import run_worker_once


def _brief(root: Path, challenge_id: str, text: str) -> Path:
    path = root / "manual" / challenge_id / "brief.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_codex_worker_parses_noisy_output_and_plans_submit(monkeypatch, tmp_path: Path):
    candidate = "TJCTF" + "{" + "wrapper_alpha_74291" + "}"
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    state_root = tmp_path / "state"
    telemetry = tmp_path / "events.jsonl"
    init_db(db)
    add_manual_challenge("codex-unit", "Codex Unit", "misc", db_path=db)
    _brief(contests, "codex-unit", "# Challenge Brief\n- challenge_dir: local\n- raw/note.txt [text]\n")

    def fake_run(*args, **kwargs):
        output = "\n".join(
            [
                '{"worker_id":"worker-test","worker_home":"/tmp/worker"}',
                '{"mode":"exec","argv":["codex","exec"],"validation":{"ok":true}}',
                "[warn] competition worker uses model=auto/unpinned approval=never sandbox=danger-full-access",
                "OpenAI Codex v0.130.0",
                "--------",
                "workdir: /repo",
                "model: auto",
                "approval: never",
                "sandbox: danger-full-access",
                "```text",
                "STATUS: solved",
                "SUMMARY: read from note.txt",
                "SOURCE: file_read",
                "LOCAL_VERIFIED: true",
                "FAKE_LIKE: false",
                f"FLAG_CANDIDATE: {candidate}",
                "FACTS:",
                "- candidate came from the local text file",
                "```",
                "tokens used: 1234",
                "",
            ]
        )
        return subprocess.CompletedProcess(args[0], 0, stdout=output, stderr="")

    monkeypatch.setattr("ctf_runner.worker_loop.subprocess.run", fake_run)

    result = run_worker_once(
        "worker-test",
        solver="codex",
        allow_codex_call=True,
        db_path=db,
        contests_root=contests,
        state_root=state_root,
        telemetry_path=telemetry,
    )

    assert result["status"] == "submit_planned"
    assert result["flag_candidate_count"] == 1
    assert result["submit_plan_status"] == "planned"
    assert result["handoff_written"] is False
    assert result["solver_result"]["summary"] == "read from note.txt"
    assert result["solver_result"]["flag_candidates"][0]["source"] == "file_read"
    assert result["submit_plans"][0]["status"] == "planned"
    assert get_challenge_state("codex-unit", db)["status"] == "submit_planned"
    assert candidate not in repr(result)
    assert candidate not in telemetry.read_text(encoding="utf-8")


def test_codex_worker_empty_output_writes_error_handoff(monkeypatch, tmp_path: Path):
    db = tmp_path / "queue.sqlite3"
    contests = tmp_path / "contests"
    state_root = tmp_path / "state"
    init_db(db)
    add_manual_challenge("codex-empty", "Codex Empty", "misc", db_path=db)
    _brief(contests, "codex-empty", "# Challenge Brief\n")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout="", stderr="")

    monkeypatch.setattr("ctf_runner.worker_loop.subprocess.run", fake_run)

    result = run_worker_once(
        "worker-test",
        solver="codex",
        allow_codex_call=True,
        db_path=db,
        contests_root=contests,
        state_root=state_root,
        telemetry_path=tmp_path / "events.jsonl",
    )

    assert result["status"] == "error"
    assert result["submit_plan_status"] == "none"
    assert result["handoff_written"] is True
    assert (state_root / "handoffs" / "handoff.jsonl").exists()
