from __future__ import annotations

from pathlib import Path

from ctf_runner import full_rehearsal, worker_loop
from ctf_runner.submit import detect_flag_candidates
from tests.test_full_rehearsal import _patch_external_checks


def test_codex_rehearsal_uses_bounded_fake_codex_path(monkeypatch, tmp_path: Path):
    _patch_external_checks(monkeypatch, tmp_path)
    expected_by_id = {
        fixture.challenge_id: fixture.correct_flag
        for fixture in full_rehearsal.final_rehearsal_fixtures(codex_smoke=True)
    }

    def fake_codex(worker_id: str, prompt: str) -> str:
        challenge_id = next((item for item in expected_by_id if item in prompt), "")
        candidate = expected_by_id[challenge_id]
        observed = detect_flag_candidates(prompt)
        evidence_source = "raw/app.py" if challenge_id == "final-web-source" else "raw/local_note.txt"
        return "\n".join(
            [
                "STATUS: solved",
                "CONFIDENCE: high",
                f"EVIDENCE_SOURCE: {evidence_source}",
                "DERIVATION: read selected local evidence and decoded or extracted the candidate",
                f"FLAG_CANDIDATE: {candidate if not observed else candidate}",
                "REJECTED_CANDIDATES:",
                "- none",
                "",
            ]
        )

    monkeypatch.setattr(worker_loop, "_run_codex_solver", fake_codex)

    result = full_rehearsal.run_full_rehearsal(
        contest_id="final-fake-codex-test",
        workers=3,
        max_parallel_codex=2,
        solver="codex",
        allow_codex_call=True,
        run_release_check=True,
    )

    assert result["status"] == "ok"
    assert result["codex_smoke"] is True
    assert result["max_parallel_observed"] <= 2
    assert result["counts"]["solved"] == 3
    assert result["counts"]["accepted_submissions"] == 3
    assert result["counts"]["postsolve_generated"] == 3
    assert result["counts"]["active_worker_count"] == 0
    assert result["counts"]["active_docker_pool_count"] == 0
    assert result["raw_leak_detected"] is False
    assert result["acceptance"]["codex_concurrency_bounded"] is True
    assert result["acceptance"]["codex_easy_solved"] is True
    assert len(result["challenge_failure_summary"]) == 3
    assert all(item["evidence_source_present"] for item in result["challenge_failure_summary"])

    report = tmp_path / "runner-state" / "contests" / "final-fake-codex-test" / "rehearsal_report.json"
    summary = tmp_path / "runner-state" / "contests" / "final-fake-codex-test" / "rehearsal_summary.md"
    rendered = report.read_text(encoding="utf-8") + summary.read_text(encoding="utf-8")
    for raw_flag in expected_by_id.values():
        assert raw_flag not in rendered


def test_codex_rehearsal_requires_explicit_allow(monkeypatch, tmp_path: Path):
    _patch_external_checks(monkeypatch, tmp_path)

    result = full_rehearsal.run_full_rehearsal(
        contest_id="final-fake-codex-blocked",
        workers=2,
        solver="codex",
        allow_codex_call=False,
        run_release_check=False,
    )

    assert result["status"] == "blocked"
    assert result["failures"] == ["allow_codex_call_required"]
    assert result["counts"]["active_worker_count"] == 0
    assert result["raw_leak_detected"] is False
