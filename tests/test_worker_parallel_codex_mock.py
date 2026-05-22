import json
import threading
import time
from pathlib import Path

from ctf_runner.fake_ctfd import default_correct_flag, fake_decoy_flag
from ctf_runner.multi_worker import run_local_e2e


def test_codex_solver_parallel_smoke_uses_bounded_concurrency_and_redacts(monkeypatch, tmp_path: Path):
    seen_workers: list[str] = []
    lock = threading.Lock()

    def fake_codex(worker_id: str, prompt: str) -> str:
        with lock:
            seen_workers.append(worker_id)
        time.sleep(0.05)
        candidate = default_correct_flag()
        return "\n".join(
            [
                "STATUS: solved",
                f"SUMMARY: fake codex subprocess output for {worker_id}",
                "SOURCE: exploit_output",
                "LOCAL_VERIFIED: true",
                "FAKE_LIKE: false",
                f"FLAG_CANDIDATE: {candidate}",
                "FACTS:",
                "- bounded codex worker mock returned a local candidate",
                "ATTEMPTS:",
                "- fake subprocess output was used for this test",
                "NEXT_IDEAS:",
                "- none",
                "",
            ]
        )

    monkeypatch.setattr("ctf_runner.worker_loop._run_codex_solver", fake_codex)

    result = run_local_e2e(
        workers=5,
        solver="codex",
        fake_ctfd=True,
        max_parallel=2,
        run_root=tmp_path / "codex-run",
    )

    assert result["status"] == "ok"
    assert result["solver"] == "codex"
    assert result["max_parallel"] == 2
    assert result["max_parallel_observed"] <= 2
    assert len(seen_workers) == 5
    assert len(set(seen_workers)) == 5
    assert result["duplicate_claims"] == 0
    assert result["accepted_submissions"] >= 4
    assert result["raw_leak_detected"] is False

    rendered = json.dumps(result, sort_keys=True)
    assert default_correct_flag() not in rendered
    assert fake_decoy_flag() not in rendered
