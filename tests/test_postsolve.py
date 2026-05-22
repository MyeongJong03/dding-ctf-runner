import json
from pathlib import Path

from ctf_runner.postsolve import write_solve_summary
from ctf_runner.submit import hash_flag


def test_postsolve_summary_contains_hash_not_raw_candidate(tmp_path: Path):
    raw = "FLAG" + "{" + "postsolve_alpha_48291" + "}"
    challenge_dir = tmp_path / "contests" / "fake_ctfd" / "1001"
    manifest_dir = challenge_dir / "manifest"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "manifest.json").write_text(
        json.dumps(
            {
                "files": [
                    {
                        "path": "note.txt",
                        "sha256": "a" * 64,
                        "interesting_score": 4,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    digest = hash_flag(raw)

    result = write_solve_summary(
        "1001",
        {"name": "Local Codex Smoke", "category": "misc", "status": "solved"},
        {
            "status": "solved",
            "solver_result": {
                "summary": "read from note.txt",
                "confidence_context": {"source": "file_read", "local_verified": True},
                "flag_candidates": [{"flag_hash": digest}],
            },
            "submit_plans": [{"status": "accepted", "confidence": "high", "flag_hash": digest}],
        },
        output_dir=challenge_dir,
    )

    postsolve_dir = challenge_dir / "postsolve"
    summary_path = postsolve_dir / "solve_summary.md"
    text = summary_path.read_text(encoding="utf-8")
    assert result["status"] == "ok"
    assert result["raw_flag_present"] is False
    assert digest in text
    assert raw not in text
    assert (postsolve_dir / "writeup_draft.md").exists()
    assert (postsolve_dir / "skill_candidate.md").exists()
    assert (postsolve_dir / "artifacts_manifest.json").exists()
    assert (postsolve_dir / "timeline.jsonl").exists()
    assert (postsolve_dir / "postsolve_summary.json").exists()
    assert "skill_candidate" in json.dumps(result, sort_keys=True)
