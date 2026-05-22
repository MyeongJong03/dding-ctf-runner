import json
from pathlib import Path

from ctf_runner.handoff import write_handoff
from ctf_runner.solve_result import parse_solver_output
from ctf_runner.submit import hash_flag


def test_handoff_jsonl_hash_only(tmp_path: Path):
    candidate = "DDING" + "{" + "handoff_verified_value" + "}"
    result = parse_solver_output(
        "\n".join(
            [
                "STATUS: solved",
                "SUMMARY: local exploit output",
                "SOURCE: exploit_output",
                "LOCAL_VERIFIED: true",
                f"FLAG_CANDIDATE: {candidate}",
                "FACTS:",
                "- recovered candidate",
            ]
        )
    )

    record = write_handoff(tmp_path, "handoff-test", result, "unit test")
    text = (tmp_path / "handoff.jsonl").read_text(encoding="utf-8")
    loaded = json.loads(text)

    assert candidate not in text
    assert hash_flag(candidate) in text
    assert loaded["flag_hashes"] == [hash_flag(candidate)]
    assert record["challenge_id"] == "handoff-test"


def test_handoff_creates_parent_directory(tmp_path: Path):
    run_dir = tmp_path / "nested" / "run"
    record = write_handoff(run_dir, "mkdir-test", {"status": "stalled"}, "needs handoff")

    handoff = run_dir / "handoff.jsonl"
    assert handoff.exists()
    loaded = json.loads(handoff.read_text(encoding="utf-8"))
    assert loaded["challenge_id"] == "mkdir-test"
    assert record["challenge_id"] == "mkdir-test"
