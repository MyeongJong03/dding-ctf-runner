import contextlib
import io
import json
import shutil
from pathlib import Path

from ctf_runner.cli import main


def test_metrics_record_summary_compare_and_report(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    root = tmp_path / "contests" / "demo" / "operator"

    init = _run_json(["interactive", "init", "--contest-id", "demo", "--json"])
    assert init["status"] == "ok"
    for name in [
        "events.jsonl",
        "sessions.jsonl",
        "challenge_metrics.jsonl",
        "tool_benchmarks.jsonl",
        "summary.json",
        "regression_report.md",
    ]:
        assert (root / "metrics" / name).exists()

    before = _run_json(["interactive", "metrics", "summary", "--contest-id", "demo", "--json"])
    before_path = tmp_path / "before-summary.json"
    shutil.copyfile(root / "metrics" / "summary.json", before_path)

    _run_json(["interactive", "metrics", "record", "--contest-id", "demo", "--agent", "a1", "--event", "claim", "--challenge-id", "birdhouse", "--json"])
    _run_json(
        [
            "interactive",
            "metrics",
            "record",
            "--contest-id",
            "demo",
            "--event",
            "usage_observed",
            "--data-json",
            '{"tokens_used": 1234}',
            "--json",
        ]
    )
    _run_json(
        [
            "interactive",
            "metrics",
            "record",
            "--contest-id",
            "demo",
            "--event",
            "submit",
            "--challenge-id",
            "birdhouse",
            "--data-json",
            '{"status": "accepted"}',
            "--json",
        ]
    )
    _run_json(
        [
            "interactive",
            "metrics",
            "record",
            "--contest-id",
            "demo",
            "--event",
            "writeup",
            "--challenge-id",
            "birdhouse",
            "--data-json",
            '{"languages": ["ko", "en"]}',
            "--json",
        ]
    )
    _run_json(["interactive", "metrics", "record", "--contest-id", "demo", "--event", "cleanup", "--challenge-id", "birdhouse", "--json"])

    events = (root / "metrics" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(events) == 5

    summary = _run_json(["interactive", "metrics", "summary", "--contest-id", "demo", "--json"])
    assert before["total_events"] == 0
    assert summary["total_events"] == 5
    assert summary["sessions"] == 1
    assert summary["claimed_count"] == 1
    assert summary["submitted_count"] == 1
    assert summary["accepted_count"] == 1
    assert summary["solved_count"] == 1
    assert summary["writeup_ko_count"] == 1
    assert summary["writeup_en_count"] == 1
    assert summary["cleanup_count"] == 1
    assert summary["tokens_total_observed"] == 1234
    assert summary["avg_time_to_solve_sec"] is not None

    compare = _run_json(["interactive", "metrics", "compare", "--before", str(before_path), "--after", str(root / "metrics" / "summary.json"), "--json"])
    assert compare["deltas"]["total_events"] == 5
    assert compare["deltas"]["tokens_total_observed"] == 1234

    report_path = tmp_path / "report.md"
    report = _run_json(["interactive", "metrics", "report", "--contest-id", "demo", "--output", str(report_path), "--json"])
    assert report["status"] == "ok"
    assert report_path.exists()
    assert "Interactive Metrics Report: demo" in report_path.read_text(encoding="utf-8")


def _run_json(argv: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    assert code == 0, output
    return json.loads(output)
