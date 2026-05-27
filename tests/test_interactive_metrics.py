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


def test_publish_snapshot_blocks_active_contest_without_confirm(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    _run_json(["interactive", "init", "--contest-id", "demo", "--json"])

    blocked = _run_json_fail(["interactive", "metrics", "publish-snapshot", "--contest-id", "demo", "--output-root", str(tmp_path / "public"), "--json"])

    assert blocked["status"] == "blocked"
    assert blocked["public_safe"] is False


def test_publish_snapshot_creates_public_safe_files_and_stalled_blockers(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    root = tmp_path / "contests" / "demo" / "operator"
    _run_json(["interactive", "init", "--contest-id", "demo", "--json"])
    (root / "board.json").write_text(
        json.dumps(
            {
                "contest_id": "demo",
                "challenges": [
                    {"challenge_id": "birdhouse", "name": "Birdhouse", "category": "misc", "status": "todo"},
                    {"challenge_id": "web2", "name": "Web Two", "category": "web", "status": "todo"},
                ],
            }
        ),
        encoding="utf-8",
    )
    synthetic_flag = "FLAG" + "{synthetic_public_leak_marker}"
    synthetic_token = "TOKEN_SYNTHETIC_MARKER"
    synthetic_session = "SESSION_SYNTHETIC_MARKER"
    _run_json(["interactive", "metrics", "record", "--contest-id", "demo", "--agent", "a1", "--event", "claim", "--challenge-id", "birdhouse", "--json"])
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
            json.dumps({"status": "accepted", "flag": synthetic_flag, "token": synthetic_token}),
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
            json.dumps({"languages": ["ko", "en"], "body": "full writeup should not appear"}),
            "--json",
        ]
    )
    _run_json(["interactive", "metrics", "record", "--contest-id", "demo", "--event", "cleanup", "--challenge-id", "birdhouse", "--json"])
    _run_json(
        [
            "interactive",
            "metrics",
            "record",
            "--contest-id",
            "demo",
            "--event",
            "stalled",
            "--challenge-id",
            "web2",
            "--data-json",
            json.dumps({"reason": f"blocked on auth model {synthetic_session}"}),
            "--json",
        ]
    )

    output_root = tmp_path / "repo-metrics" / "contests" / "demo"
    result = _run_json(
        [
            "interactive",
            "metrics",
            "publish-snapshot",
            "--contest-id",
            "demo",
            "--output-root",
            str(output_root),
            "--contest-ended",
            "--json",
        ]
    )

    assert result["status"] == "ok"
    assert result["public_safe"] is True
    for name in ["summary.public.json", "solved.public.md", "stalled.public.md", "approaches.public.md", "regression.public.md"]:
        assert (output_root / name).exists()
    combined = "\n".join(path.read_text(encoding="utf-8") for path in output_root.glob("*.public.*"))
    assert synthetic_flag not in combined
    assert synthetic_token not in combined
    assert synthetic_session not in combined
    assert "full writeup should not appear" not in combined
    stalled = (output_root / "stalled.public.md").read_text(encoding="utf-8")
    assert "Web Two" in stalled
    assert "blocked on auth model" in stalled
    assert "no writeup" in stalled.lower()


def test_dashboard_baseline_and_compare_public(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CTF_CONTESTS_ROOT", str(tmp_path / "contests"))
    metrics_root = tmp_path / "metrics"
    contest_root = metrics_root / "contests" / "demo"
    contest_root.mkdir(parents=True)
    before = contest_root / "before.public.json"
    after = contest_root / "summary.public.json"
    before.write_text(json.dumps({"solved_count": 1, "stalled_count": 2, "accepted_count": 1, "writeup_ko_count": 1, "writeup_en_count": 0, "cleanup_count": 1, "tokens_total_observed": 100, "avg_time_to_solve_sec": 12.5, "attempts_total": 3}), encoding="utf-8")
    after.write_text(json.dumps({"contest_id": "demo", "solved_count": 3, "stalled_count": 1, "accepted_count": 3, "writeup_ko_count": 2, "writeup_en_count": 1, "cleanup_count": 2, "tokens_total_observed": 250, "avg_time_to_solve_sec": 10.0, "attempts_total": 7}), encoding="utf-8")

    baseline = _run_json(["interactive", "metrics", "baseline", "--name", "unit", "--output-dir", str(metrics_root / "runs"), "--json"])
    dashboard = _run_json(["interactive", "metrics", "dashboard", "--output", str(metrics_root / "dashboard.md"), "--json"])
    compare = _run_json(["interactive", "metrics", "compare-public", "--before", str(before), "--after", str(after), "--json"])

    assert Path(baseline["baseline_path"]).exists()
    assert (metrics_root / "dashboard.md").exists()
    assert dashboard["public_snapshot_count"] == 1
    assert compare["deltas"]["solved_count"] == 2
    assert compare["deltas"]["stalled_count"] == -1
    assert compare["deltas"]["tokens_total_observed"] == 150


def _run_json(argv: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    assert code == 0, output
    return json.loads(output)


def _run_json_fail(argv: list[str]) -> dict:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    assert code != 0, output
    return json.loads(output)
