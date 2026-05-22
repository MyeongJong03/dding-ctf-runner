from pathlib import Path

from ctf_runner.brief import render_challenge_brief


def test_brief_bounded_and_redacted(tmp_path: Path):
    dummy_flag = "DH" + "{dummy_test_value}"
    manifest = {
        "file_count": 200,
        "summary": {"total_size": 1234, "by_category": {"source": 200}, "large_files": 0},
        "git": {"present": False, "repositories": []},
        "files": [
            {
                "path": f"src/file_{index}.py",
                "category": "source",
                "interesting_score": 5,
                "reasons": [dummy_flag, "route definitions"],
            }
            for index in range(200)
        ],
    }
    scan = {
        "likely_categories": [{"category": "web", "score": 50}],
        "interesting_files": [
            {"path": f"src/file_{index}.py", "category": "source", "score": 10, "reasons": [dummy_flag]}
            for index in range(200)
        ],
        "signals_by_category": {
            "web": [
                {"kind": "route_definition", "description": "routes", "files": [f"src/file_{i}.py" for i in range(40)], "count": 40}
            ]
        },
        "recommended_first_actions": ["review routes"],
        "warnings": [],
    }

    brief = render_challenge_brief(tmp_path, manifest, scan, {"challenge_id": "brief-test", "category": "web"})

    assert len(brief.encode("utf-8")) <= 12 * 1024
    assert dummy_flag not in brief
    assert "[REDACTED_FLAG]" in brief
