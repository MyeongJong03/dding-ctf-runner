import json
from pathlib import Path

from ctf_runner.ingest import ingest_text_challenge


def test_statement_only_challenge_ingest_generates_brief(tmp_path: Path):
    result = ingest_text_challenge(
        "text-1",
        text="Solve this statement only challenge.",
        contest_id="unit",
        category="web",
        name="Text One",
        output_root=tmp_path,
        points=100,
        hints=["Inspect the endpoint carefully."],
        tags=["web", "logic"],
    )

    challenge_dir = tmp_path / "unit" / "text-1"

    assert result["status"] == "ok"
    assert result["ingest_type"] == "text"
    assert (challenge_dir / "raw" / "challenge.md").exists()
    assert (challenge_dir / "manifest" / "manifest.json").exists()
    assert (challenge_dir / "manifest" / "scan.json").exists()
    brief = (challenge_dir / "brief.md").read_text(encoding="utf-8")
    assert "Text One" in brief
    assert "Solve this statement only challenge." in brief
    assert "Inspect the endpoint carefully." in brief


def test_text_ingest_redacts_raw_flag_like_content(tmp_path: Path):
    raw_flag = _flag_like("flag", "not-a-real-secret-but-flag-shaped")
    result = ingest_text_challenge(
        "text-2",
        text=f"The sample output says {raw_flag}",
        contest_id="unit",
        category="misc",
        name="Flag Shaped",
        output_root=tmp_path,
    )
    challenge_dir = tmp_path / "unit" / "text-2"
    rendered = json.dumps(result, sort_keys=True)
    challenge_md = (challenge_dir / "raw" / "challenge.md").read_text(encoding="utf-8")
    brief = (challenge_dir / "brief.md").read_text(encoding="utf-8")

    assert raw_flag not in rendered
    assert raw_flag not in challenge_md
    assert raw_flag not in brief
    assert "[REDACTED" in challenge_md


def _flag_like(prefix: str, body: str) -> str:
    return prefix + "{" + body + "}"
