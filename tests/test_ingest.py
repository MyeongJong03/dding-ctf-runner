import json
import zipfile
from pathlib import Path

from ctf_runner.ingest import ingest_challenge


def test_ingest_run_creates_outputs(tmp_path: Path):
    sample = tmp_path / "sample"
    sample.mkdir()
    dummy_flag = "DH" + "{dummy_test_value}"
    (sample / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n@app.route('/')\ndef index(): pass\n", encoding="utf-8")
    (sample / "notes.txt").write_text(f"candidate {dummy_flag}\n", encoding="utf-8")
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(sample / "app.py", "app.py")
        zf.write(sample / "notes.txt", "notes.txt")

    result = ingest_challenge(
        "ingest-test",
        [archive],
        contest_id="unit",
        category="web",
        name="Ingest Test",
        output_root=tmp_path / "contests",
    )

    challenge_dir = tmp_path / "contests" / "unit" / "ingest-test"
    assert result["status"] == "ok"
    assert (challenge_dir / "raw" / "sample.zip").exists()
    assert (challenge_dir / "extracted").exists()
    assert (challenge_dir / "manifest" / "manifest.json").exists()
    assert (challenge_dir / "manifest" / "scan.json").exists()
    assert (challenge_dir / "manifest" / "ingest_summary.json").exists()
    assert (challenge_dir / "brief.md").exists()
    assert dummy_flag not in (challenge_dir / "brief.md").read_text(encoding="utf-8")
    manifest = json.loads((challenge_dir / "manifest" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["file_count"] >= 3
