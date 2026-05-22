import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_history_scan_script_clean_temp_repo(tmp_path: Path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# clean\n", encoding="utf-8")
    (tmp_path / "GUIDE.md").write_text("# guide\n", encoding="utf-8")
    (tmp_path / "docs" / "notes.md").write_text("Generic release notes.\n", encoding="utf-8")

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "-q", "-m", "init"],
        cwd=tmp_path,
        check=True,
    )

    result = subprocess.run(
        [str(ROOT / "scripts" / "history-scan.sh"), "--repo", str(tmp_path), "--json"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "ok"
    assert data["high"] == []


def test_history_scan_script_syntax():
    result = subprocess.run(
        ["bash", "-n", str(ROOT / "scripts" / "history-scan.sh")],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
