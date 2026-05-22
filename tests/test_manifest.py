import base64
import zipfile
from pathlib import Path

from ctf_runner.file_manifest import build_manifest


def test_manifest_categories_and_preview_redaction(tmp_path: Path):
    dummy_flag = "DH" + "{dummy_test_value}"
    (tmp_path / "app.py").write_text(f"print('{dummy_flag}')\n", encoding="utf-8")
    (tmp_path / "config.yaml").write_text("debug: true\n", encoding="utf-8")
    (tmp_path / "chall").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    png_bytes = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=")
    (tmp_path / "pixel.png").write_bytes(png_bytes)
    with zipfile.ZipFile(tmp_path / "src.zip", "w") as zf:
        zf.writestr("inner.txt", "hello")

    manifest = build_manifest(tmp_path)
    by_path = {item["path"]: item for item in manifest["files"]}

    assert by_path["app.py"]["category"] == "source"
    assert by_path["config.yaml"]["category"] == "config"
    assert by_path["chall"]["category"] == "binary"
    assert by_path["pixel.png"]["category"] == "image"
    assert by_path["src.zip"]["category"] == "archive"
    assert dummy_flag not in by_path["app.py"]["preview"]
    assert "[REDACTED_FLAG]" in by_path["app.py"]["preview"]


def test_manifest_git_summary_without_dumping_git_contents(tmp_path: Path):
    git = tmp_path / ".git"
    (git / "objects" / "aa").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "objects" / "aa" / "bbbb").write_bytes(b"object")
    (tmp_path / "readme.txt").write_text("hello\n", encoding="utf-8")

    manifest = build_manifest(tmp_path)

    assert manifest["git"]["present"] is True
    assert manifest["git"]["repositories"][0]["head_exists"] is True
    assert manifest["git"]["repositories"][0]["commit_object_exists"] is True
    assert ".git/HEAD" not in {item["path"] for item in manifest["files"]}
