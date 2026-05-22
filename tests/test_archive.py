import io
import tarfile
import zipfile
from pathlib import Path

from ctf_runner.archive import safe_extract_archive


def test_zip_normal_extract(tmp_path: Path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("src/app.py", "print('ok')\n")

    dest = tmp_path / "out"
    result = safe_extract_archive(archive, dest, limits=None)

    assert result["errors"] == []
    assert result["extracted_files_count"] == 1
    assert (dest / "src" / "app.py").read_text() == "print('ok')\n"


def test_zip_path_traversal_blocked(tmp_path: Path):
    archive = tmp_path / "traversal.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.txt", "blocked\n")
        zf.writestr("safe.txt", "ok\n")

    dest = tmp_path / "out"
    result = safe_extract_archive(archive, dest, limits=None)

    assert result["extracted_files_count"] == 1
    assert any(item["reason"] == "path traversal entry" for item in result["skipped_entries"])
    assert not (tmp_path / "escape.txt").exists()
    assert (dest / "safe.txt").exists()


def test_tar_symlink_entry_skipped(tmp_path: Path):
    archive = tmp_path / "links.tar"
    with tarfile.open(archive, "w") as tf:
        data = b"ok\n"
        info = tarfile.TarInfo("safe.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("linked")
        link.type = tarfile.SYMTYPE
        link.linkname = "safe.txt"
        tf.addfile(link)

    dest = tmp_path / "out"
    result = safe_extract_archive(archive, dest, limits=None)

    assert result["extracted_files_count"] == 1
    assert (dest / "safe.txt").exists()
    assert not (dest / "linked").exists()
    assert any("symlink" in item["reason"] for item in result["skipped_entries"])
