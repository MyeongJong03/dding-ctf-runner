from pathlib import Path

from ctf_runner.codex_notice import clear_notices, notice_status


def _worker_home(tmp_path: Path) -> Path:
    home = tmp_path / ".codex-workers" / "worker-1"
    home.mkdir(parents=True)
    return home


def test_notice_status_reports_safe_candidates_without_reading_protected_files(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    home = _worker_home(tmp_path)
    safe = home / "cache" / "announcement.json"
    safe.parent.mkdir()
    safe.write_text("cached notice\n", encoding="utf-8")
    manual = home / "models_cache.json"
    manual.write_text("model cache\n", encoding="utf-8")
    (home / "auth.json").write_text("do-not-read\n", encoding="utf-8")
    (home / "config.toml").write_text('model = "gpt-test"\n', encoding="utf-8")
    session_notice = home / "sessions" / "2026" / "notice.json"
    session_notice.parent.mkdir(parents=True)
    session_notice.write_text("session transcript\n", encoding="utf-8")

    data = notice_status("worker-1")
    worker = data["workers"][0]

    assert [item["path"] for item in worker["safe_notice_candidates"]] == ["cache/announcement.json"]
    assert [item["path"] for item in worker["manual_review_required"]] == ["models_cache.json"]


def test_clear_notices_dry_run_does_not_delete(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    home = _worker_home(tmp_path)
    safe = home / "cache" / "notification.json"
    safe.parent.mkdir()
    safe.write_text("cached notice\n", encoding="utf-8")

    data = clear_notices("worker-1", apply=False)

    assert data["dry_run"] is True
    assert data["deleted"] == []
    assert safe.exists()


def test_clear_notices_apply_deletes_only_safe_notice_candidates(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    home = _worker_home(tmp_path)
    safe = home / "cache" / "tips.json"
    safe.parent.mkdir()
    safe.write_text("cached notice\n", encoding="utf-8")
    manual = home / "models_cache.json"
    manual.write_text("model cache\n", encoding="utf-8")
    auth = home / "auth.json"
    auth.write_text("do-not-delete\n", encoding="utf-8")
    config = home / "config.toml"
    config.write_text('model = "gpt-test"\n', encoding="utf-8")
    session_notice = home / "sessions" / "2026" / "announcement.json"
    session_notice.parent.mkdir(parents=True)
    session_notice.write_text("session transcript\n", encoding="utf-8")

    data = clear_notices("worker-1", apply=True)

    assert data["dry_run"] is False
    assert [item["path"] for item in data["deleted"]] == ["cache/tips.json"]
    assert not safe.exists()
    assert manual.exists()
    assert auth.exists()
    assert config.exists()
    assert session_notice.exists()
