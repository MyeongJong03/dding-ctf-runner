import json
from pathlib import Path

from ctf_runner import codex_profile
from ctf_runner.cli import main


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "dding-ctf-runner"
    repo.mkdir()
    (repo / "AGENTS.md").write_text("# Runner\n\nShort worker prompt.\n", encoding="utf-8")
    return repo


def test_init_worker_home_creates_slim_profile(monkeypatch, tmp_path):
    repo = _make_repo(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(codex_profile, "repo_root", lambda: repo)

    result = codex_profile.init_worker_home("worker-1")
    worker_dir = tmp_path / ".codex-workers" / "worker-1"

    assert result["worker_home"] == str(worker_dir)
    assert (worker_dir / "AGENTS.md").exists()
    assert (worker_dir / "config.toml").exists()
    assert result["auth_linked"] is False
    status = codex_profile.status_worker_home("worker-1")
    assert status["agents_md"]["exists"] is True
    assert status["config_toml"]["exists"] is True
    assert status["model"] is None
    assert status["model_policy"] == "auto/unpinned"
    assert status["auth_json"]["is_symlink"] is False


def test_init_worker_home_links_dummy_auth_without_reading(monkeypatch, tmp_path):
    repo = _make_repo(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(codex_profile, "repo_root", lambda: repo)
    auth_dir = tmp_path / ".codex"
    auth_dir.mkdir()
    dummy_auth = auth_dir / "auth.json"
    dummy_auth.write_text('{"dummy":"value"}', encoding="utf-8")

    result = codex_profile.init_worker_home("worker-2", link_auth=True)
    auth_link = tmp_path / ".codex-workers" / "worker-2" / "auth.json"

    assert result["auth_linked"] is True
    assert auth_link.is_symlink()
    assert auth_link.resolve() == dummy_auth.resolve()


def test_validate_worker_launch_context_flags_large_agents(monkeypatch, tmp_path):
    repo = _make_repo(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(codex_profile, "repo_root", lambda: repo)
    worker_dir = tmp_path / ".codex-workers" / "worker-3"
    worker_dir.mkdir(parents=True)
    (worker_dir / "AGENTS.md").write_text("x" * 7000, encoding="utf-8")

    result = codex_profile.validate_worker_launch_context("worker-3", repo)

    assert result["ok"] is False
    assert "worker_agents_not_slim" in result["warnings"]


def test_launch_cmd_uses_runner_cwd(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CTF_CODEX_MODEL", raising=False)
    monkeypatch.setattr(codex_profile, "repo_root", lambda: repo)
    codex_profile.init_worker_home("worker-4")

    rc = main(["codex", "launch-cmd", "--worker-id", "worker-4", "--mode", "interactive"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 0
    assert "cd ~/dding-ctf-runner" in data["command"]
    assert "CODEX_HOME=~/.codex-workers/worker-4" in data["command"]
    assert "--add-dir /home" not in data["command"]
    assert "--model" not in data["command"]
    assert "--ask-for-approval never" in data["command"]
    assert "--sandbox danger-full-access" in data["command"]
    assert data["model_policy"] == "auto/unpinned"
    assert data["model_auto_default"] is True
    assert data["dry_run"] is True


def test_launch_cmd_respects_env_overrides(monkeypatch, tmp_path):
    repo = _make_repo(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CTF_CODEX_APPROVAL", "on-request")
    monkeypatch.setenv("CTF_CODEX_SANDBOX", "workspace-write")
    monkeypatch.setenv("CTF_CODEX_EXTRA_ADD_DIRS", "~/extra:~/CTF")
    monkeypatch.setenv("CTF_CODEX_IGNORE_USER_CONFIG", "1")
    monkeypatch.setenv("CTF_CODEX_DANGER", "0")
    monkeypatch.delenv("CTF_CODEX_MODEL", raising=False)
    monkeypatch.setattr(codex_profile, "repo_root", lambda: repo)
    codex_profile.init_worker_home("worker-5")

    data = codex_profile.launch_command("worker-5", "interactive")

    assert data["approval_policy"] == "on-request"
    assert data["sandbox_mode"] == "workspace-write"
    assert data["ignore_user_config"] is True
    assert data["env"]["HOME"] == str(tmp_path / ".codex-workers" / "worker-5")
    assert data["add_dirs"].count(str(tmp_path / "CTF")) == 1
    assert str(tmp_path / "extra") in data["add_dirs"]
    assert data["model_flag_present"] is False


def test_set_model_and_model_status_preserve_auth_symlink(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(codex_profile, "repo_root", lambda: repo)
    auth_dir = tmp_path / ".codex"
    auth_dir.mkdir()
    dummy_auth = auth_dir / "auth.json"
    dummy_auth.write_text('{"dummy":"value"}', encoding="utf-8")
    codex_profile.init_worker_home("worker-1", link_auth=True)
    auth_link = tmp_path / ".codex-workers" / "worker-1" / "auth.json"

    rc = main(["codex", "set-model", "--worker-id", "worker-1", "--model", "gpt-5.4"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 0
    assert data["model"] == "gpt-5.4"
    assert data["model_policy"] == "hard-pinned"
    assert auth_link.is_symlink()
    assert auth_link.resolve() == dummy_auth.resolve()

    rc = main(["codex", "model-status", "--worker-id", "worker-1", "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 0
    assert data["workers"][0]["model"] == "gpt-5.4"
    assert data["workers"][0]["model_pinned"] is True
    assert data["workers"][0]["model_policy"] == "hard-pinned"


def test_unset_model_all_removes_model_key_and_preserves_auth_symlink(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(codex_profile, "repo_root", lambda: repo)
    auth_dir = tmp_path / ".codex"
    auth_dir.mkdir()
    dummy_auth = auth_dir / "auth.json"
    dummy_auth.write_text('{"dummy":"value"}', encoding="utf-8")
    for worker_id in ("worker-1", "worker-2", "worker-3", "worker-4", "worker-5"):
        codex_profile.init_worker_home(worker_id, link_auth=(worker_id == "worker-1"))
        codex_profile.set_worker_model(worker_id, "gpt-test")

    auth_link = tmp_path / ".codex-workers" / "worker-1" / "auth.json"
    rc = main(["codex", "unset-model-all"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert rc == 0
    assert data["model_auto_default"] is True
    assert all(worker["model"] is None for worker in data["workers"])
    assert all(worker["model_policy"] == "auto/unpinned" for worker in data["workers"])
    assert auth_link.is_symlink()
    assert auth_link.resolve() == dummy_auth.resolve()
    config_text = (tmp_path / ".codex-workers" / "worker-1" / "config.toml").read_text(encoding="utf-8")
    assert "model =" not in config_text
