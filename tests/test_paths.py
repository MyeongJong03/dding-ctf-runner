from pathlib import Path

from ctf_runner import paths


def test_docker_workspace_default_stays_ctf_on_linux(monkeypatch):
    monkeypatch.delenv("CTF_DOCKER_WORKSPACE_ROOT", raising=False)
    monkeypatch.setattr(paths.platform, "system", lambda: "Linux")
    monkeypatch.setattr(paths.Path, "home", lambda: Path("/home/operator"))

    resolved = paths.get_paths()

    assert resolved.docker_workspace_root == paths.expand("/home/operator/CTF/workspaces")


def test_docker_workspace_default_avoids_ctf_on_macos(monkeypatch):
    monkeypatch.delenv("CTF_DOCKER_WORKSPACE_ROOT", raising=False)
    monkeypatch.setattr(paths.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(paths.Path, "home", lambda: Path("/Users/operator"))

    resolved = paths.get_paths()

    assert resolved.docker_workspace_root == paths.expand("/Users/operator/.ctf-solver/runner-state/docker-workspaces")


def test_docker_workspace_env_override_wins(monkeypatch, tmp_path):
    override = tmp_path / "docker-workspaces"
    monkeypatch.setenv("CTF_DOCKER_WORKSPACE_ROOT", str(override))
    monkeypatch.setattr(paths.platform, "system", lambda: "Darwin")

    resolved = paths.get_paths()

    assert resolved.docker_workspace_root == override
