from __future__ import annotations

import subprocess

from ctf_runner import docker_pool


def test_docker_environment_reports_cli_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(docker_pool.shutil, "which", lambda name: None)
    monkeypatch.setattr(docker_pool, "_looks_codex_sandbox", lambda: False)
    monkeypatch.setattr(docker_pool, "_is_wsl", lambda: False)
    monkeypatch.setattr(docker_pool, "DOCKER_DESKTOP_CLI", tmp_path / "missing-docker")

    result = docker_pool.docker_environment()

    assert result["classification"] == "docker_cli_missing"
    assert result["base_reason"] == "docker_cli_missing"
    assert result["docker_desktop_cli"]["exists"] is False


def test_docker_environment_reports_desktop_integration_missing(monkeypatch, tmp_path):
    desktop_cli = tmp_path / "docker"
    desktop_cli.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(docker_pool.shutil, "which", lambda name: None)
    monkeypatch.setattr(docker_pool, "_looks_codex_sandbox", lambda: False)
    monkeypatch.setattr(docker_pool, "_is_wsl", lambda: True)
    monkeypatch.setattr(docker_pool, "DOCKER_DESKTOP_CLI", desktop_cli)

    result = docker_pool.docker_environment()

    assert result["classification"] == "docker_desktop_integration_missing"
    assert result["base_reason"] == "docker_desktop_integration_missing"
    assert result["docker_desktop_cli"]["exists"] is True
    assert "ln -sf" in result["docker_desktop_cli"]["symlink_hint"]


def test_image_exists_reports_docker_image_missing():
    def fake_run(cmd, **kwargs):  # noqa: ANN001 - subprocess-compatible test double.
        if cmd[:2] == ["docker", "info"]:
            return _completed(cmd, 0, '"29.0.0"\n')
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _completed(cmd, 1, stderr="Error: No such image: ctf-pwn:latest\n")
        return _completed(cmd, 1, stderr="unexpected")

    result = docker_pool.image_exists("ctf-pwn:latest", runner=fake_run)

    assert result["checked"] is True
    assert result["exists"] is False
    assert result["reason"] == "docker_image_missing"


def test_codex_sandbox_keeps_base_reason_for_docker_unreachable(monkeypatch):
    monkeypatch.setattr(docker_pool, "_looks_codex_sandbox", lambda: True)

    def fake_run(cmd, **kwargs):  # noqa: ANN001 - subprocess-compatible test double.
        return _completed(cmd, 1, stderr="Cannot connect to the Docker daemon\n")

    result = docker_pool.docker_environment(runner=fake_run)

    assert result["classification"] == "codex_sandbox_docker_unreachable"
    assert result["base_reason"] == "docker_daemon_unreachable"
    assert "normal WSL terminal" in result["diagnostic_hint"]


def _completed(cmd: list[str], returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)
