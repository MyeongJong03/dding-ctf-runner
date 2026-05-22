from __future__ import annotations

import subprocess

from ctf_runner import docker_pool


class BenchmarkDocker:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.containers: set[str] = set()

    def run(self, cmd, **kwargs):  # noqa: ANN001 - subprocess-compatible test double.
        self.commands.append(list(cmd))
        if cmd[:2] == ["docker", "info"]:
            return _completed(cmd, 0, '"25.0.0"\n')
        if cmd[:3] == ["docker", "run", "--rm"]:
            return _completed(cmd, 0)
        if cmd[:4] == ["docker", "run", "--platform", "linux/amd64"]:
            return _completed(cmd, 0)
        if cmd[:2] == ["docker", "run"]:
            name = cmd[cmd.index("--name") + 1]
            self.containers.add(name)
            return _completed(cmd, 0, name + "\n")
        if cmd[:2] == ["docker", "inspect"]:
            name = cmd[2]
            if name not in self.containers:
                return _completed(cmd, 1, stderr="No such object")
            return _completed(cmd, 0, '[{"State":{"Status":"running"},"Config":{"Image":"ctf-pwn:latest"}}]')
        if cmd[:2] == ["docker", "exec"]:
            return _completed(cmd, 0)
        if cmd[:3] == ["docker", "rm", "-f"]:
            self.containers.discard(cmd[3])
            return _completed(cmd, 0)
        return _completed(cmd, 1, stderr="unexpected")


def test_benchmark_reports_one_shot_and_persistent_timings(tmp_path):
    fake = BenchmarkDocker()

    result = docker_pool.benchmark(image="ctf-pwn:latest", iterations=5, state_root=tmp_path / "state", runner=fake.run)

    assert result["status"] == "ok"
    assert result["one_shot"]["average_ms"] >= 0
    assert result["one_shot_linux_amd64"]["average_ms"] >= 0
    assert result["persistent_exec"]["average_ms"] >= 0
    assert result["speedup_ratio"] >= 0
    assert len(result["one_shot"]["runs"]) == 5
    assert len(result["one_shot_linux_amd64"]["runs"]) == 5
    assert len(result["persistent_exec"]["runs"]) == 5
    assert sum(1 for cmd in fake.commands if cmd[:3] == ["docker", "run", "--rm"]) == 5
    assert sum(1 for cmd in fake.commands if cmd[:4] == ["docker", "run", "--platform", "linux/amd64"]) == 5
    assert sum(1 for cmd in fake.commands if cmd[:2] == ["docker", "exec"]) == 5
    assert not fake.containers


def test_benchmark_skips_cleanly_when_docker_cli_missing(monkeypatch):
    monkeypatch.setattr(docker_pool.shutil, "which", lambda name: None)

    result = docker_pool.benchmark(image="ctf-pwn:latest")

    assert result["status"] == "skipped"
    assert result["docker"]["found"] is False


def _completed(cmd: list[str], returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)
