from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ctf_runner import docker_pool


class FakeDocker:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.containers: dict[str, dict[str, str]] = {}

    def run(self, cmd, **kwargs):  # noqa: ANN001 - subprocess-compatible test double.
        self.commands.append(list(cmd))
        if cmd[:2] == ["docker", "info"]:
            return _completed(cmd, 0, '"25.0.0"\n')
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _completed(cmd, 0)
        if cmd[:2] == ["docker", "run"]:
            name = cmd[cmd.index("--name") + 1]
            image = cmd[-3]
            self.containers[name] = {"status": "running", "image": image}
            return _completed(cmd, 0, name + "\n")
        if cmd[:2] == ["docker", "inspect"]:
            name = cmd[2]
            if name not in self.containers:
                return _completed(cmd, 1, stderr="Error: No such object\n")
            item = self.containers[name]
            return _completed(cmd, 0, json.dumps([{"Name": "/" + name, "State": {"Status": item["status"]}, "Config": {"Image": item["image"]}}]))
        if cmd[:2] == ["docker", "exec"]:
            name = cmd[2]
            if name not in self.containers:
                return _completed(cmd, 1, stderr="Error: No such container\n")
            return _completed(cmd, 0, "exec ok\n")
        if cmd[:3] == ["docker", "rm", "-f"]:
            name = cmd[3]
            if name not in self.containers:
                return _completed(cmd, 1, stderr="Error: No such container\n")
            del self.containers[name]
            return _completed(cmd, 0, name + "\n")
        if cmd[:2] == ["docker", "ps"]:
            return _completed(cmd, 0, "\n".join(sorted(self.containers)) + ("\n" if self.containers else ""))
        return _completed(cmd, 1, stderr="unexpected command")


def test_container_name_and_start_command_are_contest_scoped(tmp_path: Path):
    workspace = tmp_path / "workspace"

    cmd = docker_pool.build_start_command("contest-1", "worker-1", workspace=workspace)

    assert docker_pool.container_name("contest-1", "worker-1") == "ctf-runner-contest-1-worker-1"
    assert "--name" in cmd
    assert "ctf-runner-contest-1-worker-1" in cmd
    assert f"{workspace.resolve()}:/workspace" in cmd
    assert "-e" not in cmd
    assert "--env" not in cmd
    assert "--env-file" not in cmd


def test_start_exec_status_and_cleanup_write_redacted_state(tmp_path: Path):
    fake = FakeDocker()
    state_root = tmp_path / "state"
    workspace = tmp_path / "workspace"

    start = docker_pool.start_container("contest-1", "worker-1", workspace=workspace, state_root=state_root, runner=fake.run)
    candidate = "FLAG" + "{" + "secret-value" + "}"
    exec_result = docker_pool.exec_in_container(
        "contest-1",
        "worker-1",
        "echo " + candidate,
        state_root=state_root,
        runner=fake.run,
    )
    status = docker_pool.status_container("contest-1", "worker-1", state_root=state_root, runner=fake.run)
    cleanup = docker_pool.cleanup_containers("contest-1", state_root=state_root, runner=fake.run)

    assert start["status"] == "running"
    assert exec_result["status"] == "ok"
    assert status["status"] == "running"
    assert cleanup["status"] == "ok"
    root = state_root / "contests" / "contest-1" / "docker"
    containers = json.loads((root / "containers.json").read_text(encoding="utf-8"))
    worker_state = containers["containers"]["worker-1"]
    assert worker_state["container_name"] == "ctf-runner-contest-1-worker-1"
    assert worker_state["exec_count"] == 1
    assert candidate not in (root / "worker-1.exec.log").read_text(encoding="utf-8")
    assert not fake.containers


def test_workspace_under_mnt_c_reports_warning(tmp_path: Path, monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(docker_pool, "is_under_mnt_c", lambda path: True)

    result = docker_pool.start_container("contest", "worker-1", workspace=tmp_path / "ws", state_root=tmp_path / "state", runner=fake.run)

    assert result["workspace_warning"] == "workspace_under_mnt_c"


def _completed(cmd: list[str], returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)
