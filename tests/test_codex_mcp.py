from __future__ import annotations

import json
from pathlib import Path

from ctf_runner import codex_doctor


def _config_text() -> str:
    return """
[mcp_servers.dreamhack_solver]
command = "dreamhack-secret-command"
args = ["--opaque", "raw-arg-value"]
env = { OPAQUE = "raw-env-value" }

[mcp_servers.ReVa]
command = "reva-secret-command"
args = ["--private-key", "secret-key-value"]

[mcp_servers.ctf_solver]
command = "ctf-secret-command"
env = { OPAQUE = "ctf-raw-env-value" }
"""


def test_detect_mcp_servers_returns_names_only(tmp_path: Path):
    config = tmp_path / "config.toml"
    config.write_text(_config_text(), encoding="utf-8")

    servers = codex_doctor.detect_mcp_servers(config)

    assert servers == ["ReVa", "ctf_solver", "dreamhack_solver"]


def test_diagnose_mcp_legacy_summarizes_without_raw_config(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    global_config = tmp_path / ".codex" / "config.toml"
    worker_config = tmp_path / ".codex-workers" / "worker-1" / "config.toml"
    global_config.parent.mkdir(parents=True)
    worker_config.parent.mkdir(parents=True)
    global_config.write_text(_config_text(), encoding="utf-8")
    worker_config.write_text(
        """
[mcp_servers.ctf_solver]
command = "worker-secret-command"
env = { OPAQUE = "worker-raw-env-value" }
""",
        encoding="utf-8",
    )

    data = codex_doctor.diagnose_mcp_legacy()
    rendered = json.dumps(data, sort_keys=True)

    assert data["legacy_dreamhack_present"] is True
    assert data["legacy_dreamhack_global"] is True
    assert data["canonical_ctf_solver_present"] is True
    assert data["reva_present"] is True
    assert data["global_servers"] == ["ReVa", "ctf_solver", "dreamhack_solver"]
    assert data["worker_servers"] == [{"path": str(worker_config), "servers": ["ctf_solver"]}]
    for raw in (
        "dreamhack-secret-command",
        "raw-arg-value",
        "raw-env-value",
        "reva-secret-command",
        "worker-secret-command",
        "worker-raw-env-value",
    ):
        assert raw not in rendered
