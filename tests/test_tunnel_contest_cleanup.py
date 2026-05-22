from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from ctf_runner.contest_control import disarm_contest
from ctf_runner.contest_resources import list_contest_resources, record_tunnel_resource
from ctf_runner.tunnel_manager import start_tunnel


def test_disarm_cleanup_resources_stops_fake_tunnel_process(tmp_path: Path, monkeypatch):
    _install_fake_cloudflared(tmp_path, monkeypatch)
    started = start_tunnel("cloudflared", 43210, allow_public=True, state_root=tmp_path, timeout=5)
    assert started["status"] == "started"
    record_tunnel_resource("demo", started, state_root=tmp_path)

    result = disarm_contest("demo", cleanup_resources=True, state_root=tmp_path)
    time.sleep(0.1)
    listed = list_contest_resources("demo", state_root=tmp_path)

    assert result["status"] == "disarmed"
    assert result["resource_cleanup"]["status"] == "ok"
    assert listed["active_tunnel_count"] == 0
    assert listed["resources"][0]["status"] == "closed"


def test_disarm_warns_when_active_tunnel_cleanup_missing(tmp_path: Path, monkeypatch):
    _install_fake_cloudflared(tmp_path, monkeypatch)
    started = start_tunnel("cloudflared", 43211, allow_public=True, state_root=tmp_path, timeout=5)
    try:
        record_tunnel_resource("demo", started, state_root=tmp_path)
        result = disarm_contest("demo", cleanup_resources=False, state_root=tmp_path)

        assert "active callback/tunnel resources remain" in result["warning"]
        assert result["resource_cleanup"] is None
    finally:
        from ctf_runner.tunnel_manager import stop_tunnel

        stop_tunnel(started["tunnel_id"], state_root=tmp_path)


def _install_fake_cloudflared(tmp_path: Path, monkeypatch) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    fake_cloudflared = fake_bin / "cloudflared"
    fake_cloudflared.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import time",
                "print('https://fake-contest-cleanup.trycloudflare.com', flush=True)",
                "time.sleep(60)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_cloudflared.chmod(fake_cloudflared.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))
