from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from ctf_runner import tunnel_manager


def test_cloudflared_url_parse_redacts_query():
    secret = "abc" + "def" + "ghi"
    output = f"trycloudflare.com | https://phase12.trycloudflare.com/path?token={secret}"

    parsed = tunnel_manager.parse_cloudflared_public_url(output)

    assert parsed.startswith("https://phase12.trycloudflare.com")
    assert secret not in parsed


def test_bore_output_parse_reports_tcp_forward():
    parsed = tunnel_manager.parse_bore_public_endpoint("listening at bore.pub:49152")

    assert parsed is not None
    assert parsed["provider_type"] == "tcp_forward"
    assert parsed["public_url"] == "tcp://bore.pub:49152"
    assert parsed["public_port"] == 49152


def test_public_tunnel_requires_allow_public(tmp_path: Path):
    result = tunnel_manager.start_tunnel("cloudflared", 12345, allow_public=False, state_root=tmp_path)

    assert result["status"] == "blocked"
    assert result["reason"] == "public_tunnel_requires_allow_public"


def test_fake_cloudflared_start_parse_and_stop_cleans_pid(tmp_path: Path, monkeypatch):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_cloudflared = fake_bin / "cloudflared"
    fake_cloudflared.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import time",
                "print('https://fake-phase12.trycloudflare.com', flush=True)",
                "time.sleep(60)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    fake_cloudflared.chmod(fake_cloudflared.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))

    started = tunnel_manager.start_tunnel("cloudflared", 43210, allow_public=True, state_root=tmp_path, timeout=5)
    try:
        assert started["status"] == "started"
        assert started["provider_type"] == "http"
        assert started["public_url"] == "https://fake-phase12.trycloudflare.com"
        pid_path = tunnel_manager.tunnel_root(started["tunnel_id"], state_root=tmp_path) / "provider.pid"
        assert pid_path.exists()
    finally:
        stopped = tunnel_manager.stop_tunnel(started["tunnel_id"], state_root=tmp_path)

    assert stopped["status"] == "stopped"
    assert stopped["stopped"] is True
    assert not pid_path.exists()
    time.sleep(0.1)
    assert tunnel_manager.tunnel_status(started["tunnel_id"], state_root=tmp_path)["status"] == "stopped"
