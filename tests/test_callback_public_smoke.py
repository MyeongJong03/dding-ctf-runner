from __future__ import annotations

from pathlib import Path

from ctf_runner import tunnel_manager


def test_public_smoke_uses_mock_http_provider_and_stops(tmp_path: Path, monkeypatch):
    stopped: list[str] = []

    def fake_start_tunnel(provider: str, local_port: int, **kwargs):
        return {
            "status": "started",
            "tunnel_id": "fake-tunnel",
            "provider": provider,
            "provider_type": "http",
            "local_port": local_port,
            "local_url": f"http://127.0.0.1:{local_port}",
            "public_url": f"http://127.0.0.1:{local_port}",
        }

    def fake_stop_tunnel(tunnel_id: str, **kwargs):
        stopped.append(tunnel_id)
        return {"status": "stopped", "tunnel_id": tunnel_id, "stopped": True}

    monkeypatch.setattr(tunnel_manager, "start_tunnel", fake_start_tunnel)
    monkeypatch.setattr(tunnel_manager, "stop_tunnel", fake_stop_tunnel)

    result = tunnel_manager.run_callback_public_smoke(provider="cloudflared", allow_public=True, state_root=tmp_path)

    assert result["status"] == "ok"
    assert result["http_probe"]["ok"] is True
    assert result["listener"]["hit_count"] == 1
    assert stopped == ["fake-tunnel"]
    assert result["listener_stop"]["status"] == "stopped"
    rendered = str(result)
    assert "Cookie:" not in rendered
    assert "Authorization:" not in rendered
