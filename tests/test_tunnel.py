from ctf_runner import tunnel


def test_tunnel_detection_missing_is_graceful(monkeypatch):
    monkeypatch.setattr(tunnel.shutil, "which", lambda _name: None)
    result = tunnel.check_tunnel_providers()
    assert result["ok"] is False
    assert result["public_provider_installed"] is False
    assert result["recommendation"]["status"] == "missing_tunnel_provider"
    assert all(provider["installed"] is False for provider in result["providers"])


def test_tunnel_detection_cloudflared_recommended(monkeypatch):
    monkeypatch.setattr(tunnel.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "cloudflared" else None)
    monkeypatch.setattr(tunnel, "_version_summary", lambda _exe, _args: "cloudflared version test")
    result = tunnel.check_tunnel_providers()
    assert result["ok"] is True
    assert result["public_provider_installed"] is True
    assert result["recommendation"]["provider"] == "cloudflared"
