from __future__ import annotations

import contextlib
import io
import json
from typing import Any

from ctf_runner.cli import main


def test_tunnel_start_default_redacts_public_url(monkeypatch):
    secret = "abc" + "def" + "ghi"
    monkeypatch.setattr("ctf_runner.cli.listener_status", lambda listener_id: {"status": "running", "listener_id": listener_id, "port": 8080})
    monkeypatch.setattr("ctf_runner.cli.start_tunnel", lambda provider, port, **kwargs: _tunnel_payload(f"https://phase12-secret.trycloudflare.com/cb?token={secret}"))

    result, code, raw = _run_json(["tunnel", "start", "--listener-id", "cb-1", "--allow-public", "--json"])

    assert code == 0
    assert "public_url" not in result
    assert result["public_url_display"] == "https://<redacted>.trycloudflare.com"
    assert "phase12-secret" not in raw
    assert secret not in raw
    assert "token=" not in raw


def test_tunnel_start_show_public_url_strips_query(monkeypatch):
    secret = "abc" + "def" + "ghi"
    monkeypatch.setattr("ctf_runner.cli.listener_status", lambda listener_id: {"status": "running", "listener_id": listener_id, "port": 8080})
    monkeypatch.setattr("ctf_runner.cli.start_tunnel", lambda provider, port, **kwargs: _tunnel_payload(f"https://phase12-visible.trycloudflare.com/path?token={secret}"))

    result, code, raw = _run_json(["tunnel", "start", "--listener-id", "cb-1", "--allow-public", "--show-public-url", "--json"])

    assert code == 0
    assert result["public_url_display"] == "https://phase12-visible.trycloudflare.com/path"
    assert secret not in raw
    assert "token=" not in raw


def test_callback_public_smoke_redacts_nested_tunnel_url(monkeypatch):
    secret = "abc" + "def" + "ghi"
    monkeypatch.setattr(
        "ctf_runner.cli.run_callback_public_smoke",
        lambda **kwargs: {
            "status": "ok",
            "listener": {"status": "stopped", "listener_id": "cb-1"},
            "tunnel": _tunnel_payload(f"https://phase12-nested.trycloudflare.com/ping?session={secret}"),
            "http_probe": {"attempted": True, "ok": True},
        },
    )

    result, code, raw = _run_json(["callback", "public-smoke", "--allow-public", "--json"])

    assert code == 0
    assert result["tunnel"]["public_url_display"] == "https://<redacted>.trycloudflare.com"
    assert "phase12-nested" not in raw
    assert secret not in raw
    assert "session=" not in raw


def _tunnel_payload(public_url: str) -> dict[str, Any]:
    return {
        "status": "started",
        "tunnel_id": "tn-1",
        "provider": "cloudflared",
        "provider_type": "http",
        "local_port": 8080,
        "local_url": "http://127.0.0.1:8080",
        "public_url": public_url,
        "pid": 123,
    }


def _run_json(argv: list[str]) -> tuple[dict[str, Any], int, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(argv)
    output = buffer.getvalue()
    return json.loads(output), code, output
