from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from ctf_runner.callback_server import listener_status, start_listener, stop_listener
from ctf_runner.contest_control import contest_status
from ctf_runner.contest_resources import (
    cleanup_contest_resources,
    list_contest_resources,
    record_callback_resource,
    record_tunnel_resource,
    update_callback_resource,
)


def test_record_callback_resource_list_status_and_close(tmp_path: Path):
    listener = start_listener(state_root=tmp_path)
    try:
        record = record_callback_resource("demo", listener, challenge_id="web-1", worker_id="worker-1", state_root=tmp_path)
        assert record["status"] == "active"

        with urllib.request.urlopen(f'{listener["local_url"]}/ping', timeout=5) as response:
            assert response.status == 200
        update_callback_resource(listener["listener_id"], listener=listener_status(listener["listener_id"], state_root=tmp_path), state_root=tmp_path)

        listed = list_contest_resources("demo", state_root=tmp_path)
        assert listed["active_callback_count"] == 1
        assert listed["active_tunnel_count"] == 0
        assert listed["resources"][0]["hit_count"] == 1

        status = contest_status("demo", db_path=tmp_path / "state.db", state_root=tmp_path)
        assert status["active_callback_count"] == 1
        assert status["last_callback_hit_at"]
    finally:
        stopped = stop_listener(listener["listener_id"], state_root=tmp_path)
        update_callback_resource(listener["listener_id"], listener=stopped, state_root=tmp_path)

    after = list_contest_resources("demo", state_root=tmp_path)
    assert after["active_callback_count"] == 0
    assert after["resources"][0]["status"] == "closed"


def test_record_tunnel_resource_redacts_public_url_and_stale_detection(tmp_path: Path):
    secret = "abc" + "def" + "ghi"
    record_tunnel_resource(
        "demo",
        {
            "status": "started",
            "tunnel_id": "tn-missing",
            "provider": "cloudflared",
            "local_url": "http://127.0.0.1:9999",
            "public_url": f"https://phase12-secret.trycloudflare.com/path?token={secret}",
            "pid": 99999999,
        },
        state_root=tmp_path,
    )

    listed = list_contest_resources("demo", state_root=tmp_path)
    rendered = json.dumps(listed, sort_keys=True)

    assert listed["active_tunnel_count"] == 0
    assert listed["stale_resource_count"] == 1
    assert "phase12-secret" not in rendered
    assert secret not in rendered
    assert listed["resources"][0]["public_url_display"] == "https://<redacted>.trycloudflare.com"


def test_cleanup_resources_uses_managers_and_records_events(tmp_path: Path, monkeypatch):
    calls: list[tuple[str, str]] = []
    record_callback_resource(
        "demo",
        {"status": "running", "listener_id": "cb-fake", "local_url": "http://127.0.0.1:4444", "pid": 123, "hit_count": 0},
        state_root=tmp_path,
    )
    record_tunnel_resource(
        "demo",
        {
            "status": "started",
            "tunnel_id": "tn-fake",
            "provider": "cloudflared",
            "local_url": "http://127.0.0.1:4444",
            "public_url": "https://cleanup-test.trycloudflare.com",
            "pid": 456,
        },
        state_root=tmp_path,
    )

    monkeypatch.setattr("ctf_runner.contest_resources.listener_status", lambda listener_id, **kwargs: {"status": "stale", "listener_id": listener_id, "hit_count": 0})
    monkeypatch.setattr("ctf_runner.contest_resources.tunnel_status", lambda tunnel_id, **kwargs: {"status": "stale", "tunnel_id": tunnel_id, "provider": "cloudflared"})

    def fake_stop_listener(listener_id: str, **kwargs):
        calls.append(("callback", listener_id))
        return {"status": "stopped", "listener_id": listener_id, "stopped": True, "hit_count": 0}

    def fake_stop_tunnel(tunnel_id: str, **kwargs):
        calls.append(("tunnel", tunnel_id))
        return {"status": "stopped", "tunnel_id": tunnel_id, "stopped": True, "provider": "cloudflared"}

    monkeypatch.setattr("ctf_runner.contest_resources.stop_listener", fake_stop_listener)
    monkeypatch.setattr("ctf_runner.contest_resources.stop_tunnel", fake_stop_tunnel)

    result = cleanup_contest_resources("demo", state_root=tmp_path)

    assert result["status"] == "ok"
    assert sorted(calls) == [("callback", "cb-fake"), ("tunnel", "tn-fake")]
    assert result["cleaned_count"] == 2
    assert (tmp_path / "contests" / "demo" / "resources" / "cleanup_events.jsonl").exists()
