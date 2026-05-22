from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from ctf_runner.callback_server import listener_hits, listener_status, start_listener, stop_listener


def test_callback_listener_loopback_start_hit_stop(tmp_path: Path):
    listener = start_listener(state_root=tmp_path)
    try:
        assert listener["status"] == "running"
        assert listener["host"] == "127.0.0.1"
        assert int(listener["port"]) > 0

        with urllib.request.urlopen(f'{listener["local_url"]}/ping', timeout=5) as response:
            assert response.status == 200

        status = listener_status(listener["listener_id"], state_root=tmp_path)
        assert status["hit_count"] == 1
    finally:
        stopped = stop_listener(listener["listener_id"], state_root=tmp_path)
    assert stopped["status"] == "stopped"


def test_callback_hits_store_redacted_summary_only(tmp_path: Path):
    listener = start_listener(state_root=tmp_path)
    secret = "abc" + "def" + "ghi"
    try:
        request = urllib.request.Request(
            f'{listener["local_url"]}/collect?token={secret}&safe=visible',
            data=f"session={secret}&note=visible".encode(),
            headers={
                "Authorization": "Bearer " + secret,
                "Cookie": "sessionid=" + secret,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200

        hits = listener_hits(listener["listener_id"], state_root=tmp_path)
        rendered = json.dumps(hits, sort_keys=True)
        assert hits["hit_count"] == 1
        assert secret not in rendered
        assert "visible" not in rendered
        assert "[REDACTED]" in rendered
        hit = hits["hits"][0]
        assert hit["query"]["keys"] == ["safe", "token"]
        assert "Authorization" in hit["headers"]["sensitive_names"]
        assert hit["body"]["sensitive_keys"] == ["session"]
    finally:
        stop_listener(listener["listener_id"], state_root=tmp_path)


def test_hit_path_token_is_redacted_and_json_readable(tmp_path: Path):
    listener = start_listener(state_root=tmp_path)
    path_value = "path" + "secret"
    try:
        with urllib.request.urlopen(f'{listener["local_url"]}/hit/{path_value}', timeout=5) as response:
            assert response.status == 200

        hits = listener_hits(listener["listener_id"], state_root=tmp_path)
        rendered = json.dumps(hits, sort_keys=True)
        assert path_value not in rendered
        assert hits["hits"][0]["endpoint"]["kind"] == "hit"
        assert hits["hits"][0]["endpoint"]["path_token_value"] == "[REDACTED]"
    finally:
        stop_listener(listener["listener_id"], state_root=tmp_path)
