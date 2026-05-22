import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from ctf_runner.platform_base import action_to_dict
from ctf_runner.platform_generic import GenericPlatform

pytest.importorskip("playwright.sync_api")


def test_browser_discover_extracts_network_json_and_rsc_without_post(tmp_path: Path):
    with FakeNextPlatformServer() as server:
        platform = GenericPlatform(
            config={
                "platform": "generic",
                "name": "fake_next",
                "base_url": server.base_url,
                "contest_url": f"{server.base_url}/contests/demo",
                "auth": {"method": "manual"},
                "policy": {
                    "allow_live_discovery": True,
                    "allow_live_download": False,
                    "allow_submission": False,
                    "allow_instance_start": False,
                },
                "downloads": {"root": str(tmp_path / "contests")},
            }
        )

        action = platform.browser_discover(live=True)
        payload = action_to_dict(action)
        rendered = json.dumps(payload, sort_keys=True)
        ids = {item["challenge_id"] for item in payload["details"]["challenges"]}

        assert action.status == "ok"
        assert {"web-json", "rev-rsc"}.issubset(ids)
        assert server.post_log == []
        assert not any("/api/submit" in item for item in server.get_log)
        assert any(item["path"] == "/api/submit" for item in payload["details"]["blocked_requests"])
        assert payload["details"]["storage_keys"]["local_storage_keys"] == ["authToken"]
        assert "signed-network-token" not in rendered
        assert "?token=" not in rendered


class FakeNextPlatformServer:
    def __init__(self) -> None:
        self._httpd = HTTPServer(("127.0.0.1", 0), _FakeNextHandler)
        self._httpd.owner = self  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None
        self.get_log: list[str] = []
        self.post_log: list[str] = []

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address
        return f"http://{host}:{port}"

    def __enter__(self) -> "FakeNextPlatformServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=2)
        return False


class _FakeNextHandler(BaseHTTPRequestHandler):
    server_version = "FakeNext/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    @property
    def owner(self) -> FakeNextPlatformServer:
        return self.server.owner  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        self.owner.get_log.append(self.path)
        if self.path.startswith("/contests/demo?_rsc="):
            chunk = json.dumps(
                {
                    "tasks": [
                        {
                            "id": "rev-rsc",
                            "title": "Rev RSC",
                            "category": "rev",
                            "points": 200,
                        }
                    ]
                }
            )
            self._send("text/x-component", f"self.__next_f.push([1,{json.dumps(chunk)}]);".encode())
            return
        if path == "/contests/demo":
            self._send(
                "text/html",
                b"""
                <html>
                  <body>
                    <main>Contest demo challenges</main>
                    <script>
                      localStorage.setItem('authToken', 'raw-browser-storage-value');
                      fetch('/api/challenges?token=signed-network-token');
                      fetch('/contests/demo?_rsc=rsc-secret');
                      fetch('/api/submit', {method: 'POST', body: '{}'});
                    </script>
                  </body>
                </html>
                """,
            )
            return
        if path == "/api/challenges":
            self._send(
                "application/json",
                json.dumps(
                    {
                        "challenges": [
                            {
                                "id": "web-json",
                                "name": "Web JSON",
                                "category": "web",
                                "points": 100,
                                "files": [{"name": "web.zip", "url": "/files/web.zip?token=signed-network-token"}],
                            }
                        ]
                    }
                ).encode(),
            )
            return
        if path in {"/api/problems", "/api/tasks", "/trpc", "/api/contests/demo", "/api/contests/demo/challenges"}:
            self.send_error(404)
            return
        self.send_error(404)

    def do_HEAD(self) -> None:
        self.send_error(404)

    def do_POST(self) -> None:
        self.owner.post_log.append(self.path)
        self.send_error(405)

    def _send(self, content_type: str, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
