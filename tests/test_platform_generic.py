import json
import urllib.error
from pathlib import Path

from ctf_runner.platform_base import action_to_dict
from ctf_runner.platform_generic import (
    GenericPlatform,
    discover_api_candidates,
    discover_from_html,
    parse_challenges_from_json,
    try_readonly_api_candidates,
)


class FakeResponse:
    def __init__(self, payload: bytes, *, url: str = "https://ctf.example.com/", content_type: str = "application/json", status: int = 200):
        self.payload = payload
        self.offset = 0
        self.url = url
        self.status = status
        self.code = status
        self.headers = {"content-type": content_type}

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self.payload) - self.offset
        chunk = self.payload[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_html_challenge_card_and_embedded_json_parsing_redacts_signed_urls():
    html = """
    <a class="challenge-card" href="/contests/demo/challenges/warmup">Warmup</a>
    <a href="/files/warmup.zip?token=signed-download-token" download>download</a>
    <script id="__NEXT_DATA__" type="application/json">
      {"props":{"pageProps":{"challenges":[
        {"id":"rev-1","title":"Reverse One","category":"rev","points":150,"solve_count":2,
         "files":[{"filename":"rev.zip","url":"/files/rev.zip?signature=secret-value"}]}
      ]}}}
    </script>
    """

    result = discover_from_html(html, "https://ctf.example.com", "https://ctf.example.com/contests/demo")
    rendered = json.dumps(result, sort_keys=True)

    assert result["challenge_count"] == 2
    assert {item["challenge_id"] for item in result["challenges"]} == {"warmup", "rev-1"}
    assert result["challenges"][1]["has_files"] is True
    assert "signed-download-token" not in rendered
    assert "secret-value" not in rendered
    assert "?token=" not in rendered
    assert "?signature=" not in rendered


def test_parse_challenges_from_json_best_effort_shapes():
    payload = {
        "data": {
            "tasks": [
                {
                    "uuid": "crypto-a",
                    "name": "Crypto A",
                    "category": {"name": "crypto"},
                    "score": "200",
                    "solves": "5",
                    "attachments": [{"name": "../crypto?.zip", "signed_url": "/dl/crypto.zip?token=secret"}],
                }
            ]
        }
    }

    challenges = parse_challenges_from_json(payload, base_url="https://ctf.example.com")
    rendered = json.dumps(challenges, sort_keys=True)

    assert challenges[0]["challenge_id"] == "crypto-a"
    assert challenges[0]["points"] == 200
    assert challenges[0]["file_count"] == 1
    assert "token=secret" not in rendered


def test_api_candidate_extraction_is_bounded_same_origin_and_get_only():
    html = """
    <script>
      window.__routes = ["/api/contests/demo/challenges", "/api/challenges/attempt",
                         "https://evil.example/api/challenges", "/graphql?token=secret"];
    </script>
    """
    candidates = discover_api_candidates(html, [], base_url="https://ctf.example.com", contest_url="https://ctf.example.com/contests/demo")

    assert "https://ctf.example.com/api/contests/demo/challenges" in candidates
    assert not any("attempt" in item for item in candidates)
    assert not any("evil.example" in item for item in candidates)

    calls: list[tuple[str, str]] = []

    def fake_open(request, timeout=0):
        calls.append((request.get_method(), request.full_url))
        return FakeResponse(
            json.dumps({"challenges": [{"id": "web", "name": "Web", "category": "web", "points": 100}]}).encode(),
            url=request.full_url,
        )

    result = try_readonly_api_candidates(
        candidates + ["https://ctf.example.com/api/submit"],
        {},
        live=True,
        base_url="https://ctf.example.com",
        urlopen=fake_open,
        max_requests=2,
    )
    rendered = json.dumps(result, sort_keys=True)

    assert len(result["tried"]) == 2
    assert calls
    assert all(method == "GET" for method, _ in calls)
    assert "token=secret" not in rendered


def test_generic_discover_uses_auth_header_without_leaking_cookie(tmp_path: Path):
    secret_path = tmp_path / "cookie.txt"
    raw_cookie = "session=raw-cookie-value"
    secret_path.write_text(raw_cookie, encoding="utf-8")
    requests: list[object] = []

    def fake_open(request, timeout=0):
        requests.append(request)
        if request.full_url.endswith("/contests/demo"):
            return FakeResponse(
                b'<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"challenges":[{"id":"one","name":"One","category":"misc","points":50}]}}}</script>',
                url=request.full_url,
                content_type="text/html",
            )
        if request.full_url.endswith(("/contests/demo/challenges", "/contests/demo/problems", "/contests/demo/tasks")):
            raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)
        if "/api/" in request.full_url or request.full_url.endswith("/trpc"):
            raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)
        raise AssertionError(f"unexpected URL {request.full_url}")

    platform = GenericPlatform(
        config={
            "platform": "generic",
            "name": "unit",
            "base_url": "https://ctf.example.com",
            "contest_url": "https://ctf.example.com/contests/demo",
            "auth": {"method": "cookie_header_file", "path": str(secret_path)},
            "policy": {
                "allow_live_discovery": True,
                "allow_live_download": False,
                "allow_submission": False,
                "allow_instance_start": False,
            },
        },
        urlopen=fake_open,
    )

    action = platform.discover_challenges(live=True)
    rendered = json.dumps(action_to_dict(action), sort_keys=True)

    assert action.status == "ok"
    assert action.details["challenge_count"] == 1
    assert any(request.headers.get("Cookie") == raw_cookie for request in requests)
    assert raw_cookie not in rendered
    assert "session=" not in rendered
