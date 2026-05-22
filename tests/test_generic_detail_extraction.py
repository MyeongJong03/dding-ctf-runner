import json
import urllib.error
from pathlib import Path

from ctf_runner.platform_generic import GenericPlatform, parse_rsc_payload


class FakeResponse:
    def __init__(self, payload: bytes, *, url: str, content_type: str = "text/html", status: int = 200):
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


def test_challenge_detail_extraction_from_detail_page_without_post(tmp_path: Path):
    calls: list[tuple[str, str]] = []

    def fake_open(request, timeout=0):
        calls.append((request.get_method(), request.full_url))
        if request.full_url.endswith("/contests/demo"):
            return FakeResponse(
                json.dumps(
                    {
                        "challenges": [
                            {
                                "id": "web-1",
                                "name": "Web One",
                                "category": "web",
                                "points": 100,
                                "url": "/challenges/web-1",
                            }
                        ]
                    }
                ).encode(),
                url=request.full_url,
                content_type="application/json",
            )
        if request.full_url.endswith("/challenges/web-1"):
            return FakeResponse(
                b"""
                <html>
                  <h1>Web One</h1>
                  <article>Exploit the voucher checker. Hint: inspect the role parameter.</article>
                  <a href="/docs/web-one">docs</a>
                </html>
                """,
                url=request.full_url,
            )
        if "/api/" in request.full_url or "/contests/demo/" in request.full_url or request.full_url.endswith("/trpc"):
            raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)
        raise AssertionError(request.full_url)

    platform = GenericPlatform(
        config={
            "platform": "generic",
            "name": "unit",
            "base_url": "https://ctf.example.com",
            "contest_url": "https://ctf.example.com/contests/demo",
            "auth": {"method": "manual"},
            "policy": {
                "allow_live_discovery": True,
                "allow_live_download": False,
                "allow_submission": False,
                "allow_instance_start": False,
            },
            "downloads": {"root": str(tmp_path / "contests")},
        },
        urlopen=fake_open,
    )

    detail = platform.get_text_detail("web-1", live=True)
    public = detail["public"]

    assert detail["status"] == "ok"
    assert public["detail_text_found"] is True
    assert detail["challenge"]["statement"]
    assert detail["challenge"]["hints"]
    assert detail["challenge"]["_links_private"][0]["url"] == "https://ctf.example.com/docs/web-one"
    assert all(method == "GET" for method, _ in calls)
    assert not any("submit" in url for _, url in calls)


def test_rsc_detail_body_extracts_hints_tags_and_connection_info():
    chunk = json.dumps(
        {
            "cards": [
                {
                    "id": "rev-1",
                    "title": "Rev One",
                    "category": "rev",
                    "value": 200,
                    "statement": "Reverse the validator.",
                    "hints": [{"content": "Strings first."}],
                    "tags": [{"name": "crackme"}],
                    "connection_info": "nc rev.example 31337",
                }
            ]
        }
    )

    challenges = parse_rsc_payload(f"self.__next_f.push([1,{json.dumps(chunk)}]);", base_url="https://ctf.example.com")

    assert challenges[0]["challenge_id"] == "rev-1"
    assert challenges[0]["detail_text_found"] is True
    assert challenges[0]["hint_count"] == 1
    assert challenges[0]["tag_count"] == 1
    assert challenges[0]["connection_info_present"] is True
