import hashlib
import io
import json
import urllib.error
from pathlib import Path

from ctf_runner.platform_ctfd import CTFdPlatform


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.offset = 0

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


def test_ctfd_variant_list_and_detail_file_shapes(tmp_path: Path):
    platform = CTFdPlatform(config=_config(tmp_path), urlopen=_variant_open)

    discover = platform.discover_challenges(live=True)
    detail = platform.get_challenge("7", live=True)

    assert discover.status == "ok"
    item = discover.details["challenges"][0]
    assert item["challenge_id"] == "7"
    assert item["category"] == ""
    assert item["solves"] is None
    assert item["tags"] == ["intro"]
    assert item["has_files"] is False
    assert detail.status == "ok"
    assert detail.details["attachment_count"] == 2
    rendered = json.dumps(detail.details, sort_keys=True)
    assert "download-token" not in rendered
    assert "signature-value" not in rendered


def test_ctfd_download_handles_relative_and_absolute_urls(tmp_path: Path):
    platform = CTFdPlatform(config=_config(tmp_path), urlopen=_variant_open)

    action = platform.download_attachments("7", live=True)

    assert action.status == "ok"
    assert action.details["download_count"] == 2
    downloads = {item["filename"]: item for item in action.details["downloads"]}
    assert downloads["one.txt"]["sha256"] == hashlib.sha256(b"relative file").hexdigest()
    assert downloads["two.bin"]["sha256"] == hashlib.sha256(b"absolute file").hexdigest()
    assert all(Path(item["fs_path"]).exists() for item in downloads.values())
    assert "download-token" not in json.dumps(action.details, sort_keys=True)


def test_ctfd_download_auth_required_is_normalized(tmp_path: Path):
    def fake_open(request, timeout=0):
        if request.full_url.endswith("/api/v1/challenges/8"):
            return FakeResponse(
                json.dumps(
                    {
                        "data": {
                            "id": 8,
                            "name": "Private",
                            "files": [{"url": "/files/private.txt?token=secret", "name": "private.txt"}],
                        }
                    }
                ).encode("utf-8")
            )
        raise urllib.error.HTTPError(
            request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"message":"auth required"}'),
        )

    platform = CTFdPlatform(config=_config(tmp_path), urlopen=fake_open)

    action = platform.download_attachments("8", live=True)

    assert action.status == "auth_required"
    assert action.details["download_count"] == 0
    assert action.details["failure_count"] == 1
    assert action.details["failures"][0]["http_status"] == 403
    assert "token=secret" not in json.dumps(action.details, sort_keys=True)


def test_ctfd_discover_auth_required_is_normalized(tmp_path: Path):
    def fake_open(request, timeout=0):
        raise urllib.error.HTTPError(
            request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"message":"login required"}'),
        )

    platform = CTFdPlatform(config=_config(tmp_path), urlopen=fake_open)

    action = platform.discover_challenges(live=True)

    assert action.status == "auth_required"
    assert action.details["http_status"] == 403


def _variant_open(request, timeout=0):
    if request.full_url.endswith("/api/v1/challenges"):
        return FakeResponse(
            json.dumps(
                {
                    "data": {
                        "results": [
                            {
                                "id": 7,
                                "name": "Warmup",
                                "value": "50",
                                "tags": "intro",
                            }
                        ]
                    }
                }
            ).encode("utf-8")
        )
    if request.full_url.endswith("/api/v1/challenges/7"):
        return FakeResponse(
            json.dumps(
                {
                    "data": {
                        "challenge": {
                            "id": 7,
                            "name": "Warmup",
                            "files": [
                                "/files/one.txt?token=download-token",
                                {
                                    "url": "https://cdn.example.org/two.bin?signature=signature-value",
                                    "filename": "two.bin",
                                },
                            ],
                            "connection_info": None,
                            "tags": "intro",
                        }
                    }
                }
            ).encode("utf-8")
        )
    if request.full_url.startswith("https://ctf.example.com/files/one.txt"):
        return FakeResponse(b"relative file")
    if request.full_url.startswith("https://cdn.example.org/two.bin"):
        return FakeResponse(b"absolute file")
    raise AssertionError(f"unexpected url {request.full_url}")


def _config(root: Path) -> dict:
    secret_path = root / "ctfd.token"
    secret_path.write_text("raw-token-value", encoding="utf-8")
    return {
        "platform": "ctfd",
        "name": "variant",
        "base_url": "https://ctf.example.com",
        "auth": {"method": "api_token_file", "path": str(secret_path)},
        "policy": {
            "allow_live_discovery": True,
            "allow_live_download": True,
            "allow_submission": False,
            "allow_instance_start": False,
        },
        "downloads": {"root": str(root / "contests")},
    }
