import json
from pathlib import Path

from ctf_runner.fake_ctfd import CHALLENGE_ID, FakeCTFdServer, run_smoke, wrong_flag
from ctf_runner.platform_ctfd import CTFdPlatform


def test_fake_ctfd_discover_get_download_submit_and_logs(tmp_path: Path):
    with FakeCTFdServer() as server:
        platform = CTFdPlatform(config=server_config(server.base_url, tmp_path))

        discover = platform.discover_challenges(live=True)
        detail = platform.get_challenge(CHALLENGE_ID, live=True)
        download = platform.download_attachments(CHALLENGE_ID, live=True)
        rejected = platform.submit_flag(CHALLENGE_ID, wrong_flag(), live=True, confirm=True)
        accepted = platform.submit_flag(CHALLENGE_ID, server.correct_flag, live=True, confirm=True)

        assert discover.status == "ok"
        assert detail.status == "ok"
        assert detail.details["attachment_count"] == 1
        assert download.status == "ok"
        assert Path(download.details["downloads"][0]["fs_path"]).exists()
        assert rejected.status == "rejected"
        assert accepted.status == "accepted"

        rendered = json.dumps(
            {
                "discover": discover.details,
                "detail": detail.details,
                "download": download.details,
                "accepted": accepted.details,
                "rejected": rejected.details,
                "log": server.request_log,
            },
            sort_keys=True,
        )
        assert server.correct_flag not in rendered
        assert wrong_flag() not in rendered
        assert "flag_hash" in rendered


def test_fake_ctfd_smoke_is_local_and_redacted():
    result = run_smoke()
    rendered = json.dumps(result, sort_keys=True)

    assert result["status"] == "ok"
    assert result["server"]["base_url"].startswith("http://127.0.0.1:")
    assert result["wrong_submit_status"] == "rejected"
    assert result["accepted_submit_status"] == "accepted"
    assert result["raw_leak_detected"] is False
    assert "flag_hash" in rendered


def server_config(base_url: str, root: Path) -> dict:
    return {
        "platform": "ctfd",
        "name": "fake_ctfd",
        "base_url": base_url,
        "auth": {"method": "manual"},
        "policy": {
            "allow_live_discovery": True,
            "allow_live_download": True,
            "allow_submission": True,
        },
        "downloads": {"root": str(root / "contests")},
    }
