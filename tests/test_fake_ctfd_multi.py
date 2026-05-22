import json
from pathlib import Path

from ctf_runner.fake_ctfd import FakeCTFdServer, fake_decoy_flag, platform_config, wrong_flag
from ctf_runner.platform_ctfd import CTFdPlatform


def test_fake_ctfd_multiple_challenges_submit_states_are_per_challenge(tmp_path: Path):
    with FakeCTFdServer() as server:
        platform = CTFdPlatform(config=platform_config(server.base_url, tmp_path / "contests"))

        discover = platform.discover_challenges(live=True)
        assert discover.status == "ok"
        assert discover.details["challenge_count"] == 5
        discovered_ids = {item["challenge_id"] for item in discover.details["challenges"]}
        assert {"easy-misc-1", "easy-crypto-1", "easy-web-1", "stalled-1", "duplicate-decoy-1"} <= discovered_ids

        for fixture in server.fixtures:
            detail = platform.get_challenge(fixture.challenge_id, live=True)
            download = platform.download_attachments(fixture.challenge_id, live=True)
            rejected = platform.submit_flag(fixture.challenge_id, wrong_flag(), live=True, confirm=True)
            accepted = platform.submit_flag(fixture.challenge_id, fixture.correct_flag, live=True, confirm=True)
            duplicate = platform.submit_flag(fixture.challenge_id, fixture.correct_flag, live=True, confirm=True)

            assert detail.status == "ok"
            assert detail.details["attachment_count"] == 1
            assert download.status == "ok"
            assert rejected.status == "rejected"
            assert accepted.status == "accepted"
            assert duplicate.status == "accepted"
            assert duplicate.details["result_summary_redacted"]["ctfd_status"] == "already_solved"

        rendered = json.dumps(
            {
                "discover": discover.details,
                "server_info": server.public_info(),
                "request_log": server.request_log,
                "submission_log": server.submission_log,
            },
            sort_keys=True,
        )
        for raw in [*server.correct_flags, wrong_flag(), fake_decoy_flag()]:
            assert raw not in rendered
        assert "flag_hash" in rendered
