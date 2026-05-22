import pytest

from ctf_runner.run_mode import check_action_allowed, resolve_run_mode, target_kind_for_challenge, target_kind_for_platform


def test_default_run_mode_is_setup(monkeypatch):
    monkeypatch.delenv("CTF_RUN_MODE", raising=False)

    assert resolve_run_mode() == "setup"


def test_env_run_mode_override(monkeypatch):
    monkeypatch.setenv("CTF_RUN_MODE", "rehearsal")

    assert resolve_run_mode() == "rehearsal"


def test_cli_run_mode_overrides_env(monkeypatch):
    monkeypatch.setenv("CTF_RUN_MODE", "competition")

    assert resolve_run_mode("setup") == "setup"


def test_invalid_run_mode_rejected(monkeypatch):
    monkeypatch.setenv("CTF_RUN_MODE", "unsafe")

    with pytest.raises(ValueError):
        resolve_run_mode()


def test_action_matrix_real_platform_modes():
    assert check_action_allowed("setup", "real_platform_discover", "real_platform").allowed
    assert not check_action_allowed("setup", "real_platform_ingest", "real_platform").allowed
    assert check_action_allowed(
        "setup",
        "real_platform_ingest",
        "real_platform",
        flags={"allow_real_readonly": True},
    ).allowed
    assert not check_action_allowed("setup", "real_challenge_solve", "real_platform").allowed
    assert not check_action_allowed("rehearsal", "real_challenge_solve", "real_platform").allowed
    assert check_action_allowed(
        "rehearsal",
        "real_challenge_solve",
        "real_platform",
        flags={"allow_real_solve_dry_run": True},
    ).allowed
    assert not check_action_allowed("setup", "live_submit", "real_platform").allowed
    assert check_action_allowed(
        "competition",
        "live_submit",
        "real_platform",
        flags={
            "confirm_competition": True,
            "confirm_submit": True,
            "contest_armed": True,
            "allow_live_submit": True,
        },
        policy={"allow_submission": True},
    ).allowed


def test_fake_and_local_targets_are_setup_safe():
    assert check_action_allowed("setup", "real_challenge_solve", "fake").allowed
    assert check_action_allowed("setup", "live_submit", "local").allowed
    assert target_kind_for_platform({"name": "fake_ctfd", "base_url": "https://example.invalid"}) == "fake"
    assert target_kind_for_platform({"name": "demo", "base_url": "http://127.0.0.1:8000"}) == "local"
    assert target_kind_for_challenge({"source": "platform", "contest_id": "example-real", "metadata": "{}"}) == "real_platform"
    assert target_kind_for_challenge({"source": "manual", "contest_id": "manual", "metadata": "{}"}) == "local"
