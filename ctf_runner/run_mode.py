from __future__ import annotations

import json
import os
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any, Mapping


RUN_MODES = ("setup", "rehearsal", "competition")
TARGET_KINDS = ("fake", "local", "real_platform")


@dataclass(frozen=True)
class RunModeDecision:
    allowed: bool
    reason: str
    required_flags: tuple[str, ...] = ()
    safe_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["required_flags"] = list(self.required_flags)
        return data


def resolve_run_mode(cli_value: str | None = None) -> str:
    raw = str(cli_value or os.environ.get("CTF_RUN_MODE") or "setup").strip().lower()
    if raw not in RUN_MODES:
        raise ValueError(f"unsupported run mode: {raw or '<empty>'}")
    return raw


def check_action_allowed(
    mode: str,
    action: str,
    target_kind: str,
    flags: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
) -> RunModeDecision:
    mode = resolve_run_mode(mode)
    action = str(action or "").strip().lower()
    target_kind = normalize_target_kind(target_kind)
    flags = flags or {}
    policy = policy or {}

    if action in {"fake_local_e2e", "mock_solver"}:
        return _allow("local_test_allowed", mode, action, target_kind)

    if target_kind in {"fake", "local"} and action in {
        "real_platform_discover",
        "real_platform_download",
        "real_platform_ingest",
        "real_challenge_solve",
        "live_submit",
    }:
        return _allow("non_real_target_allowed", mode, action, target_kind)

    if action in {"real_platform_profile", "real_platform_discover"}:
        return _allow("read_only_discovery_allowed", mode, action, target_kind)

    if action in {"real_platform_download", "real_platform_ingest"}:
        if mode == "setup" and target_kind == "real_platform" and not _flag(flags, "allow_real_readonly"):
            return _block(
                "setup_requires_allow_real_readonly",
                ("--allow-real-readonly",),
                mode,
                action,
                target_kind,
            )
        return _allow("real_readonly_allowed", mode, action, target_kind)

    if action == "real_challenge_solve":
        if target_kind != "real_platform":
            return _allow("non_real_target_allowed", mode, action, target_kind)
        if mode == "setup":
            return _block(
                "setup_blocks_real_challenge_solve",
                ("--mode rehearsal --allow-real-solve-dry-run", "--mode competition --confirm-competition"),
                mode,
                action,
                target_kind,
            )
        if mode == "rehearsal":
            if _flag(flags, "allow_real_solve_dry_run"):
                return _allow("rehearsal_real_solve_dry_run_allowed", mode, action, target_kind)
            return _block(
                "rehearsal_requires_allow_real_solve_dry_run",
                ("--allow-real-solve-dry-run",),
                mode,
                action,
                target_kind,
            )
        if not _flag(flags, "confirm_competition"):
            return _block(
                "competition_requires_confirm_competition",
                ("--confirm-competition",),
                mode,
                action,
                target_kind,
            )
        if not _flag(flags, "contest_armed"):
            return _block(
                "competition_not_armed",
                ("ctfctl contest arm --confirm-competition",),
                mode,
                action,
                target_kind,
            )
        return _allow("competition_real_solve_allowed", mode, action, target_kind)

    if action == "live_submit":
        if target_kind != "real_platform":
            return _allow("non_real_target_allowed", mode, action, target_kind)
        if mode in {"setup", "rehearsal"}:
            return _block(
                f"{mode}_blocks_live_submit",
                ("--mode competition", "--confirm-competition"),
                mode,
                action,
                target_kind,
            )
        if not _flag(flags, "confirm_competition"):
            return _block(
                "competition_requires_confirm_competition",
                ("--confirm-competition",),
                mode,
                action,
                target_kind,
            )
        if not _flag(flags, "contest_armed"):
            return _block(
                "competition_not_armed",
                ("ctfctl contest arm --confirm-competition",),
                mode,
                action,
                target_kind,
            )
        if not _flag(flags, "allow_live_submit"):
            return _block(
                "contest_live_submit_not_allowed",
                ("ctfctl contest arm --confirm-competition", "omit --no-live-submit or pass --allow-live-submit"),
                mode,
                action,
                target_kind,
            )
        if not (_flag(flags, "confirm_submit") or _flag(flags, "confirm")):
            return _block("live_submit_requires_confirm", ("--confirm-submit", "--confirm"), mode, action, target_kind)
        if not _flag(policy, "allow_submission"):
            return _block("live_submit_not_allowed_by_policy", ("policy.allow_submission=true",), mode, action, target_kind)
        return _allow("competition_live_submit_allowed", mode, action, target_kind)

    if action == "instance_start":
        if mode in {"setup", "rehearsal"} and target_kind == "real_platform":
            return _block(f"{mode}_blocks_instance_start", ("--mode competition",), mode, action, target_kind)
        if target_kind == "real_platform":
            if not _flag(flags, "confirm_competition"):
                return _block("competition_requires_confirm_competition", ("--confirm-competition",), mode, action, target_kind)
            if not _flag(flags, "contest_armed"):
                return _block(
                    "competition_not_armed",
                    ("ctfctl contest arm --confirm-competition",),
                    mode,
                    action,
                    target_kind,
                )
            if not _flag(flags, "allow_instance_start"):
                return _block(
                    "contest_instance_start_not_allowed",
                    ("ctfctl contest arm --allow-instance-start",),
                    mode,
                    action,
                    target_kind,
                )
            if not _flag(policy, "allow_instance_start"):
                return _block("instance_start_not_allowed_by_policy", ("policy.allow_instance_start=true",), mode, action, target_kind)
        return _allow("instance_start_allowed", mode, action, target_kind)

    if action == "browser_login":
        if mode in {"setup", "rehearsal"}:
            if _flag(flags, "allow_auth_capture"):
                return _allow("manual_auth_capture_allowed", mode, action, target_kind)
            return _block("auth_capture_requires_explicit_allow", ("--allow-auth-capture",), mode, action, target_kind)
        if not _flag(flags, "confirm_competition"):
            return _block("competition_requires_confirm_competition", ("--confirm-competition",), mode, action, target_kind)
        if not (_flag(policy, "allow_browser_login") or _flag(policy, "allow_auth_capture") or _flag(flags, "allow_auth_capture")):
            return _block("browser_login_not_allowed_by_policy", ("policy.allow_browser_login=true",), mode, action, target_kind)
        return _allow("competition_browser_login_allowed", mode, action, target_kind)

    if action == "public_tunnel":
        if mode in {"setup", "rehearsal"}:
            return _block(f"{mode}_blocks_public_tunnel", ("--mode competition",), mode, action, target_kind)
        if not _flag(flags, "confirm_competition"):
            return _block("competition_requires_confirm_competition", ("--confirm-competition",), mode, action, target_kind)
        if not (_flag(policy, "allow_public_tunnel") or _flag(policy, "allow_tunnel")):
            return _block("public_tunnel_not_allowed_by_policy", ("policy.allow_public_tunnel=true",), mode, action, target_kind)
        return _allow("competition_public_tunnel_allowed", mode, action, target_kind)

    return _block("unknown_action", (), mode, action, target_kind)


def normalize_target_kind(value: str | None) -> str:
    target = str(value or "real_platform").strip().lower()
    if target not in TARGET_KINDS:
        return "real_platform"
    return target


def target_kind_for_platform(platform: Any | Mapping[str, Any] | None) -> str:
    if platform is None:
        return "real_platform"
    if isinstance(platform, Mapping):
        config = platform
        name = str(config.get("name") or config.get("platform") or "").lower()
        base_url = str(config.get("base_url") or config.get("url") or "")
    else:
        config = getattr(platform, "config", {})
        name = str(getattr(platform, "platform_name", "") or (config.get("name") if isinstance(config, Mapping) else "") or "").lower()
        base_url = str(getattr(platform, "base_url", "") or (config.get("base_url") if isinstance(config, Mapping) else "") or "")
    if _looks_fake_or_local_name(name):
        return "fake"
    if is_loopback_url(base_url):
        return "local"
    return "real_platform"


def target_kind_for_challenge(challenge: Mapping[str, Any]) -> str:
    metadata = _metadata_dict(challenge.get("metadata"))
    source = str(challenge.get("source") or "").strip().lower()
    contest_id = str(challenge.get("contest_id") or metadata.get("contest_id") or "").strip().lower()
    platform_name = str(metadata.get("platform") or metadata.get("name") or "").strip().lower()
    if _looks_fake_or_local_name(contest_id) or _looks_fake_or_local_name(platform_name):
        return "fake"
    for key in ("base_url", "url", "contest_url"):
        if is_loopback_url(str(metadata.get(key) or "")):
            return "local"
    if source == "platform":
        return "real_platform"
    return "local"


def is_loopback_url(value: str) -> bool:
    if not value:
        return False
    try:
        host = urllib.parse.urlsplit(value).hostname
    except ValueError:
        return False
    return host in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def _allow(reason: str, mode: str, action: str, target_kind: str) -> RunModeDecision:
    return RunModeDecision(True, reason, (), f"{mode}:{target_kind}:{action}:allowed")


def _block(reason: str, required_flags: tuple[str, ...], mode: str, action: str, target_kind: str) -> RunModeDecision:
    return RunModeDecision(False, reason, required_flags, f"{mode}:{target_kind}:{action}:blocked")


def _flag(values: Mapping[str, Any], key: str) -> bool:
    return bool(values.get(key))


def _metadata_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            loaded = json.loads(value)
            return loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _looks_fake_or_local_name(value: str) -> bool:
    lowered = str(value or "").lower()
    return lowered in {"fake", "fake_ctfd", "local", "localhost", "mock", "local-fake"} or lowered.startswith(("fake_", "fake-", "final-fake", "local_", "local-"))
