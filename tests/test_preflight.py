from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from ctf_runner import preflight
from ctf_runner.codex_profile import DEFAULT_WORKER_IDS


def _baseline_worker_status(worker_id: str) -> dict[str, object]:
    return {
        "worker_id": worker_id,
        "exists": True,
        "agents_md": {"exists": True},
        "config_toml": {"exists": True},
        "auth_json": {"exists": False, "is_symlink": False},
        "auth_linked": False,
        "model": None,
        "model_policy": "auto/unpinned",
    }


def _baseline_model_status(pinned: bool = False) -> dict[str, object]:
    workers = []
    for worker_id in DEFAULT_WORKER_IDS:
        model = "gpt-test" if pinned and worker_id == "worker-1" else None
        workers.append(
            {
                "worker_id": worker_id,
                "model": model,
                "model_pinned": bool(model),
                "model_policy": "hard-pinned" if model else "auto/unpinned",
                "model_auto_default": model is None,
                "parse_error": "",
            }
        )
    return {
        "default_model_policy": "auto/unpinned",
        "model_auto_default": all(not item["model_pinned"] for item in workers),
        "workers": workers,
    }


def _mcp_status(*, legacy: bool = False, canonical: bool = True, reva: bool = True) -> dict[str, object]:
    global_servers = []
    if legacy:
        global_servers.append("dreamhack_solver")
    if reva:
        global_servers.append("ReVa")
    if canonical:
        global_servers.append("ctf_solver")
    return {
        "global_config": "/tmp/.codex/config.toml",
        "global_servers": global_servers,
        "worker_servers": [],
        "legacy_dreamhack_present": legacy,
        "legacy_dreamhack_global": legacy,
        "legacy_dreamhack_worker_paths": [],
        "canonical_ctf_solver_present": canonical,
        "reva_present": reva,
        "recommended_action": "test",
    }


def _patch_preflight_baseline(
    monkeypatch,
    tmp_path: Path,
    *,
    pinned: bool = False,
    mcp_legacy: bool = False,
    mcp_canonical: bool = True,
) -> None:
    repo = tmp_path / "dding-ctf-runner"
    repo.mkdir()
    wrapper = repo / "scripts" / "run-codex-worker.sh"
    wrapper.parent.mkdir()
    wrapper.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    wrapper.chmod(0o755)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(preflight, "get_paths", lambda: SimpleNamespace(repo=repo, warnings=lambda: []))
    monkeypatch.setattr(preflight, "is_under_mnt_c", lambda path: False)
    monkeypatch.setattr(preflight, "_run_version", lambda cmd: {"found": True, "version": "ok", "returncode": 0})
    monkeypatch.setattr(preflight, "_command_found", lambda name: {"found": True})
    monkeypatch.setattr(preflight.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(preflight, "playwright_import_status", lambda: {"playwright_import": True})
    monkeypatch.setattr(preflight, "run_callback_smoke", lambda: {"ok": True})
    monkeypatch.setattr(preflight, "check_tunnel_providers", lambda: {"public_provider_installed": True})
    monkeypatch.setattr(preflight, "default_cwd_risk", lambda: {"warnings": []})
    monkeypatch.setattr(
        preflight,
        "diagnose_codex_update_issue",
        lambda: {
            "active_binary": {"version": "0.130.0"},
            "preferred_binary": {"exists": True, "version": "0.130.0"},
            "path_conflict": False,
            "update_mismatch": False,
            "stale_binary_present": False,
        },
    )
    monkeypatch.setattr(
        preflight,
        "diagnose_mcp_legacy",
        lambda: _mcp_status(legacy=mcp_legacy, canonical=mcp_canonical),
    )
    monkeypatch.setattr(preflight, "status_worker_home", _baseline_worker_status)
    monkeypatch.setattr(preflight, "codex_model_status", lambda: _baseline_model_status(pinned=pinned))
    monkeypatch.setattr(
        preflight,
        "notice_status",
        lambda: {"workers": [{"worker_id": worker_id, "safe_notice_candidates": []} for worker_id in DEFAULT_WORKER_IDS]},
    )
    monkeypatch.setattr(preflight, "validate_worker_launch_context", lambda worker_id, root: {"warnings": []})
    monkeypatch.setattr(
        preflight,
        "launch_command",
        lambda worker_id, mode: {
            "command": "codex --ask-for-approval never --sandbox danger-full-access",
            "model": None,
            "model_flag_present": False,
            "model_auto_default": True,
        },
    )
    monkeypatch.setattr(
        preflight,
        "default_model_smoke",
        lambda worker_id: {
            "attempted": True,
            "ok": True,
            "observed_default_model": "gpt-5.3-codex",
            "model_flag_used": False,
            "response_ok": True,
        },
    )
    monkeypatch.setattr(preflight, "_docker_reachable", lambda: {"found": True, "reachable": True})
    monkeypatch.setattr(preflight, "_docker_image_exists", lambda image: {"image": image, "exists": True, "checked": True})
    monkeypatch.setattr(
        preflight,
        "_docker_pool_readiness",
        lambda: {
            "status": "ready",
            "docker": {"found": True, "reachable": True},
            "image": {"image": "ctf-pwn:latest", "exists": True, "checked": True},
            "active_container_count": 0,
        },
    )


def test_preflight_auto_model_default_has_no_model_high_risk(monkeypatch, tmp_path):
    _patch_preflight_baseline(monkeypatch, tmp_path)

    data = preflight.collect_preflight()

    assert "worker_model_not_gpt55" not in data["risk"]["High"]
    assert "worker_model_not_pinned" not in data["risk"]["High"]
    assert "worker_model_hard_pinned" not in data["risk"]["Medium"]
    assert "model_hard_pinned" not in data["risk"]["Medium"]
    assert data["codex_worker_isolation"]["model_auto_default"] is True
    assert data["codex_worker_isolation"]["default_model_smoke"]["attempted"] is False
    assert "expected_model" not in data["codex_worker_isolation"]


def test_preflight_hard_pinned_model_is_medium_not_high(monkeypatch, tmp_path):
    _patch_preflight_baseline(monkeypatch, tmp_path, pinned=True)

    data = preflight.collect_preflight()

    assert "model_hard_pinned" in data["risk"]["Medium"]
    assert "worker_model_hard_pinned" not in data["risk"]["Medium"]
    assert "worker_model_not_gpt55" not in data["risk"]["High"]
    assert data["risk"]["High"] == []
    assert data["codex_worker_isolation"]["model_auto_default"] is False


def test_preflight_model_smoke_records_observed_default_as_info(monkeypatch, tmp_path):
    _patch_preflight_baseline(monkeypatch, tmp_path)

    data = preflight.collect_preflight(deep=True, model_smoke=True)

    assert data["codex_worker_isolation"]["observed_default_model"] == "gpt-5.3-codex"
    assert "default_model_observed" in data["risk"]["Info"]
    assert "default_model_unknown" not in data["risk"]["Low"]


def test_preflight_reports_legacy_mcp_as_medium_and_missing_ctf_solver_as_info(monkeypatch, tmp_path):
    _patch_preflight_baseline(monkeypatch, tmp_path, mcp_legacy=True, mcp_canonical=False)

    data = preflight.collect_preflight()

    assert "legacy_dreamhack_solver_mcp" in data["risk"]["Medium"]
    assert "ctf_solver_mcp_missing" in data["risk"]["Info"]
    assert data["codex_worker_isolation"]["mcp_status"]["global_servers"] == ["dreamhack_solver", "ReVa"]


def test_preflight_docker_missing_is_optional_low_risk(monkeypatch, tmp_path):
    _patch_preflight_baseline(monkeypatch, tmp_path)
    monkeypatch.setattr(preflight, "_docker_reachable", lambda: {"found": False, "reachable": False, "classification": "codex_sandbox_docker_unreachable", "reason": "docker_cli_missing"})
    monkeypatch.setattr(preflight, "_docker_image_exists", lambda image: {"image": image, "exists": False, "checked": False, "reason": "codex_sandbox_docker_unreachable"})
    monkeypatch.setattr(
        preflight,
        "_docker_pool_readiness",
        lambda: {"status": "not_ready", "active_container_count": 0, "image": {"checked": False}},
    )

    data = preflight.collect_preflight()

    assert "docker_unreachable" not in data["risk"]["High"]
    assert "ctf_pwn_image_missing" not in data["risk"]["Medium"]
    assert "codex_sandbox_docker_unreachable" in data["risk"]["Low"]
    assert "ctf_pwn_image_missing" not in data["risk"]["Low"]


def test_preflight_desktop_integration_missing_is_medium_outside_codex(monkeypatch, tmp_path):
    _patch_preflight_baseline(monkeypatch, tmp_path)
    monkeypatch.setattr(
        preflight,
        "_docker_reachable",
        lambda: {
            "found": False,
            "reachable": False,
            "classification": "docker_desktop_integration_missing",
            "reason": "docker_desktop_integration_missing",
            "base_reason": "docker_desktop_integration_missing",
        },
    )
    monkeypatch.setattr(preflight, "_docker_image_exists", lambda image: {"image": image, "exists": False, "checked": False, "reason": "docker_desktop_integration_missing"})
    monkeypatch.setattr(
        preflight,
        "_docker_pool_readiness",
        lambda: {"status": "not_ready", "active_container_count": 0, "image": {"checked": False}},
    )

    data = preflight.collect_preflight()

    assert "docker_desktop_integration_missing" in data["risk"]["Medium"]
    assert "docker_desktop_integration_missing" not in data["risk"]["Low"]
    assert "WSL Integration" in data["risk_guidance"]["docker_desktop_integration_missing"]


def test_preflight_missing_ctf_pwn_image_is_medium_by_default(monkeypatch, tmp_path):
    _patch_preflight_baseline(monkeypatch, tmp_path)
    monkeypatch.setattr(preflight, "_docker_image_exists", lambda image: {"image": image, "exists": False, "checked": True, "reason": "image_missing"})
    monkeypatch.setattr(
        preflight,
        "_docker_pool_readiness",
        lambda: {"status": "not_ready", "active_container_count": 0, "image": {"checked": True, "exists": False}},
    )

    data = preflight.collect_preflight()

    assert "ctf_pwn_image_missing" in data["risk"]["Medium"]
    assert "ctf_pwn_image_missing" not in data["risk"]["High"]


def test_preflight_missing_ctf_pwn_image_is_high_when_pwn_rev_enabled(monkeypatch, tmp_path):
    _patch_preflight_baseline(monkeypatch, tmp_path)
    monkeypatch.setenv("CTF_PWN_REV_ENABLED", "1")
    monkeypatch.setattr(preflight, "_docker_image_exists", lambda image: {"image": image, "exists": False, "checked": True, "reason": "image_missing"})
    monkeypatch.setattr(
        preflight,
        "_docker_pool_readiness",
        lambda: {"status": "not_ready", "active_container_count": 0, "image": {"checked": True, "exists": False}},
    )

    data = preflight.collect_preflight()

    assert "ctf_pwn_image_missing" in data["risk"]["High"]
