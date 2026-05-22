from __future__ import annotations

import json
import os
import select
import stat
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

from .auth import load_config_metadata


DEFAULT_CAPTURE_TIMEOUT_SEC = 300


def storage_state_summary(path: str | Path) -> dict[str, Any]:
    storage_path = Path(path).expanduser()
    payload: dict[str, Any] = {
        "path": _display_path(storage_path),
        "path_exists": storage_path.exists(),
        "size": 0,
        "cookie_count": 0,
        "origin_count": 0,
        "domains": [],
        "origins": [],
        "permission_warning": None,
    }
    if not storage_path.exists():
        payload["status"] = "missing"
        payload["warning"] = "storage_state_path_missing"
        return payload
    payload["size"] = storage_path.stat().st_size
    payload["permission_warning"] = _permission_warning(storage_path)
    try:
        state = json.loads(storage_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        payload["status"] = "invalid_json"
        return payload
    if not isinstance(state, Mapping):
        payload["status"] = "invalid_shape"
        return payload
    cookies = state.get("cookies") if isinstance(state.get("cookies"), list) else []
    origins = state.get("origins") if isinstance(state.get("origins"), list) else []
    domains = sorted(
        {
            str(cookie.get("domain") or "").lstrip(".")
            for cookie in cookies
            if isinstance(cookie, Mapping) and str(cookie.get("domain") or "").strip()
        }
    )
    origin_summaries: list[dict[str, Any]] = []
    for origin in origins:
        if not isinstance(origin, Mapping):
            continue
        origin_url = str(origin.get("origin") or "")
        host = urllib.parse.urlsplit(origin_url).netloc or origin_url
        local_storage = origin.get("localStorage") if isinstance(origin.get("localStorage"), list) else []
        origin_summaries.append(
            {
                "origin": _origin_only(origin_url),
                "host": host,
                "local_storage_key_count": len(local_storage),
                "local_storage_keys": [
                    str(item.get("name") or "")[:120]
                    for item in local_storage[:50]
                    if isinstance(item, Mapping) and str(item.get("name") or "")
                ],
            }
        )
    payload.update(
        {
            "status": "ok",
            "cookie_count": len(cookies),
            "origin_count": len(origins),
            "domains": domains[:50],
            "origins": origin_summaries[:50],
        }
    )
    return payload


def capture_storage_state(
    config: str | Path,
    output: str | Path,
    *,
    live: bool = False,
    headed: bool = False,
    timeout_sec: int = DEFAULT_CAPTURE_TIMEOUT_SEC,
) -> dict[str, Any]:
    config_path = Path(config).expanduser()
    output_path = Path(output).expanduser()
    loaded = load_config_metadata(config_path)
    profile = dict(loaded.get("data") or {}) if loaded.get("exists") else {}
    target_url = _capture_target_url(profile)
    planned = {
        "config_path": _display_path(config_path),
        "output_path": _display_path(output_path),
        "target_url": _redact_url(target_url),
        "headed": bool(headed),
        "timeout_sec": int(timeout_sec),
        "manual_login": True,
        "writes_storage_state": live and headed,
    }
    if not live:
        return {"status": "planned", "live_required": True, **planned}
    if not headed:
        return {
            "status": "blocked",
            "reason": "headed_browser_required_for_manual_login",
            **planned,
            "alternatives": _manual_capture_alternatives(),
        }
    if not loaded.get("exists"):
        return {"status": "blocked", "reason": "profile_config_missing", **planned}
    if not target_url:
        return {"status": "blocked", "reason": "target_url_missing", **planned}

    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001 - summarized without environment details.
        return {
            "status": "blocked",
            "reason": "playwright_unavailable",
            "error_type": exc.__class__.__name__,
            **planned,
            "alternatives": _manual_capture_alternatives(),
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + max(1, int(timeout_sec))
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=False)
            context = browser.new_context()
            page = context.new_page()
            page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            while time.monotonic() < deadline:
                if _stdin_enter_pressed():
                    break
                if _looks_authenticated(page, target_url):
                    break
                try:
                    page.wait_for_timeout(1000)
                except PlaywrightTimeoutError:
                    pass
            context.storage_state(path=str(output_path))
            context.close()
            browser.close()
    except Exception as exc:  # noqa: BLE001 - headed launch can fail under WSL GUI setups.
        return {
            "status": "blocked",
            "reason": "headed_browser_unavailable",
            "error_type": exc.__class__.__name__,
            **planned,
            "alternatives": _manual_capture_alternatives(),
        }

    os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)
    summary = storage_state_summary(output_path)
    return {"status": "ok", **planned, "storage_state": summary}


def _capture_target_url(profile: Mapping[str, Any]) -> str:
    contest_url = str(profile.get("contest_url") or profile.get("contest") or "").strip()
    if contest_url:
        return contest_url
    base_url = str(profile.get("base_url") or profile.get("url") or "").strip().rstrip("/")
    if base_url:
        return f"{base_url}/login"
    return ""


def _stdin_enter_pressed() -> bool:
    if not sys.stdin or not sys.stdin.isatty():
        return False
    ready, _, _ = select.select([sys.stdin], [], [], 0)
    if not ready:
        return False
    sys.stdin.readline()
    return True


def _looks_authenticated(page: Any, target_url: str) -> bool:
    try:
        current = str(page.url)
        target_path = urllib.parse.urlsplit(target_url).path.rstrip("/")
        current_path = urllib.parse.urlsplit(current).path.rstrip("/")
        if target_path and current_path == target_path:
            text = str(page.locator("body").inner_text(timeout=1000)).lower()
            if any(marker in text for marker in ("challenge", "challenges", "contest", "problem", "task")):
                if not _visible_login_control(page):
                    return True
    except Exception:
        return False
    return False


def _visible_login_control(page: Any) -> bool:
    selectors = [
        "button:has-text('Login')",
        "button:has-text('Log in')",
        "a:has-text('Login')",
        "a:has-text('Log in')",
        "input[type='password']",
    ]
    for selector in selectors:
        try:
            if page.locator(selector).first.is_visible(timeout=500):
                return True
        except Exception:
            continue
    return False


def _manual_capture_alternatives() -> list[str]:
    return [
        "Use a headed Playwright browser in WSL after GUI support is available.",
        "Export equivalent storage state manually from a trusted browser workflow.",
        "Use cookie_header_file or api_token_file fallback when storage_state capture is unavailable.",
        "Headless Playwright cannot perform manual login capture.",
    ]


def _permission_warning(path: Path) -> str | None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return None
    if os.name != "nt" and mode & 0o077:
        return "file readable by group/other"
    return None


def _origin_only(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return ""
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _redact_url(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return ""
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _display_path(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path).replace(str(Path.home()), "~", 1)
    except RuntimeError:
        return str(path)
