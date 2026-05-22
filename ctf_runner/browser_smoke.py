from __future__ import annotations

import importlib
import importlib.util
from contextlib import suppress
from typing import Any

from .redact import redact_text


MAX_WARNING_CHARS = 600


def _bounded_summary(value: object, limit: int = MAX_WARNING_CHARS) -> str:
    text = redact_text(str(value))
    normalized = " ".join(line.strip() for line in text.splitlines() if line.strip())
    if len(normalized) <= limit:
        return normalized
    head_len = limit // 2
    tail_len = limit - head_len
    return f"{normalized[:head_len]} ... {normalized[-tail_len:]}"


def playwright_import_status() -> dict[str, Any]:
    module_found = importlib.util.find_spec("playwright") is not None
    sync_api_found = importlib.util.find_spec("playwright.sync_api") is not None if module_found else False
    return {
        "python_module": module_found,
        "sync_api": sync_api_found,
        "playwright_import": module_found and sync_api_found,
    }


def run_browser_smoke() -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": False,
        "playwright_import": False,
        "chromium_launch": False,
        "reason": "",
        "warnings": [],
    }

    try:
        sync_api = importlib.import_module("playwright.sync_api")
    except ModuleNotFoundError:
        result["reason"] = "playwright_missing"
        result["warnings"].append("install repo-local playwright with scripts/setup-browser.sh")
        return result
    except Exception as exc:  # noqa: BLE001 - smoke output should summarize failures.
        result["reason"] = "playwright_import_failed"
        result["warnings"].append(_bounded_summary(exc))
        return result

    result["playwright_import"] = True
    browser = None
    try:
        with sync_api.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            result["chromium_launch"] = True
            page = browser.new_page()
            page.set_content(
                "<!doctype html><html><head><title>ctf-runner-smoke</title></head>"
                "<body><main id='status'>browser smoke ok</main></body></html>",
                wait_until="load",
            )
            title = page.title()
            text = page.locator("#status").inner_text(timeout=2_000)
            if title == "ctf-runner-smoke" and text == "browser smoke ok":
                result["ok"] = True
                result["reason"] = "ok"
            else:
                result["reason"] = "page_check_failed"
                result["warnings"].append("local html title/text mismatch")
            browser.close()
            browser = None
    except Exception as exc:  # noqa: BLE001 - summarize dependency/launch failures.
        result["reason"] = "browser_launch_failed" if not result["chromium_launch"] else "browser_smoke_failed"
        result["warnings"].append(_bounded_summary(exc))
    finally:
        if browser is not None:
            with suppress(Exception):
                browser.close()

    return result
