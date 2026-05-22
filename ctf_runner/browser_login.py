from __future__ import annotations

from typing import Any


def planned_browser_login(method: str, *, live: bool = False, confirm: bool = False) -> dict[str, Any]:
    supported = {"storage_state", "cookie_import", "username_password"}
    if method not in supported:
        return {"status": "blocked", "reason": "unsupported_method", "method": method}
    if not live or not confirm:
        return {
            "status": "planned",
            "method": method,
            "network": False,
            "requires_live": True,
            "requires_confirm": True,
            "note": "browser automation is disabled until ctfctl auth browser-login --live --confirm",
        }
    return {
        "status": "blocked",
        "method": method,
        "network": False,
        "reason": "playwright implementation deferred; preflight must pass first",
    }
