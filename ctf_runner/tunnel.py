from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from .redact import redact_text


@dataclass(frozen=True)
class ProviderSpec:
    provider: str
    executables: tuple[str, ...]
    recommended_for: str
    risk: str
    version_args: tuple[str, ...] = ("--version",)


PROVIDERS: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        "cloudflared",
        ("cloudflared",),
        "HTTP/browser callback",
        "public URL exposure; cleanup tunnel after challenge",
    ),
    ProviderSpec(
        "bore",
        ("bore",),
        "simple TCP/HTTP callback",
        "public TCP exposure; confirm target port before use",
    ),
    ProviderSpec(
        "ngrok",
        ("ngrok",),
        "manual HTTP/TCP callback when account policy allows",
        "account/token handling; never store tokens in repo",
        ("version",),
    ),
    ProviderSpec(
        "localtunnel",
        ("lt", "localtunnel"),
        "manual HTTP callback",
        "public URL exposure; node/npm supply-chain and stale tunnel cleanup",
    ),
    ProviderSpec(
        "ssh",
        ("ssh",),
        "manual reverse tunnel fallback",
        "requires trusted remote host; avoid secret-bearing URLs in logs",
        ("-V",),
    ),
    ProviderSpec(
        "socat",
        ("socat",),
        "local TCP plumbing fallback",
        "easy to expose unintended ports if paired with a public endpoint",
        ("-V",),
    ),
)

PUBLIC_TUNNEL_PROVIDERS = {"cloudflared", "bore", "ngrok", "localtunnel"}


def _version_summary(executable: str, args: tuple[str, ...], timeout: float = 3.0) -> str:
    try:
        proc = subprocess.run(
            [executable, *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001 - detection must be best-effort.
        return redact_text(str(exc))[:240]

    for line in proc.stdout.splitlines():
        stripped = redact_text(line.strip())
        if stripped:
            return stripped[:240]
    return ""


def detect_provider(spec: ProviderSpec) -> dict[str, Any]:
    executable = next((name for name in spec.executables if shutil.which(name)), None)
    installed = executable is not None
    return {
        "provider": spec.provider,
        "installed": installed,
        "executable": executable or "",
        "version": _version_summary(executable, spec.version_args) if executable else "",
        "recommended_for": spec.recommended_for,
        "risk": spec.risk,
    }


def check_tunnel_providers() -> dict[str, Any]:
    providers = [detect_provider(spec) for spec in PROVIDERS]
    by_name = {provider["provider"]: provider for provider in providers}
    public_installed = [p for p in providers if p["provider"] in PUBLIC_TUNNEL_PROVIDERS and p["installed"]]
    fallback_installed = [p for p in providers if p["provider"] in {"ssh", "socat"} and p["installed"]]

    if by_name["cloudflared"]["installed"]:
        recommendation = {
            "status": "recommended",
            "provider": "cloudflared",
            "reason": "default for HTTP/browser callback",
        }
    elif by_name["bore"]["installed"]:
        recommendation = {
            "status": "recommended",
            "provider": "bore",
            "reason": "simple TCP/HTTP callback provider available",
        }
    elif public_installed or fallback_installed:
        recommendation = {
            "status": "manual_fallback",
            "provider": public_installed[0]["provider"] if public_installed else fallback_installed[0]["provider"],
            "reason": "cloudflared/bore missing; use only with explicit public exposure approval",
        }
    else:
        recommendation = {
            "status": "missing_tunnel_provider",
            "provider": "",
            "reason": "install a public callback provider before live browser/tunnel challenges",
        }

    return {
        "ok": bool(public_installed),
        "providers": providers,
        "recommendation": recommendation,
        "public_provider_installed": bool(public_installed),
    }
