from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .file_manifest import is_sensitive_path, redact_ingest_text


SCAN_READ_LIMIT = 256 * 1024
_MAX_SIGNAL_FILES = 12
_MAX_INTERESTING_FILES = 50


_WEB_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("route_definition", "route definitions", re.compile(r"(@\w+\.route\s*\(|\bapp\.(get|post|put|delete|patch)\s*\(|\brouter\.(get|post|put|delete|patch)\s*\(|@(Get|Post|Request)Mapping\b|urlpatterns\s*=)", re.I)),
    ("framework_hint", "framework hints", re.compile(r"\b(flask|fastapi|express\s*\(|django|springframework|koa|hapi)\b", re.I)),
    ("template_render", "template render", re.compile(r"\b(render_template|res\.render|templateResponse|render\s*\()", re.I)),
    ("code_execution_sink", "eval/exec/subprocess/os.system", re.compile(r"\b(eval|exec|subprocess\.(run|popen|call)|os\.system|child_process|Runtime\.getRuntime)\s*\(", re.I)),
    ("sql_construction", "SQL query/string concat", re.compile(r"\b(select|insert|update|delete)\b.{0,80}(\+|%|\{|\$\{|format\s*\()", re.I | re.S)),
    ("jwt_session_cookie", "JWT/session/cookie", re.compile(r"\b(jwt|session|cookie|set-cookie|signedcookie|csrf)\b", re.I)),
    ("upload_file_path", "upload/file path", re.compile(r"\b(upload|multipart|filename|send_file|send_from_directory|path\.join|open\s*\()", re.I)),
    ("ssrf_redirect", "SSRF/open redirect hints", re.compile(r"\b(requests\.(get|post)|axios|fetch\s*\(|http\.Get|redirect\s*\(|url=|next=|return_to)\b", re.I)),
    ("bot_admin_report", "bot/admin/report endpoint hints", re.compile(r"\b(admin|bot|report|puppeteer|playwright|chromium)\b", re.I)),
]
_CRYPTO_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("rsa_ecc_aes_hash", "RSA/ECC/AES/hash keywords", re.compile(r"\b(RSA|ECC|ECDSA|AES|DES|CBC|CTR|GCM|SHA256|MD5|HMAC|cipher|decrypt|encrypt)\b", re.I)),
    ("sage_crypto_script", "Sage/Python crypto script", re.compile(r"\b(from Crypto|Crypto\.|sage|Zmod|GF\(|inverse_mod|long_to_bytes)\b", re.I)),
    ("public_key_ciphertext", "public key/ciphertext files", re.compile(r"-----BEGIN (RSA |EC |)PUBLIC KEY-----|ciphertext|modulus|exponent", re.I)),
]


def scan_source(root_dir: str | Path, manifest: dict[str, Any]) -> dict[str, Any]:
    root = Path(root_dir).expanduser().resolve()
    signals: dict[str, list[dict[str, Any]]] = {
        "web": [],
        "pwn_rev": [],
        "crypto": [],
        "forensics_misc": [],
    }
    scores = {"web": 0, "pwn_rev": 0, "crypto": 0, "forensics_misc": 0}
    interesting: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    files = list(manifest.get("files", []))
    for item in files:
        path = str(item.get("path") or "")
        category = str(item.get("category") or "unknown")
        score = int(item.get("interesting_score") or 0)
        reasons = list(item.get("reasons") or [])
        if score > 0:
            _add_interesting(interesting, path, category, score, reasons)

        if category in {"binary", "shared_library"}:
            scores["pwn_rev"] += 5
            signal = {
                "kind": "elf_file" if category == "binary" else "shared_library",
                "description": "ELF/shared object candidate",
                "files": [path],
                "count": 1,
            }
            signals["pwn_rev"].append(signal)
            _add_interesting(interesting, path, category, score + 5, ["binary analysis candidate"])
            _scan_binary(root, item, signals, scores, interesting, warnings)

        if category in {"image", "audio", "video", "pcap", "document"}:
            scores["forensics_misc"] += 3
            signals["forensics_misc"].append(
                {
                    "kind": f"{category}_file",
                    "description": f"{category} artifact",
                    "files": [path],
                    "count": 1,
                }
            )
            _add_interesting(interesting, path, category, score + 3, ["forensics artifact"])

        lower_name = Path(path).name.lower()
        if lower_name in {"package.json", "requirements.txt", "dockerfile", "docker-compose.yml"}:
            scores["web"] += 3
            signals["web"].append(
                {
                    "kind": "runtime_descriptor",
                    "description": "package/runtime descriptor",
                    "files": [path],
                    "count": 1,
                }
            )

        if category in {"source", "config", "text"} and item.get("readable_text") and not is_sensitive_path(path):
            text = _read_bounded(root / path)
            if text:
                _scan_text_file(path, text, signals, scores, interesting)

    collapsed = {category: _collapse_signals(values) for category, values in signals.items()}
    likely = _likely_categories(scores)
    return {
        "signals_by_category": collapsed,
        "likely_categories": likely,
        "recommended_first_actions": _recommended_actions(likely),
        "interesting_files": sorted(interesting.values(), key=lambda item: (-item["score"], item["path"]))[
            :_MAX_INTERESTING_FILES
        ],
        "warnings": warnings,
    }


def _read_bounded(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            data = fh.read(SCAN_READ_LIMIT + 1)
    except OSError:
        return ""
    return data[:SCAN_READ_LIMIT].decode("utf-8", errors="replace")


def _scan_text_file(
    rel_path: str,
    text: str,
    signals: dict[str, list[dict[str, Any]]],
    scores: dict[str, int],
    interesting: dict[str, dict[str, Any]],
) -> None:
    safe_text = redact_ingest_text(text)
    for kind, description, pattern in _WEB_PATTERNS:
        count = len(pattern.findall(safe_text))
        if count:
            scores["web"] += min(count, 5)
            signals["web"].append({"kind": kind, "description": description, "files": [rel_path], "count": count})
            _add_interesting(interesting, rel_path, "source", 5 + count, [description])
    for kind, description, pattern in _CRYPTO_PATTERNS:
        count = len(pattern.findall(safe_text))
        if count:
            scores["crypto"] += min(count * 2, 8)
            signals["crypto"].append({"kind": kind, "description": description, "files": [rel_path], "count": count})
            _add_interesting(interesting, rel_path, "source", 5 + count, [description])


def _scan_binary(
    root: Path,
    item: dict[str, Any],
    signals: dict[str, list[dict[str, Any]]],
    scores: dict[str, int],
    interesting: dict[str, dict[str, Any]],
    warnings: list[str],
) -> None:
    rel_path = str(item.get("path") or "")
    file_path = root / rel_path
    keywords = _strings_keywords(file_path)
    if keywords:
        scores["pwn_rev"] += min(len(keywords) * 2, 10)
        signals["pwn_rev"].append(
            {
                "kind": "interesting_strings",
                "description": "strings keywords",
                "files": [rel_path],
                "count": len(keywords),
                "keywords": sorted(keywords),
            }
        )
        _add_interesting(interesting, rel_path, str(item.get("category") or "binary"), 8, [f"strings: {', '.join(sorted(keywords))}"])
    checksec = _checksec(file_path, root)
    if checksec:
        signals["pwn_rev"].append(
            {
                "kind": "checksec",
                "description": "checksec summary",
                "files": [rel_path],
                "count": 1,
                "summary": checksec,
            }
        )
    elif shutil.which("checksec") is None:
        warnings.append("checksec not available")


def _strings_keywords(path: Path) -> set[str]:
    if shutil.which("strings") is None:
        return set()
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", "4", str(path)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    safe_output = redact_ingest_text(result.stdout[:200_000]).lower()
    keywords = set()
    for keyword in ("flag", "win", "shell", "system", "/bin/sh", "password", "admin", "secret"):
        if keyword in safe_output:
            keywords.add(keyword)
    return keywords


def _checksec(path: Path, root: Path) -> str:
    checksec = shutil.which("checksec")
    if checksec is None:
        return ""
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = str(path)
    try:
        result = subprocess.run(
            [checksec, f"--file={rel}"],
            cwd=root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    output = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    output = redact_ingest_text(output)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return " | ".join(lines[:4])[:1000]


def _add_interesting(
    interesting: dict[str, dict[str, Any]],
    path: str,
    category: str,
    score: int,
    reasons: list[str],
) -> None:
    if not path:
        return
    entry = interesting.setdefault(path, {"path": path, "category": category, "score": 0, "reasons": []})
    entry["score"] = max(int(entry["score"]), int(score))
    for reason in reasons:
        if reason and reason not in entry["reasons"]:
            entry["reasons"].append(reason)
    entry["reasons"] = entry["reasons"][:8]


def _collapse_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    collapsed: dict[tuple[str, str], dict[str, Any]] = {}
    for signal in signals:
        key = (str(signal.get("kind")), str(signal.get("description")))
        item = collapsed.setdefault(
            key,
            {
                "kind": signal.get("kind"),
                "description": signal.get("description"),
                "files": [],
                "count": 0,
            },
        )
        item["count"] += int(signal.get("count") or 0)
        for path in signal.get("files") or []:
            if path not in item["files"] and len(item["files"]) < _MAX_SIGNAL_FILES:
                item["files"].append(path)
        for extra_key in ("keywords", "summary"):
            if extra_key in signal and extra_key not in item:
                item[extra_key] = signal[extra_key]
    return sorted(collapsed.values(), key=lambda item: (-int(item["count"]), str(item["kind"])))


def _likely_categories(scores: dict[str, int]) -> list[dict[str, Any]]:
    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return [{"category": category, "score": score} for category, score in ordered if score > 0]


def _recommended_actions(likely: list[dict[str, Any]]) -> list[str]:
    if not likely:
        return ["Review manifest top interesting files and challenge metadata."]
    top = likely[0]["category"]
    if top == "web":
        return [
            "Start with routes, auth/session handling, input parsing, and template/file sinks.",
            "Review package/runtime descriptors before sending payloads.",
        ]
    if top == "pwn_rev":
        return [
            "Inspect ELF protections and strings; do not execute attachments during ingest.",
            "Select primary binary plus libc/ld candidates for worker analysis.",
        ]
    if top == "crypto":
        return [
            "Identify algorithm, public parameters, ciphertexts, and helper scripts.",
            "Prefer bounded local parsing before Sage or heavy math.",
        ]
    return [
        "Inspect media/pcap/document metadata with offline tools only.",
        "Preserve originals and work from extracted copies/manifests.",
    ]
