from __future__ import annotations

import os
import platform
import re
import shutil
from pathlib import Path
from typing import Any, Iterable, Mapping

from .docker_pool import DEFAULT_IMAGE, docker_environment, image_exists
from .redact import redact_text
from .state import utc_now


PLAYBOOK_CATEGORIES = ("web", "pwn", "rev", "crypto", "forensics/misc", "osint", "ai/ml", "kernel/initramfs", "remote", "core")
DOCTOR_COMMANDS = (
    "python3",
    "pip",
    "uv",
    "git",
    "curl",
    "wget",
    "nc",
    "openssl",
    "socat",
    "file",
    "strings",
    "readelf",
    "objdump",
    "checksec",
    "gdb",
    "lldb",
    "qemu-system-x86_64",
    "cpio",
    "ncat",
    "tshark",
    "zsteg",
    "steghide",
    "foremost",
    "yara",
    "volatility3",
    "scapy",
    "sage",
    "z3",
    "ROPgadget",
    "one_gadget",
    "patchelf",
    "pwninit",
    "docker",
)

_TOOL_CATEGORIES: dict[str, tuple[str, ...]] = {
    "python3": ("core", "web", "pwn", "rev", "crypto", "forensics/misc", "osint", "ai/ml"),
    "pip": ("core", "web", "pwn", "rev", "crypto", "forensics/misc", "ai/ml"),
    "uv": ("core", "web", "pwn", "rev", "crypto", "ai/ml"),
    "git": ("core", "web", "pwn", "rev", "crypto", "forensics/misc", "osint", "ai/ml"),
    "curl": ("core", "web", "osint", "remote"),
    "wget": ("core", "web", "osint", "remote"),
    "nc": ("remote", "web", "pwn"),
    "ncat": ("remote", "web", "pwn"),
    "openssl": ("core", "remote", "web", "crypto", "pwn"),
    "socat": ("remote", "web", "pwn"),
    "file": ("core", "pwn", "rev", "forensics/misc", "kernel/initramfs"),
    "strings": ("core", "pwn", "rev", "forensics/misc", "kernel/initramfs"),
    "readelf": ("pwn", "rev", "kernel/initramfs"),
    "objdump": ("pwn", "rev"),
    "checksec": ("pwn",),
    "gdb": ("pwn", "rev"),
    "lldb": ("pwn", "rev"),
    "qemu-system-x86_64": ("pwn", "kernel/initramfs"),
    "cpio": ("forensics/misc", "kernel/initramfs", "pwn"),
    "tshark": ("forensics/misc",),
    "zsteg": ("forensics/misc",),
    "steghide": ("forensics/misc",),
    "foremost": ("forensics/misc",),
    "yara": ("forensics/misc", "rev"),
    "volatility3": ("forensics/misc",),
    "scapy": ("forensics/misc", "web", "crypto"),
    "sage": ("crypto",),
    "z3": ("crypto", "rev"),
    "ROPgadget": ("pwn",),
    "one_gadget": ("pwn",),
    "patchelf": ("pwn",),
    "pwninit": ("pwn",),
    "docker": ("core", "pwn", "rev", "kernel/initramfs"),
    "ctf-pwn:latest": ("pwn", "rev", "kernel/initramfs"),
    "binwalk": ("forensics/misc", "kernel/initramfs"),
    "exiftool": ("forensics/misc", "osint"),
    "xxd": ("forensics/misc", "rev", "crypto"),
    "tcpdump": ("forensics/misc",),
    "bsdtar": ("forensics/misc", "kernel/initramfs"),
    "r2": ("rev",),
    "ghidra": ("rev",),
    "pwntools": ("pwn",),
}

_HIGH_PRIORITY: dict[str, tuple[str, ...]] = {
    "core": ("python3", "git", "curl", "file", "strings", "openssl"),
    "remote": ("ncat", "nc", "openssl", "socat"),
    "web": ("python3", "curl", "openssl", "nc", "ncat"),
    "pwn": ("python3", "file", "strings", "readelf", "objdump", "checksec", "gdb", "lldb", "ncat", "patchelf", "pwninit", "docker", "ctf-pwn:latest"),
    "rev": ("python3", "file", "strings", "readelf", "objdump", "gdb", "lldb", "r2", "ghidra", "docker", "ctf-pwn:latest"),
    "crypto": ("python3", "openssl", "sage", "z3"),
    "forensics/misc": ("file", "strings", "binwalk", "exiftool", "tshark", "zsteg", "steghide", "foremost", "yara", "volatility3"),
    "osint": ("curl", "wget", "exiftool"),
    "ai/ml": ("python3", "pip", "uv"),
    "kernel/initramfs": ("file", "strings", "qemu-system-x86_64", "cpio", "docker", "ctf-pwn:latest"),
}

_INSTALL_HINTS: dict[str, dict[str, str]] = {
    "ncat": {"macos": "brew install nmap", "linux": "apt install ncat or dnf install nmap-ncat", "windows_wsl": "apt install ncat inside WSL"},
    "nc": {"macos": "use the system nc or brew install netcat", "linux": "apt install netcat-openbsd", "windows_wsl": "apt install netcat-openbsd inside WSL"},
    "cpio": {"macos": "brew install cpio if the system cpio is unavailable", "linux": "apt install cpio", "windows_wsl": "apt install cpio inside WSL"},
    "tshark": {"macos": "brew install wireshark", "linux": "apt install tshark", "windows_wsl": "apt install tshark inside WSL"},
    "zsteg": {"macos": "gem install zsteg", "linux": "gem install zsteg", "windows_wsl": "gem install zsteg inside WSL"},
    "steghide": {"macos": "brew install steghide", "linux": "apt install steghide", "windows_wsl": "apt install steghide inside WSL"},
    "foremost": {"macos": "brew install foremost", "linux": "apt install foremost", "windows_wsl": "apt install foremost inside WSL"},
    "yara": {"macos": "brew install yara", "linux": "apt install yara", "windows_wsl": "apt install yara inside WSL"},
    "volatility3": {"macos": "pipx install volatility3", "linux": "pipx install volatility3", "windows_wsl": "pipx install volatility3 inside WSL"},
    "sage": {"macos": "brew install sage", "linux": "apt install sagemath", "windows_wsl": "apt install sagemath inside WSL"},
    "z3": {"macos": "brew install z3 or pip install z3-solver", "linux": "apt install z3 or pip install z3-solver", "windows_wsl": "apt install z3 inside WSL"},
    "ROPgadget": {"macos": "pipx install ROPGadget", "linux": "pipx install ROPGadget", "windows_wsl": "pipx install ROPGadget inside WSL"},
    "one_gadget": {"macos": "gem install one_gadget", "linux": "gem install one_gadget", "windows_wsl": "gem install one_gadget inside WSL"},
    "patchelf": {"macos": "brew install patchelf", "linux": "apt install patchelf", "windows_wsl": "apt install patchelf inside WSL"},
    "pwninit": {"macos": "install pwninit from its release binary", "linux": "install pwninit from its release binary", "windows_wsl": "install pwninit inside WSL"},
    "checksec": {"macos": "brew install checksec", "linux": "apt install checksec", "windows_wsl": "apt install checksec inside WSL"},
    "qemu-system-x86_64": {"macos": "brew install qemu", "linux": "apt install qemu-system-x86", "windows_wsl": "apt install qemu-system-x86 inside WSL"},
    "ctf-pwn:latest": {"macos": "build or load the ctf-pwn:latest Docker image", "linux": "build or load the ctf-pwn:latest Docker image", "windows_wsl": "build or load ctf-pwn:latest with Docker Desktop WSL integration"},
    "pwntools": {"macos": "pipx install pwntools or install in a virtualenv", "linux": "pipx install pwntools or install in a virtualenv", "windows_wsl": "pipx install pwntools inside WSL"},
}

_FALLBACKS: dict[str, list[dict[str, Any]]] = {
    "ncat": [
        {
            "id": "openssl_s_client",
            "description": "Use OpenSSL for TLS services when ncat --ssl is unavailable.",
            "requires": ["openssl"],
            "command_templates": ["openssl s_client -connect HOST:PORT -servername HOST -quiet"],
        },
        {
            "id": "nc_plain_tcp",
            "description": "Use nc for non-TLS TCP services.",
            "requires": ["nc"],
            "command_templates": ["nc HOST PORT"],
        },
        {
            "id": "socat_tcp",
            "description": "Use socat for TCP/TLS plumbing when installed.",
            "requires": ["socat"],
            "command_templates": ["socat - TCP:HOST:PORT", "socat - OPENSSL:HOST:PORT,verify=0"],
        },
    ],
    "nc": [
        {
            "id": "ncat_plain_tcp",
            "description": "Use ncat for plain TCP services.",
            "requires": ["ncat"],
            "command_templates": ["ncat HOST PORT"],
        },
        {
            "id": "python_socket",
            "description": "Use a small Python socket script for basic TCP interaction.",
            "requires": ["python3"],
            "command_templates": ["python3 - <<'PY'\nimport socket\ns=socket.create_connection(('HOST', PORT), timeout=5)\nprint(s.recv(4096))\nPY"],
        },
    ],
    "cpio": [
        {
            "id": "bsdtar_cpio_extract",
            "description": "Use bsdtar to list or extract many cpio/initramfs archives.",
            "requires": ["bsdtar"],
            "command_templates": ["mkdir -p extracted && bsdtar -xf initramfs.cpio -C extracted", "bsdtar -tf initramfs.cpio | sed -n '1,80p'"],
        },
        {
            "id": "python_cpio_parser",
            "description": "Use a small Python newc parser for simple initramfs extraction when cpio is absent.",
            "requires": ["python3"],
            "command_templates": ["python3 scripts/extract_newc.py initramfs.cpio extracted"],
        },
        {
            "id": "docker_ctf_pwn_extract",
            "description": "Use the ctf-pwn Docker image if local archive tooling is incomplete.",
            "requires": ["docker", "ctf-pwn:latest"],
            "command_templates": ["ctfctl docker pool-exec --contest-id <contest> --worker-id <worker> --command 'mkdir -p extracted && cd extracted && cpio -idmv < ../initramfs.cpio' --json"],
        },
    ],
    "tshark": [
        {
            "id": "tcpdump_read",
            "description": "Use tcpdump for quick packet summaries when tshark is missing.",
            "requires": ["tcpdump"],
            "command_templates": ["tcpdump -nn -r capture.pcap | sed -n '1,120p'"],
        },
        {
            "id": "scapy_read",
            "description": "Use Scapy from Python for packet parsing and extraction.",
            "requires": ["python3", "scapy"],
            "command_templates": ["python3 - <<'PY'\nfrom scapy.all import rdpcap\nfor p in rdpcap('capture.pcap')[:20]: print(p.summary())\nPY"],
        },
    ],
    "zsteg": [
        {
            "id": "file_strings_binwalk",
            "description": "Fall back to format identification, strings, and carving before zsteg-specific LSB checks.",
            "requires": ["file", "strings"],
            "command_templates": ["file image.png", "strings -a -n 5 image.png | sed -n '1,120p'", "binwalk image.png"],
        }
    ],
    "steghide": [
        {
            "id": "file_binwalk_strings",
            "description": "Check file structure and embedded data when steghide is unavailable.",
            "requires": ["file", "strings"],
            "command_templates": ["file artifact", "binwalk artifact", "strings -a -n 5 artifact | sed -n '1,120p'"],
        }
    ],
    "r2": [
        {
            "id": "objdump_readelf",
            "description": "Use objdump/readelf/strings for first-pass reversing when radare2/rizin is unavailable.",
            "requires": ["objdump", "readelf", "strings"],
            "command_templates": ["readelf -h ./chall", "objdump -d ./chall | sed -n '1,160p'", "strings -a -n 4 ./chall | sed -n '1,160p'"],
        },
        {
            "id": "ghidra_reva",
            "description": "Use Ghidra or ReVa for deeper reversing if local CLI disassembly is not enough.",
            "requires": ["ghidra"],
            "command_templates": ["Open the primary artifact in Ghidra/ReVa and record findings in evidence.md."],
        },
    ],
    "pwninit": [
        {
            "id": "patchelf_manual_libc",
            "description": "Patch interpreter/RPATH manually when pwninit is missing.",
            "requires": ["patchelf"],
            "command_templates": ["patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./chall"],
        },
        {
            "id": "docker_ctf_pwn_runtime",
            "description": "Run the binary inside ctf-pwn Docker when libc setup is awkward locally.",
            "requires": ["docker", "ctf-pwn:latest"],
            "command_templates": ["ctfctl docker pool-exec --contest-id <contest> --worker-id <worker> --command './chall' --json"],
        },
    ],
    "checksec": [
        {
            "id": "readelf_objdump_protections",
            "description": "Approximate binary protection checks with readelf/objdump.",
            "requires": ["readelf", "objdump"],
            "command_templates": ["readelf -h ./chall", "readelf -l ./chall | rg 'GNU_STACK|GNU_RELRO'", "objdump -x ./chall | rg 'RELRO|STACK|NX'"],
        }
    ],
    "pwntools": [
        {
            "id": "python_socket_subprocess",
            "description": "Use Python socket/subprocess helpers until pwntools is installed.",
            "requires": ["python3"],
            "command_templates": ["python3 exploit.py"],
        }
    ],
}

_MODULE_TOOL_MAP = {"pwn": "pwntools", "z3": "z3", "scapy": "scapy", "requests": "requests"}


def collect_toolchain_capabilities(*, category: str | None = None, probe_docker: bool = True) -> dict[str, Any]:
    selected_categories = _selected_categories(category)
    tool_names = _tool_names_for_categories(selected_categories)
    platform_info = platform_notes()
    tools = [_tool_status(name, platform_info=platform_info, probe_docker=probe_docker) for name in tool_names]
    by_name = {str(row["name"]): row for row in tools}
    tools_by_category = {
        cat: [by_name[name] for name in sorted(tool_names) if cat in _TOOL_CATEGORIES.get(name, ())]
        for cat in selected_categories
    }
    missing = _missing_high_priority(selected_categories, by_name)
    recommended = _recommended_fallbacks(missing, by_name)
    available = sorted(name for name, row in by_name.items() if row.get("available"))
    docker = {
        "available": bool(by_name.get("docker", {}).get("available")),
        "checked": bool(probe_docker),
        "reachable": bool(by_name.get("docker", {}).get("reachable")),
        "ctf_pwn_image": by_name.get("ctf-pwn:latest", {}),
    }
    return {
        "status": "ok",
        "schema": "ctf_toolchain_capabilities_v1",
        "generated_at": utc_now(),
        "category": category or "",
        "categories": list(selected_categories),
        "platform": platform_info,
        "tools": tools,
        "tools_by_category": tools_by_category,
        "available_tools": available,
        "missing_high_priority_tools": missing,
        "recommended_fallbacks": recommended,
        "docker": docker,
        "no_auto_install": True,
    }


def toolchain_doctor(*, category: str | None = None) -> dict[str, Any]:
    report = collect_toolchain_capabilities(category=category, probe_docker=True)
    report["schema"] = "ctf_toolchain_doctor_v1"
    report["doctor_commands"] = list(DOCTOR_COMMANDS)
    report["install_policy"] = "no automatic install; hints are planned operator actions only"
    return report


def fallback_suggestions(tool: str, *, available_tools: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, Any]:
    normalized = _normalize_tool_name(tool)
    suggestions = []
    for row in _FALLBACKS.get(normalized, []):
        item = dict(row)
        if available_tools is not None:
            item["available"] = all(bool((available_tools.get(req) or {}).get("available")) for req in item.get("requires") or [])
        suggestions.append(item)
    install_hints = _INSTALL_HINTS.get(normalized, {})
    return {
        "status": "ok" if suggestions or install_hints else "unknown_tool",
        "tool": normalized,
        "suggestions": suggestions,
        "install_hints": install_hints,
        "no_auto_install": True,
    }


def summarize_capabilities_for_category(report: Mapping[str, Any], category: str | None = None) -> dict[str, Any]:
    normalized = _normalize_category(category or str(report.get("category") or ""))
    selected = [normalized] if normalized else list(report.get("categories") or [])
    tools = report.get("tools") if isinstance(report.get("tools"), list) else []
    by_name = {str(row.get("name")): row for row in tools if isinstance(row, Mapping)}
    category_tools = [
        name
        for name, row in by_name.items()
        if not selected or any(cat in _TOOL_CATEGORIES.get(name, ()) for cat in selected) or name in _HIGH_PRIORITY.get(normalized, ())
    ]
    available = sorted(name for name in category_tools if by_name.get(name, {}).get("available"))
    missing = _missing_high_priority(tuple(selected or ["core"]), by_name)
    recommended = _recommended_fallbacks(missing, by_name)
    return {
        "category": normalized or "",
        "available_tools": available,
        "missing_critical_tools": missing,
        "recommended_fallbacks": recommended,
        "platform_notes": list((report.get("platform") or {}).get("notes") or []),
        "docker": report.get("docker") or {},
        "generated_at": str(report.get("generated_at") or ""),
    }


def render_capabilities_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Toolchain Capabilities",
        "",
        f"- generated_at: {report.get('generated_at')}",
        f"- category: {report.get('category') or 'all'}",
        "- install_policy: no automatic sudo/install; hints are planned operator actions only",
        "",
        "## Platform",
    ]
    platform_info = report.get("platform") if isinstance(report.get("platform"), Mapping) else {}
    for key in ("os", "system", "machine", "is_wsl", "is_macos", "is_windows"):
        lines.append(f"- {key}: {platform_info.get(key)}")
    notes = list(platform_info.get("notes") or [])
    if notes:
        lines.extend(["", "## Platform Notes"])
        lines.extend(f"- {redact_text(str(note))}" for note in notes)
    lines.extend(["", "## Tools By Category"])
    tools_by_category = report.get("tools_by_category") if isinstance(report.get("tools_by_category"), Mapping) else {}
    for category, rows in tools_by_category.items():
        lines.append(f"### {category}")
        for row in rows if isinstance(rows, list) else []:
            status = "available" if row.get("available") else "missing"
            priority = str(row.get("priority") or "optional")
            lines.append(f"- {row.get('name')}: {status} ({priority})")
    missing = list(report.get("missing_high_priority_tools") or [])
    lines.extend(["", "## Missing High-Priority Tools"])
    lines.extend(f"- {tool}" for tool in missing) if missing else lines.append("- none")
    fallbacks = list(report.get("recommended_fallbacks") or [])
    lines.extend(["", "## Recommended Fallbacks"])
    if fallbacks:
        for row in fallbacks:
            suggestions = ", ".join(str(item.get("id") or "") for item in row.get("suggestions") or [])
            lines.append(f"- {row.get('tool')}: {suggestions or 'install/planned action'}")
    else:
        lines.append("- none")
    lines.extend(["", "## Docker"])
    docker = report.get("docker") if isinstance(report.get("docker"), Mapping) else {}
    image = docker.get("ctf_pwn_image") if isinstance(docker.get("ctf_pwn_image"), Mapping) else {}
    lines.append(f"- docker_available: {docker.get('available')}")
    lines.append(f"- docker_reachable: {docker.get('reachable')}")
    lines.append(f"- ctf_pwn_image_available: {image.get('available')}")
    return "\n".join(lines) + "\n"


def command_available(report: Mapping[str, Any], command: str) -> bool:
    by_name = _tools_by_name(report)
    row = by_name.get(_normalize_tool_name(command))
    if row is not None:
        return bool(row.get("available"))
    return shutil.which(command) is not None


def choose_command_or_fallback(command: list[str], report: Mapping[str, Any]) -> tuple[list[str] | None, dict[str, Any] | None]:
    if not command:
        return None, None
    tool = _normalize_tool_name(command[0])
    if command_available(report, tool):
        return command, None
    fallback = fallback_command_for(tool, command, report)
    if fallback:
        return list(fallback["command"]), fallback
    return None, {"tool": tool, "reason": "tool_missing", "fallbacks": fallback_suggestions(tool, available_tools=_tools_by_name(report)).get("suggestions", [])}


def fallback_command_for(tool: str, original: list[str], report: Mapping[str, Any]) -> dict[str, Any] | None:
    tool = _normalize_tool_name(tool)
    by_name = _tools_by_name(report)
    target = _last_pathish_arg(original)
    def avail(name: str) -> bool:
        return bool((by_name.get(name) or {}).get("available")) or (name not in by_name and shutil.which(name) is not None)

    if tool == "checksec" and target:
        if avail("readelf"):
            return {"tool": tool, "fallback_id": "readelf_objdump_protections", "command": ["readelf", "-h", target], "reason": "checksec_missing"}
        if avail("objdump"):
            return {"tool": tool, "fallback_id": "objdump_headers", "command": ["objdump", "-x", target], "reason": "checksec_missing"}
    if tool == "readelf" and target and avail("objdump"):
        return {"tool": tool, "fallback_id": "objdump_headers", "command": ["objdump", "-f", target], "reason": "readelf_missing"}
    if tool == "objdump" and target and avail("readelf"):
        return {"tool": tool, "fallback_id": "readelf_headers", "command": ["readelf", "-h", target], "reason": "objdump_missing"}
    if tool in {"exiftool", "binwalk"} and target:
        if avail("file"):
            return {"tool": tool, "fallback_id": "file_identify", "command": ["file", target], "reason": f"{tool}_missing"}
        if avail("strings"):
            return {"tool": tool, "fallback_id": "strings_scan", "command": ["strings", "-a", "-n", "5", target], "reason": f"{tool}_missing"}
    if tool == "tshark" and target:
        if avail("tcpdump"):
            return {"tool": tool, "fallback_id": "tcpdump_read", "command": ["tcpdump", "-nn", "-r", target], "reason": "tshark_missing"}
    return None


def detect_missing_tool_failure(stdout: str, stderr: str) -> dict[str, Any] | None:
    text = f"{stdout}\n{stderr}"
    patterns = [
        r"(?P<tool>[A-Za-z0-9_.+-]+): command not found",
        r"command not found: (?P<tool>[A-Za-z0-9_.+-]+)",
        r"No such file or directory: ['\"](?P<tool>[^'\"]+)['\"]",
        r"ModuleNotFoundError: No module named ['\"](?P<module>[^'\"]+)['\"]",
        r"ImportError: No module named (?P<module>[A-Za-z0-9_.+-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        raw = match.groupdict().get("tool") or match.groupdict().get("module") or ""
        name = _MODULE_TOOL_MAP.get(raw, raw)
        tool = _normalize_tool_name(Path(name).name)
        return {"tool": tool, "raw": raw, "fallback": fallback_suggestions(tool)}
    return None


def platform_notes() -> dict[str, Any]:
    system = platform.system()
    lower = system.lower()
    is_wsl = _is_wsl()
    is_macos = lower == "darwin"
    is_windows = lower == "windows"
    os_name = "windows_wsl" if is_wsl else "macos" if is_macos else "windows" if is_windows else "linux" if lower == "linux" else lower or "unknown"
    notes: list[str] = []
    if is_wsl:
        notes.append("Use Linux tools inside WSL; Windows-native tools may not be visible on PATH.")
        notes.append("Docker fallback requires Docker Desktop WSL integration or a reachable Linux Docker daemon.")
    elif is_macos:
        notes.append("macOS ships BSD userland; GNU ELF tooling may need Homebrew binutils or Docker fallback.")
        notes.append("Apple Silicon may need Docker linux/amd64 images for pwn/rev parity.")
    elif is_windows:
        notes.append("Prefer WSL2 for Linux CTF tooling; native Windows shells will miss many ELF and pwn tools.")
    elif lower == "linux":
        notes.append("Linux host detected; package names vary by distro and install hints are planned actions only.")
    else:
        notes.append("Unknown platform; prefer Docker or WSL/Linux for CTF tool parity.")
    return {
        "os": os_name,
        "system": system,
        "release": platform.release(),
        "machine": platform.machine(),
        "is_wsl": is_wsl,
        "is_macos": is_macos,
        "is_windows": is_windows,
        "notes": notes,
    }


def _tool_status(name: str, *, platform_info: Mapping[str, Any], probe_docker: bool) -> dict[str, Any]:
    categories = list(_TOOL_CATEGORIES.get(name, ()))
    priority = _priority_for_tool(name)
    if name == "ctf-pwn:latest":
        row: dict[str, Any] = {
            "name": name,
            "kind": "docker_image",
            "available": False,
            "categories": categories,
            "priority": priority,
            "install_hint": _install_hint(name, platform_info),
        }
        if probe_docker:
            image = image_exists(DEFAULT_IMAGE)
            row.update({"available": bool(image.get("exists")), "checked": bool(image.get("checked")), "reason": image.get("reason")})
        else:
            row.update({"checked": False, "reason": "not_probed"})
        return row
    if name == "docker" and probe_docker:
        env = docker_environment()
        return {
            "name": name,
            "kind": "command",
            "available": bool(env.get("found")),
            "reachable": bool(env.get("reachable")),
            "categories": categories,
            "priority": priority,
            "reason": env.get("classification") or env.get("reason") or "ok",
            "install_hint": _install_hint(name, platform_info),
        }
    found = shutil.which(name)
    return {
        "name": name,
        "kind": "command",
        "available": bool(found),
        "categories": categories,
        "priority": priority,
        "reason": "ok" if found else "missing",
        "install_hint": _install_hint(name, platform_info),
    }


def _selected_categories(category: str | None) -> tuple[str, ...]:
    normalized = _normalize_category(category or "")
    if normalized:
        categories = ["core", normalized]
        if normalized in {"web", "pwn"}:
            categories.append("remote")
        if normalized == "kernel/initramfs":
            categories.append("pwn")
        return tuple(dict.fromkeys(categories))
    return PLAYBOOK_CATEGORIES


def _tool_names_for_categories(categories: Iterable[str]) -> list[str]:
    selected = set(categories)
    names = set(DOCTOR_COMMANDS)
    names.add("ctf-pwn:latest")
    names.update(name for name, cats in _TOOL_CATEGORIES.items() if selected.intersection(cats))
    return sorted(names)


def _missing_high_priority(categories: Iterable[str], by_name: Mapping[str, Mapping[str, Any]]) -> list[str]:
    result: list[str] = []
    for category in categories:
        for name in _HIGH_PRIORITY.get(category, ()):
            row = by_name.get(name)
            if row is None:
                continue
            if not row.get("available"):
                result.append(name)
    return sorted(dict.fromkeys(result))


def _recommended_fallbacks(missing: Iterable[str], by_name: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for tool in missing:
        fallback = fallback_suggestions(tool, available_tools=by_name)
        suggestions = list(fallback.get("suggestions") or [])
        if suggestions or fallback.get("install_hints"):
            rows.append({"tool": tool, "suggestions": suggestions[:4], "install_hints": fallback.get("install_hints") or {}})
    return rows


def _install_hint(name: str, platform_info: Mapping[str, Any]) -> str:
    hints = _INSTALL_HINTS.get(name) or {}
    os_name = str(platform_info.get("os") or "")
    return str(hints.get(os_name) or hints.get("linux") or "")


def _priority_for_tool(name: str) -> str:
    if name in _HIGH_PRIORITY.get("core", ()):
        return "critical"
    if any(name in values for category, values in _HIGH_PRIORITY.items() if category != "core"):
        return "high"
    return "optional"


def _normalize_category(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    compact = re.sub(r"[^a-z0-9]+", "", raw)
    if compact in {"", "all"}:
        return ""
    if compact in {"web", "http", "browser"}:
        return "web"
    if compact in {"pwn", "pwnable", "binaryexploitation", "exploit"}:
        return "pwn"
    if compact in {"rev", "reverse", "reversing", "reverseengineering"}:
        return "rev"
    if compact in {"crypto", "cryptography"}:
        return "crypto"
    if compact in {"forensics", "forensic", "misc", "stego", "steganography", "network"}:
        return "forensics/misc"
    if compact in {"osint", "opensourceintelligence"}:
        return "osint"
    if compact in {"ai", "ml", "aiml", "machinelearning", "llm"}:
        return "ai/ml"
    if compact in {"kernel", "initramfs", "kernelinitramfs"}:
        return "kernel/initramfs"
    if compact in {"remote", "netcat", "tcp"}:
        return "remote"
    if compact == "core":
        return "core"
    return raw if raw in PLAYBOOK_CATEGORIES else ""


def _normalize_tool_name(tool: str) -> str:
    raw = str(tool or "").strip()
    aliases = {
        "netcat": "nc",
        "nmap-ncat": "ncat",
        "radare2": "r2",
        "rizin": "r2",
        "ropgadget": "ROPgadget",
        "ctf-pwn": "ctf-pwn:latest",
        "ctf-pwn image": "ctf-pwn:latest",
    }
    return aliases.get(raw.lower(), raw)


def _tools_by_name(report: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    tools = report.get("tools") if isinstance(report.get("tools"), list) else []
    return {str(row.get("name")): row for row in tools if isinstance(row, Mapping)}


def _last_pathish_arg(command: list[str]) -> str:
    for part in reversed(command[1:]):
        if part.startswith("-"):
            continue
        if "=" in part and part.split("=", 1)[0].startswith("--"):
            return part.split("=", 1)[1]
        return part
    return ""


def _is_wsl() -> bool:
    if "WSL_DISTRO_NAME" in os.environ:
        return True
    try:
        text = Path("/proc/version").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False
    return "microsoft" in text or "wsl" in text
