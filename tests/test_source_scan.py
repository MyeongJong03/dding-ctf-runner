from pathlib import Path

from ctf_runner.file_manifest import build_manifest
from ctf_runner.source_scan import scan_source


def test_source_scan_detects_web_signals(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "\n".join(
            [
                "from flask import Flask, request, render_template",
                "app = Flask(__name__)",
                "@app.route('/upload', methods=['POST'])",
                "def upload():",
                "    filename = request.files['f'].filename",
                "    return eval(request.form['x'])",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"1.0.0"}}\n', encoding="utf-8")

    manifest = build_manifest(tmp_path)
    scan = scan_source(tmp_path, manifest)
    web_kinds = {item["kind"] for item in scan["signals_by_category"]["web"]}

    assert "route_definition" in web_kinds
    assert "code_execution_sink" in web_kinds
    assert "upload_file_path" in web_kinds
    assert scan["likely_categories"][0]["category"] == "web"


def test_source_scan_elf_like_file_without_execution(tmp_path: Path):
    (tmp_path / "chall").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"system\x00/bin/sh\x00" + b"\x00" * 64)

    manifest = build_manifest(tmp_path)
    scan = scan_source(tmp_path, manifest)

    assert any(item["category"] == "pwn_rev" for item in scan["likely_categories"])
    assert any(item["kind"] in {"elf_file", "interesting_strings"} for item in scan["signals_by_category"]["pwn_rev"])
