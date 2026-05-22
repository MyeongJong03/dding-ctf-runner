from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "lib" / "macos-fd-limit.sh"


def test_macos_fd_limit_helper_syntax():
    result = subprocess.run(
        ["bash", "-n", str(HELPER)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_release_and_fresh_clone_scripts_load_fd_helper():
    for rel in ("scripts/release-check.sh", "scripts/fresh-clone-check.sh", "scripts/ctfctl"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "scripts/lib/macos-fd-limit.sh" in text
        assert "ctf_runner_raise_macos_fd_limit" in text
