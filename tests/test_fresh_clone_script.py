from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_fresh_clone_check_script_help_is_public_safe():
    result = subprocess.run(
        [str(ROOT / "scripts" / "fresh-clone-check.sh"), "--help"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    assert "--keep-dir" in result.stdout
    assert "external CTF" in result.stdout
    assert "interactive" in result.stdout.lower()
    assert "cookie" not in result.stdout.lower()


def test_fresh_clone_check_script_syntax():
    result = subprocess.run(
        ["bash", "-n", str(ROOT / "scripts" / "fresh-clone-check.sh")],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
