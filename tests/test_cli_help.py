import subprocess
import sys


def test_help_lists_safety_commands():
    result = subprocess.run(
        [sys.executable, "-m", "hijackrewind", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    text = result.stdout.casefold()
    for word in ("ingest", "kill", "audit", "dashboard", "trap-pack", "sandbox"):
        assert word in text
