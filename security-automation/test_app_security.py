"""Test cases for security-scan.py.

All tests use --engine builtin so results are deterministic and need no network
or external tools. Run with:  python -m pytest -v
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "security-scan.py"
EXAMPLES = ROOT / "examples"


def scan(path, *extra):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--path", str(path), "--format", "json",
         "--engine", "builtin", *extra],
        capture_output=True, text=True,
    )
    report = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, report, proc.stdout


def test_vulnerable_app_fails_across_all_four_categories():
    code, report, _ = scan(EXAMPLES / "vulnerable-app")
    assert code == 1
    assert report["decision"] == "FAIL"
    assert {f["category"] for f in report["findings"]} == {"sast", "dependencies", "secrets", "iac"}
    assert report["summary"]["critical"] >= 1


def test_clean_app_passes():
    code, report, _ = scan(EXAMPLES / "clean-app")
    assert code == 0
    assert report["decision"] == "PASS"
    assert report["total"] == 0


def test_dotenv_secret_is_found_and_never_printed(tmp_path):
    secret_value = "SuperSecret123"
    (tmp_path / ".env").write_text("DB_PASSWORD = " + '"' + secret_value + '"' + "\n")
    code, report, raw = scan(tmp_path)
    assert code == 1
    assert any(f["file"] == ".env" and f["category"] == "secrets" for f in report["findings"])
    assert secret_value not in raw


def test_dependency_check_compares_versions(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\npyyaml==6.0.1\n")
    code, report, _ = scan(tmp_path)
    flagged = [f["message"] for f in report["findings"] if f["category"] == "dependencies"]
    assert code == 1
    assert len(flagged) == 1 and flagged[0].startswith("requests 2.30.0")  # fixed pyyaml is not flagged


def test_fail_on_threshold_and_bad_path(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")          # unpinned: low severity only
    assert scan(tmp_path)[0] == 0                                  # default threshold is high
    assert scan(tmp_path, "--fail-on", "low")[0] == 1
    assert scan(tmp_path / "missing")[0] == 2                      # usage error
