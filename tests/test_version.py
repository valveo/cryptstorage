"""The build version the server shows (api/version.py, scripts/version.sh)."""
import os
import re
import subprocess

import version

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_version_file_is_read_and_missing_means_dev(tmp_path, monkeypatch):
    monkeypatch.setattr(version, "_FILE", str(tmp_path / "BUILD_VERSION"))
    assert version._read() == "dev"
    (tmp_path / "BUILD_VERSION").write_text("dev+9151441 (2026-10-29)\n")
    assert version._read() == "dev+9151441 (2026-10-29)"
    (tmp_path / "BUILD_VERSION").write_text("x" * 500)
    assert len(version._read()) == 80


def test_health_and_server_info_show_it(client):
    assert client.get("/health").json()["version"] == version.VERSION


def test_version_script_names_the_commit():
    out = subprocess.run([os.path.join(ROOT, "scripts", "version.sh")], capture_output=True, text=True, check=True).stdout
    assert re.fullmatch(r"(dev\+[0-9a-f]{7}(-modified)?|\d[^ ]*) \(\d{4}-\d\d-\d\d\)\n", out), out
