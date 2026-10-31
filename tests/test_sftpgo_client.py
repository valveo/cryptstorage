"""
The daemon's SFTPGo client against a REAL SFTPGo server (SFTPGO_BIN, or /usr/bin/sftpgo). Skipped when the
binary is not installed; CI installs the pinned release (scripts/install_sftpgo.sh).
"""
import os
import shutil
import socket
import subprocess
import time

import pytest

import sftpgo_client as sg

SFTPGO = os.getenv("SFTPGO_BIN") or shutil.which("sftpgo")
pytestmark = pytest.mark.skipif(not SFTPGO, reason="sftpgo is not installed")

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host"
KEY2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPb5R0xGb3Zq2yqjEJbQsmP1m7eC0tqZ4Zk9d4m3lhQe other@host"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    base = tmp_path_factory.mktemp("sftpgo")
    cfg, data = base / "cfg", base / "data"
    cfg.mkdir(); data.mkdir()
    share = os.getenv("SFTPGO_SHARE") or "/usr/share/sftpgo"
    for d in ("templates", "static", "openapi"):
        if os.path.isdir(f"{share}/{d}"):
            os.symlink(f"{share}/{d}", cfg / d)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cfg / "hostkey")], check=True)
    api, sftp = _free_port(), _free_port()
    env = dict(os.environ, SFTPGO_CONFIG_DIR=str(cfg), SFTPGO_LOG_FILE_PATH="",
               SFTPGO_DATA_PROVIDER__DRIVER="sqlite", SFTPGO_DATA_PROVIDER__NAME=str(cfg / "db"),
               SFTPGO_DATA_PROVIDER__CREATE_DEFAULT_ADMIN="1", SFTPGO_DEFAULT_ADMIN_USERNAME="cryptstorage",
               SFTPGO_DEFAULT_ADMIN_PASSWORD="pw-for-tests-123456",
               SFTPGO_SFTPD__BINDINGS__0__PORT=str(sftp), SFTPGO_SFTPD__BINDINGS__0__ADDRESS="127.0.0.1",
               SFTPGO_SFTPD__HOST_KEYS=str(cfg / "hostkey"),
               SFTPGO_HTTPD__BINDINGS__0__PORT=str(api), SFTPGO_HTTPD__BINDINGS__0__ADDRESS="127.0.0.1",
               SFTPGO_HTTPD__BINDINGS__0__ENABLE_WEB_ADMIN="0", SFTPGO_HTTPD__BINDINGS__0__ENABLE_WEB_CLIENT="0")
    proc = subprocess.Popen([SFTPGO, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", api), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("sftpgo did not start")
    saved = (sg.API_URL, sg.ADMIN_USER, sg.DATA_BASE, os.environ.get("SFTPGO_ADMIN_PASSWORD"))
    saved += (sg.DATA_UID, sg.DATA_GID)
    sg.API_URL, sg.ADMIN_USER, sg.DATA_BASE = f"http://127.0.0.1:{api}", "cryptstorage", str(data)
    sg.DATA_UID, sg.DATA_GID = os.getuid(), os.getgid()
    os.environ["SFTPGO_ADMIN_PASSWORD"] = "pw-for-tests-123456"
    sg._token.update(value=None, expires=0.0)
    yield types_ns(api=api, sftp=sftp, data=data)
    proc.terminate(); proc.wait(timeout=10)
    sg.API_URL, sg.ADMIN_USER, sg.DATA_BASE = saved[:3]
    sg.DATA_UID, sg.DATA_GID = saved[4:]
    if saved[3] is None:
        os.environ.pop("SFTPGO_ADMIN_PASSWORD", None)


def types_ns(**kw):
    import types
    return types.SimpleNamespace(**kw)


def test_provision_is_idempotent_and_account_name_matches(server):
    a = sg.provision("alice", KEY, 5 * 1024 ** 2)
    assert a == sg.account_name("alice") and sg.provision("alice", KEY, 5 * 1024 ** 2) == a
    user = sg._call("GET", f"/users/{a}")
    assert user["public_keys"] == [KEY] and user["quota_size"] == 5 * 1024 ** 2
    assert user["filters"]["denied_protocols"] == ["FTP", "DAV", "HTTP"]
    assert "password" in user["filters"]["denied_login_methods"]
    assert os.path.isdir(os.path.join(sg.DATA_BASE, a, "data"))


def test_zero_quota_gets_the_default_not_unlimited(server):
    a = sg.provision("zeroq", KEY, 0)
    assert sg._call("GET", f"/users/{a}")["quota_size"] == sg.DEFAULT_QUOTA


def test_set_key_replaces_and_provision_without_key_keeps_it(server):
    a = sg.provision("keyed", KEY, 1024 ** 3)
    sg.set_key("keyed", KEY2)
    assert sg._call("GET", f"/users/{a}")["public_keys"] == [KEY2]
    sg.provision("keyed", None, 2 * 1024 ** 3)           # a quota change must not drop the key
    user = sg._call("GET", f"/users/{a}")
    assert user["public_keys"] == [KEY2] and user["quota_size"] == 2 * 1024 ** 3


def test_set_key_for_unknown_user_fails(server):
    with pytest.raises(sg.ProvisionError):
        sg.set_key("nobodyhere", KEY)


def test_delete_removes_user_and_data_and_is_idempotent(server):
    a = sg.provision("goner", KEY, 1024 ** 3)
    (server.data / a / "data" / "x.bin").write_bytes(b"x" * 10)
    sg.delete("goner")
    assert sg._call("GET", f"/users/{a}", ok_missing=True) is None and not (server.data / a).exists()
    sg.delete("goner")                                    # again: no error
    assert sg.usage_bytes("goner") == 0


def test_real_login_quota_and_no_shell_or_forwarding(server, tmp_path):
    priv = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(priv)], check=True)
    pub = (tmp_path / "k.pub").read_text().strip()
    a = sg.provision("quota_user", pub, 1_000_000)
    opts = ["-i", str(priv), "-P", str(server.sftp), "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes"]
    small, big = tmp_path / "small", tmp_path / "big"
    small.write_bytes(b"s" * 400_000); big.write_bytes(b"b" * 900_000)
    batch = f"put {small} /data/s\nput {big} /data/b\n"
    r = subprocess.run(["sftp", "-q", *opts, "-b", "-", f"{a}@127.0.0.1"], input=batch, text=True, capture_output=True)
    assert (server.data / a / "data" / "s").stat().st_size == 400_000
    assert r.returncode != 0                              # the second file exceeds the 1 MB quota
    assert sg.usage_bytes("quota_user") <= 1_000_000
    ssh = ["ssh", "-q", "-i", str(priv), "-p", str(server.sftp), "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes"]
    assert subprocess.run([*ssh, f"{a}@127.0.0.1", "id"], capture_output=True, timeout=20).stdout == b""
    other = subprocess.run(["sftp", "-q", "-i", str(tmp_path / "nokey"), "-P", str(server.sftp), "-o", "BatchMode=yes",
                            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                            f"{a}@127.0.0.1"], input="ls\n", text=True, capture_output=True)
    assert other.returncode != 0                          # no key, no password login


def test_wrong_admin_password_is_a_provision_error(server, monkeypatch):
    monkeypatch.setenv("SFTPGO_ADMIN_PASSWORD", "wrong")
    sg._token.update(value=None, expires=0.0)
    with pytest.raises(sg.ProvisionError):
        sg.provision("alice", KEY)
    sg._token.update(value=None, expires=0.0)
