"""
Test setup: puts api/ and cryptdaemon/ on sys.path and configures the API's
environment BEFORE any API module is imported.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "cryptdaemon"))
sys.path.insert(1, os.path.join(ROOT, "api"))

_tmp = tempfile.mkdtemp(prefix="cryptstorage-tests-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp}/test.db")
os.environ.setdefault("JWT_SECRET_KEY", "test-" + "k" * 40)
os.environ.setdefault("REFRESH_TOKEN_HMAC_KEY", "cd" * 32)   # must be hex
os.environ.setdefault("TOTP_ENCRYPTION_KEY", "ef" * 32)           # must be hex
os.environ.setdefault("DAEMON_AUTH_KEY", "ab" * 32)
os.environ.setdefault("REQUIRE_EMAIL_VERIFICATION", "true")
# Most tests exercise one thing at a time: the factor policy and the delay have their own tests
os.environ.setdefault("REQUIRED_FACTORS", "password")
os.environ.setdefault("CHANGE_DELAY_HOURS", "0")
os.environ.setdefault("CHANGE_WORKER_INTERVAL", "0")


# ---------------------------------------------------------------------------
# Shared fixtures: the API talking to the real daemon code over a real Unix socket,
# with only the root-only parts (the sftpgo_client's system accounts) replaced.
# ---------------------------------------------------------------------------
import socket
import threading

import pytest
from fastapi.testclient import TestClient

KEY = bytes.fromhex("ab" * 32)
SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host"
PASSWORD = "correct horse battery staple"


import daemon          # noqa: E402  (imported after the environment above is configured)
import sftpgo_client  # noqa: E402
import socket_client   # noqa: E402


class CallLog(list):
    """Recorded daemon-side operations; .path is the daemon's socket."""
    path = None


@pytest.fixture
def calls(tmp_path, monkeypatch):
    """Daemon running in a thread on a temp socket, with root-only parts mocked."""
    log = CallLog()
    monkeypatch.setattr(sftpgo_client, "provision", lambda uid, key=None, quota=None: (log.append(("provision", uid, key)), "sdtest")[1])
    monkeypatch.setattr(sftpgo_client, "set_key", lambda uid, key: log.append(("set_key", uid, key)))
    monkeypatch.setattr(sftpgo_client, "delete", lambda uid: log.append(("delete", uid)))
    monkeypatch.setattr(sftpgo_client, "usage_bytes", lambda uid: 1234)
    monkeypatch.setattr(daemon, "CONNECTION_TIMEOUT", 0.5)

    path = str(tmp_path / "d.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(5)
    srv.settimeout(0.1)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            daemon.handle_connection(conn, KEY)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    monkeypatch.setattr(socket_client, "SOCKET_PATH", path)
    monkeypatch.setattr(socket_client, "_AUTH_KEY", None)
    log.path = path
    yield log
    stop.set()
    srv.close()
    t.join(timeout=2)


@pytest.fixture
def client(monkeypatch):
    import main
    monkeypatch.setattr(main.limiter, "enabled", False)   # the register limit is 5/min
    sent = {}
    monkeypatch.setattr(main, "send_verification_email", lambda email, user, token: sent.update(token=token))
    with TestClient(main.app) as c:
        c.sent = sent
        yield c


