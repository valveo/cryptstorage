import os
import pytest

import socket_auth
from socket_auth import AuthError, sign_command, verify_command

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = bytes.fromhex("ab" * 32)
SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host"


def test_api_and_daemon_use_identical_auth_code():
    """The API ships its own copy; the two must never diverge again."""
    daemon_copy = open(os.path.join(ROOT, "cryptdaemon", "socket_auth.py"), "rb").read()
    api_copy = open(os.path.join(ROOT, "api", "socket_auth.py"), "rb").read()
    assert daemon_copy == api_copy


def test_sign_then_verify_roundtrip():
    cmd = sign_command({"action": "umount", "user_id": "alice"}, KEY)
    verify_command(cmd, KEY)


@pytest.mark.parametrize("field,value", [
    ("user_id", "mallory"),
    ("action", "delete_user"),
    ("ssh_public_key", SSH.replace("OMqq", "XXXX")),
    ("master_key", "00" * 32),
    ("quota_bytes", 1),
])
def test_every_field_is_covered_by_the_mac(field, value):
    cmd = sign_command({"action": "mount", "user_id": "alice", "master_key": "11" * 32,
                        "ssh_public_key": SSH, "quota_bytes": 5}, KEY)
    cmd[field] = value
    with pytest.raises(AuthError):
        verify_command(cmd, KEY)


def test_wrong_key_rejected():
    cmd = sign_command({"action": "umount", "user_id": "alice"}, KEY)
    with pytest.raises(AuthError):
        verify_command(cmd, bytes.fromhex("cd" * 32))


def test_replay_outside_window_rejected(monkeypatch):
    cmd = sign_command({"action": "umount", "user_id": "alice"}, KEY)
    monkeypatch.setattr(socket_auth.time, "time", lambda: cmd["ts"] + 3600)
    with pytest.raises(AuthError):
        verify_command(cmd, KEY)


@pytest.mark.parametrize("bad", [
    {"auth": 123, "ts": 1}, {"auth": "x", "ts": "now"}, {"auth": "é", "ts": 1},
    {"auth": None, "ts": None}, {"auth": "x", "ts": True}, [], "text", None,
])
def test_malformed_auth_fields_raise_only_autherror(bad):
    # TypeError here used to escape and take the whole daemon down
    with pytest.raises(AuthError):
        verify_command(bad, KEY)
