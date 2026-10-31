import os
import socket
import threading

import pytest

import daemon
import handler
import schemas
import validator
from socket_auth import AuthError, ReplayCache, sign_command, verify_command

KEY = bytes.fromhex("ab" * 32)
SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host"


# ---------- replay protection ----------

def test_replayed_command_is_rejected():
    cmd = sign_command({"action": "e2ee_delete", "user_id": "alice"}, KEY)
    cache = ReplayCache()
    verify_command(cmd, KEY, cache)
    with pytest.raises(AuthError, match="Replay"):
        verify_command(cmd, KEY, cache)


def test_nonce_is_required_and_covered_by_the_mac():
    cmd = sign_command({"action": "e2ee_delete", "user_id": "alice"}, KEY)
    no_nonce = {k: v for k, v in cmd.items() if k != "nonce"}
    with pytest.raises(AuthError):
        verify_command(no_nonce, KEY, ReplayCache())
    other = dict(cmd, nonce="0" * 32)
    with pytest.raises(AuthError, match="signature"):
        verify_command(other, KEY, ReplayCache())


def test_forged_commands_cannot_fill_the_cache():
    cache = ReplayCache()
    forged = sign_command({"action": "e2ee_delete", "user_id": "alice"}, bytes.fromhex("cd" * 32))
    with pytest.raises(AuthError):
        verify_command(forged, KEY, cache)
    assert len(cache._seen) == 0


def test_nonces_expire_and_cache_is_bounded():
    now = [1000.0]
    cache = ReplayCache(ttl=10, max_entries=2, clock=lambda: now[0])
    cache.check_and_store("a" * 32)
    cache.check_and_store("b" * 32)
    with pytest.raises(AuthError, match="Too many"):
        cache.check_and_store("c" * 32)
    now[0] += 11                                  # old entries expire, space is freed
    cache.check_and_store("c" * 32)


def _roundtrip(payload: dict, *, replay_cache=None, cmd=None):
    """Run daemon.handle_connection over a socketpair; return the decoded response."""
    import json
    a, b = socket.socketpair()
    a.settimeout(5)
    cmd = cmd or sign_command(payload, KEY)
    a.sendall(json.dumps(cmd).encode() + b"\n")
    t = threading.Thread(target=daemon.handle_connection, args=(b, KEY, replay_cache), daemon=True)
    t.start()
    data = b""
    while b"\n" not in data:
        chunk = a.recv(1024)
        if not chunk:
            break
        data += chunk
    t.join(timeout=5)
    a.close()
    return json.loads(data)


def test_daemon_rejects_a_replayed_command(monkeypatch):
    monkeypatch.setattr(daemon, "handle_command", lambda c: {"status": "ok"})
    cache = ReplayCache()
    cmd = sign_command({"action": "e2ee_delete", "user_id": "alice"}, KEY)
    assert _roundtrip(None, replay_cache=cache, cmd=cmd)["status"] == "ok"
    assert _roundtrip(None, replay_cache=cache, cmd=cmd)["message"] == "Unauthorized."


# ---------- peer credentials ----------

def test_peer_uid_allowlist(monkeypatch):
    monkeypatch.setattr(daemon, "handle_command", lambda c: {"status": "ok"})
    me = os.getuid()
    monkeypatch.setattr(daemon, "ALLOWED_UIDS", {me + 12345})
    assert _roundtrip({"action": "e2ee_delete", "user_id": "alice"})["message"] == "Unauthorized."
    monkeypatch.setattr(daemon, "ALLOWED_UIDS", {me})
    assert _roundtrip({"action": "e2ee_delete", "user_id": "alice"})["status"] == "ok"


# ---------- concurrency ----------

def test_different_users_are_handled_in_parallel(monkeypatch):
    barrier = threading.Barrier(2, timeout=5)   # both deletes must be running at the same time

    def slow_delete(uid):
        barrier.wait()

    monkeypatch.setattr(handler.sftpgo_client, "delete", slow_delete)
    results = {}

    def run(user):
        results[user] = handler.handle_command({"action": "e2ee_delete", "user_id": user})

    threads = [threading.Thread(target=run, args=(u,)) for u in ("alice", "bobby")]
    [t.start() for t in threads]
    [t.join(timeout=10) for t in threads]
    assert results["alice"]["status"] == "ok" and results["bobby"]["status"] == "ok"


def test_commands_for_one_user_never_overlap(monkeypatch):
    state = {"active": 0, "max": 0}
    guard = threading.Lock()

    def slow(uid, *a):
        with guard:
            state["active"] += 1
            state["max"] = max(state["max"], state["active"])
        threading.Event().wait(0.1)
        with guard:
            state["active"] -= 1

    monkeypatch.setattr(handler.sftpgo_client, "provision", lambda uid, key=None, quota=None: (slow(uid), "sdcarol")[1])
    monkeypatch.setattr(handler.sftpgo_client, "delete", slow)

    threads = [
        threading.Thread(target=handler.handle_command, args=({"action": "e2ee_provision", "user_id": "carol"},)),
        threading.Thread(target=handler.handle_command, args=({"action": "e2ee_delete", "user_id": "carol"},)),
    ]
    [t.start() for t in threads]
    [t.join(timeout=10) for t in threads]
    assert state["max"] == 1


# ---------- shared rules ----------

@pytest.mark.parametrize("name", ["root", "ROOT", "sshd", "nobody", "cryptuser"])
def test_reserved_names_are_rejected_by_the_daemon(name):
    with pytest.raises(validator.ValidationError):
        validator.validate_command({"action": "e2ee_delete", "user_id": name})


def test_api_and_daemon_agree_on_reserved_names():
    assert schemas.RESERVED_USERNAMES == validator.RESERVED_USER_IDS
