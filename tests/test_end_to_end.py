"""
Smoke test of the whole chain on one machine:

  API (FastAPI TestClient, SQLite)  --real Unix socket-->  daemon.handle_connection
                                                           (real auth, validator, handler)

Only the parts that need root are replaced: the OS account and chroot of the
SFTP provisioner. Register -> verify -> login -> storage -> usage -> delete.
"""
import json
import socket
import time


from socket_auth import sign_command

KEY = bytes.fromhex("ab" * 32)
SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host"
PASSWORD = "correct horse battery staple"


def auth(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_full_lifecycle(client, calls, monkeypatch):
    """Register -> verify -> login -> storage -> usage -> delete, API and daemon over the real socket."""
    import handler
    seen = []
    monkeypatch.setattr(handler.sftpgo_client, "provision",
                        lambda uid, key, quota=None: (seen.append(("provision", uid, key)), "sdalice0000000")[1])
    monkeypatch.setattr(handler.sftpgo_client, "usage_bytes", lambda uid: 1234)
    monkeypatch.setattr(handler.sftpgo_client, "delete", lambda uid: seen.append(("delete", uid)))

    r = client.post("/auth/register", json={
        "username": "alice", "email": "alice@example.com",
        "password": PASSWORD, "ssh_public_key": SSH})
    assert r.status_code == 201, r.text
    assert "recovery_code" not in r.json()          # the server holds no key that could make one

    # Not usable before the e-mail is verified
    assert client.post("/auth/login", json={"username": "alice", "password": PASSWORD}).status_code != 200

    r = client.post("/auth/verify-email", json={"token": client.sent["token"]})
    assert r.status_code == 200, r.text
    assert seen == []                               # nothing on the host yet: the account comes with /storage/e2ee

    r = client.post("/auth/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 200, r.text
    tokens = r.json()
    assert set(tokens) == {"access_token", "token_type", "refresh_token"}

    r = client.get("/storage/e2ee", headers=auth(tokens["access_token"]))
    assert r.status_code == 200, r.text
    assert r.json()["ssh_user"] == "sdalice0000000" and r.json()["used_bytes"] == 1234
    assert ("provision", "alice", SSH) in seen      # the registered SSH key reaches the SFTP account

    usage = client.get("/storage/usage", headers=auth(tokens["access_token"]))
    assert usage.status_code == 200 and usage.json()["used_bytes"] == 1234

    r = client.request("DELETE", "/storage", json={"password": PASSWORD},
                       headers=auth(tokens["access_token"]))
    assert r.status_code == 200, r.text
    assert ("delete", "alice") in seen

    for gone in ("/storage/mount", "/storage/umount", "/storage/status", "/auth/recover", "/users/me/recovery-code"):
        assert client.post(gone, json={}).status_code in (404, 405)


def _raw(path, payload: bytes, half_close=False) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(path)
        s.sendall(payload)
        if half_close:
            s.shutdown(socket.SHUT_WR)
        data = b""
        while b"\n" not in data:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        return json.loads(data)


def test_daemon_survives_hostile_input_and_keeps_serving(calls):
    path = calls.path

    def good() -> bytes:   # a fresh nonce each time: a repeated command is a replay
        return json.dumps(sign_command({"action": "e2ee_delete", "user_id": "alice"}, KEY)).encode() + b"\n"

    for bad in (b'{"auth": 123, "ts": "x"}\n', b'{"auth": "\xc3\xa9", "ts": 1}\n',
                b"not json\n", b"[]\n", b'{"action": "e2ee_delete"}\n'):
        assert _raw(path, bad)["status"] == "error"

    assert _raw(path, good())["status"] == "ok"                      # still alive
    assert _raw(path, good().rstrip(b"\n"), half_close=True)["status"] == "ok"   # EOF-terminated also works

    replayed = good()
    assert _raw(path, replayed)["status"] == "ok"
    assert _raw(path, replayed)["message"] == "Unauthorized."       # same nonce twice


def test_silent_client_cannot_block_the_daemon(calls):
    path = calls.path
    good = json.dumps(sign_command({"action": "e2ee_delete", "user_id": "alice"}, KEY)).encode() + b"\n"
    hog = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    hog.connect(path)                      # connects and says nothing
    try:
        t0 = time.time()
        assert _raw(path, good)["status"] == "ok"
        assert time.time() - t0 < 3        # served after the 0.5 s receive timeout
    finally:
        hog.close()
