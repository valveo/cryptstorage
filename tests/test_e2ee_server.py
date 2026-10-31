"""The server never sees a master key, and only manages ciphertext access."""
import hashlib

import pytest

import config
import database
import main
import models
import pending
import test_api_security as base
from test_api_security import PASSWORD, bearer, login, make_user

client = base.client      # reuse the fixture


@pytest.fixture
def e2(client, monkeypatch):
    calls = []
    provision = lambda user, key=None, quota=None: calls.append(("provision", user, key)) or "sdabc123abc123"  # noqa: E731
    monkeypatch.setattr(main, "daemon_e2ee_provision", provision)
    monkeypatch.setattr(pending, "daemon_e2ee_provision", provision)
    monkeypatch.setattr(pending, "daemon_e2ee_delete", lambda user: calls.append(("delete", user)))
    monkeypatch.setattr(main, "daemon_e2ee_usage",
                        lambda user, quota: {"used_bytes": 5, "quota_bytes": quota, "free_bytes": quota - 5, "percent": 0.0})
    client.calls = calls
    return client


def test_register_has_no_master_key_or_recovery_code(e2):
    r = e2.post("/auth/register", json={"username": "erin", "email": "erin@example.com", "password": "ab" * 32})
    assert r.status_code == 201 and "recovery_code" not in r.json()
    with database.SessionLocal() as db:
        u = db.query(models.User).filter_by(username="erin").one()
        assert u.recovery_encrypted_master_key is None


def test_login_issues_no_mount_token(e2):
    make_user(e2, "frank")
    r = login(e2, "frank")
    assert r.status_code == 200 and "mount_token" not in r.json()


def test_legacy_endpoints_are_gone(e2):
    make_user(e2, "gina")
    h = bearer(e2, "gina")
    assert e2.post("/storage/mount", json={"mount_token": "x"}, headers=h).status_code in (404, 405)
    assert e2.post("/storage/umount", headers=h).status_code in (404, 405)
    assert e2.get("/storage/status", headers=h).status_code in (404, 405)
    assert e2.post("/users/me/recovery-code", json={"password": PASSWORD}, headers=h).status_code in (404, 405)
    assert e2.post("/auth/recover", json={"username": "gina", "recovery_code": "x", "new_password": PASSWORD}).status_code in (404, 405)


def test_storage_endpoint_provisions_and_reports(e2):
    make_user(e2, "hank", ssh=base.SSH)
    r = e2.get("/storage/e2ee", headers=bearer(e2, "hank"))
    assert r.status_code == 200
    body = r.json()
    assert body["ssh_user"] == "sdabc123abc123" and body["used_bytes"] == 5 and body["ssh_port"] > 0
    assert e2.calls[-1][:2] == ("provision", "hank")


def test_storage_endpoint_lists_the_sftp_host_keys(e2, tmp_path, monkeypatch):
    good = tmp_path / "id_ed25519.pub"
    good.write_text("ssh-ed25519 " + base.SSH.split()[1] + " root@host\n")
    bad = tmp_path / "broken.pub"
    bad.write_text("-----BEGIN PRIVATE KEY-----\n")
    monkeypatch.setattr(main, "SFTP_HOST_KEY_FILES", [str(good), str(bad), str(tmp_path / "missing.pub")])
    make_user(e2, "hope", ssh=base.SSH)
    r = e2.get("/storage/e2ee", headers=bearer(e2, "hope"))
    assert r.status_code == 200
    # only the usable key, without its comment; unusable files are skipped, not fatal
    assert r.json()["ssh_host_keys"] == ["ssh-ed25519 " + base.SSH.split()[1]]


def test_ssh_key_change_reaches_the_sftp_server(e2):
    make_user(e2, "iris")
    r = e2.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": base.SSH}, headers=bearer(e2, "iris"))
    assert r.status_code == 200, r.text
    assert any(c[0] == "provision" and c[2] == base.SSH for c in e2.calls)


def test_password_change_needs_no_master_key(e2):
    make_user(e2, "jack")
    r = e2.post("/users/me/password", json={"current_password": PASSWORD, "new_password": "cd" * 32}, headers=bearer(e2, "jack"))
    assert r.status_code == 200, r.text
    assert login(e2, "jack", "cd" * 32).status_code == 200


def test_delete_removes_sftp_account(e2):
    make_user(e2, "kate")
    r = e2.request("DELETE", "/storage", json={"password": PASSWORD}, headers=bearer(e2, "kate"))
    assert r.status_code == 200 and ("delete", "kate") in e2.calls


def test_server_info_and_escrow_policy(e2, monkeypatch):
    monkeypatch.delenv("TOTP_ENCRYPTION_KEY", raising=False)
    assert e2.get("/server-info").json() == {"storage_mode": "e2ee", "version": main.version.VERSION,
                                             "recovery_policy": "user",
                                             "escrow_public_key": None, "escrow_key_fingerprint": None,
                                             "account_lifetime_hours": None, "server_id": None}
    make_user(e2, "liam")
    h = bearer(e2, "liam")
    blob = "ab" * 92
    assert e2.put("/users/me/escrow", json={"blob": blob}, headers=h).status_code == 409   # policy "user"
    monkeypatch.setenv("RECOVERY_POLICY", "both")
    monkeypatch.setenv("ESCROW_PUBLIC_KEY", "cd" * 32)
    info = e2.get("/server-info").json()
    assert info["escrow_public_key"] == "cd" * 32 and info["recovery_policy"] == "both"
    assert e2.put("/users/me/escrow", json={"blob": blob}, headers=h).status_code == 200
    fp = hashlib.sha256(bytes.fromhex("cd" * 32)).hexdigest()
    assert info["escrow_key_fingerprint"] == fp
    state = e2.get("/users/me/escrow", headers=h).json()
    assert state["has_escrow"] is True and state["sealed_key_fingerprint"] == fp
    assert state["recovery_policy"] == "both" and state["escrow_key_fingerprint"] == fp
    assert e2.put("/users/me/escrow", json={"blob": "zz" * 92}, headers=h).status_code == 422


def test_config_rejects_escrow_without_key(monkeypatch):
    monkeypatch.setenv("RECOVERY_POLICY", "escrow")
    monkeypatch.delenv("ESCROW_PUBLIC_KEY", raising=False)
    with pytest.raises(config.ConfigError):
        config.validate()


def test_recovery_with_proof_resets_login_key(e2, monkeypatch):
    monkeypatch.setattr(main, "_recover_by_ip_user", main.FailureTracker(5, 900))
    monkeypatch.setattr(main, "_recover_by_user", main.FailureTracker(10, 3600))
    make_user(e2, "mona")
    h = bearer(e2, "mona")
    proof = "9f" * 32
    assert e2.put("/users/me/recovery-verifier", json={"proof": proof}, headers=h).status_code == 200
    bad = e2.post("/auth/recover-e2ee", json={"username": "mona", "proof": "00" * 32, "new_password": "ef" * 32})
    assert bad.status_code == 401
    nobody = e2.post("/auth/recover-e2ee", json={"username": "nosuchuser", "proof": proof, "new_password": "ef" * 32})
    assert nobody.status_code == 401 and nobody.json() == bad.json()
    ok = e2.post("/auth/recover-e2ee", json={"username": "mona", "proof": proof, "new_password": "ef" * 32})
    assert ok.status_code == 200, ok.text
    assert login(e2, "mona").status_code == 401                      # old key is dead
    assert login(e2, "mona", "ef" * 32).status_code == 200
    assert e2.get("/users/me", headers=h).status_code == 401         # old sessions ended


def test_recovery_throttled(e2, monkeypatch):
    monkeypatch.setattr(main, "_recover_by_ip_user", main.FailureTracker(5, 900))
    monkeypatch.setattr(main, "_recover_by_user", main.FailureTracker(10, 3600))
    make_user(e2, "nils")
    body = {"username": "nils", "proof": "00" * 32, "new_password": "ef" * 32}
    codes = [e2.post("/auth/recover-e2ee", json=body).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
