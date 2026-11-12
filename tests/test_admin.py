"""
The administrator's command (api/admin.py): accounts, quotas, the second factor and invitations.
The daemon runs for real over its socket (conftest `calls`), only SFTPGo itself is replaced.
"""
import database
import models
import sftpgo_client
import totp

import test_api_security as base
import admin

client = base.client


def run(*argv):
    return admin.run(list(argv))


def _user(name):
    with database.SessionLocal() as db:
        return db.query(models.User).filter_by(username=name).one_or_none()


def _with_storage(name):
    with database.SessionLocal() as db:
        db.query(models.User).filter_by(username=name).one().storage_created = True
        db.commit()


def _events(user_id):
    with database.SessionLocal() as db:
        return [e.event_type for e in db.query(models.SecurityEvent).filter_by(user_id=user_id)]


def test_unknown_user_and_list(client, calls):
    base.make_user(client, "adm_list")
    assert run("show", "adm_nobody") == (1, "No account named 'adm_nobody'.")
    code, text = run("users")
    assert code == 0 and "adm_list" in text and "adm_list@example.com" in text
    assert "adm_list" not in run("users", "--state", "locked")[1]


def test_lock_ends_sessions_and_the_storage_account_and_unlock_undoes_it(client, calls, monkeypatch):
    locked = []
    monkeypatch.setattr(sftpgo_client, "set_enabled", lambda uid, on: locked.append((uid, on)))
    base.make_user(client, "adm_lock")
    _with_storage("adm_lock")
    tokens = base.login(client, "adm_lock").json()
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.get("/users/me", headers=auth).status_code == 200

    assert run("lock", "adm_lock")[0] == 0
    assert locked == [("adm_lock", False)]
    assert client.get("/users/me", headers=auth).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert base.login(client, "adm_lock").status_code == 401
    assert "locked" in run("show", "adm_lock")[1]
    assert "adm_lock" in run("users", "--state", "locked")[1]

    assert run("unlock", "adm_lock")[0] == 0
    assert locked[-1] == ("adm_lock", True)
    assert base.login(client, "adm_lock").status_code == 200
    assert client.get("/users/me", headers=auth).status_code == 401      # the old session stays ended
    assert {"admin_lock", "admin_unlock"} <= set(_events(_user("adm_lock").id))


def test_lock_without_storage_does_not_need_the_daemon(client):
    base.make_user(client, "adm_nostore")
    assert run("lock", "adm_nostore")[0] == 0       # no `calls` fixture: there is no daemon to reach
    assert _user("adm_nostore").is_active is False


def test_quota(client, calls, monkeypatch):
    seen = []
    monkeypatch.setattr(sftpgo_client, "provision", lambda uid, key=None, quota=None: (seen.append((uid, key, quota)), "sdx")[1])
    base.make_user(client, "adm_quota")
    assert run("quota", "adm_quota", "lots")[0] == 1
    assert run("quota", "adm_quota", "500M")[0] == 0 and seen == []       # no storage yet: the database only
    assert _user("adm_quota").quota_bytes == 500 * 1024 ** 2
    _with_storage("adm_quota")
    assert run("quota", "adm_quota", "20G")[0] == 0
    assert seen == [("adm_quota", None, 20 * 1024 ** 3)]                   # no key: the registered one is kept
    assert _user("adm_quota").quota_bytes == 20 * 1024 ** 3


def test_reset_2fa_removes_app_and_passkeys_and_tells_the_user(client, monkeypatch):
    told = []
    monkeypatch.setattr(admin, "send_security_notice_email", lambda email, user, what, action="": told.append((email, what)))
    base.make_user(client, "adm_2fa")
    with database.SessionLocal() as db:
        u = db.query(models.User).filter_by(username="adm_2fa").one()
        u.totp_enabled, u.totp_secret_enc = True, totp.encrypt_secret(totp.generate_secret(), u.id)
        db.add(models.WebAuthnCredential(user_id=u.id, credential_id="abc", credential_hash="h" * 64,
                                         public_key="pk", name="key"))
        db.commit()
        uid = u.id
    assert base.login(client, "adm_2fa").json()["detail"] == "TOTP_REQUIRED"
    code, text = run("reset-2fa", "adm_2fa")
    assert code == 0 and "1 passkey" in text and "told by e-mail" in text
    assert told and told[0][0] == "adm_2fa@example.com" and "administrator" in told[0][1]
    assert base.login(client, "adm_2fa").status_code == 200
    with database.SessionLocal() as db:
        assert db.query(models.WebAuthnCredential).filter_by(user_id=uid).count() == 0
    assert "admin_reset_2fa" in _events(uid)


def test_verify_and_delete(client, calls):
    r = client.post("/auth/register", json={"username": "adm_del", "email": "adm_del@example.com", "password": base.PASSWORD})
    assert r.status_code == 201
    assert base.login(client, "adm_del").status_code == 403
    assert run("verify", "adm_del")[0] == 0
    assert base.login(client, "adm_del").status_code == 200

    assert run("delete", "adm_del")[0] == 1 and _user("adm_del") is not None      # needs --yes
    assert run("delete", "adm_del", "--yes")[0] == 0
    assert _user("adm_del") is None
    assert ("delete", "adm_del") in calls


def test_invitations(client, monkeypatch):
    monkeypatch.setenv("REGISTRATION", "invite")
    code, text = run("invite", "create", "--email", "new@example.org", "--note", "for Bob", "--days", "2")
    assert code == 0
    invite_code = text.splitlines()[0].split(": ", 1)[1]
    listing = run("invite", "list")[1]
    assert "new@example.org" in listing and "for Bob" in listing and invite_code not in listing
    r = client.post("/auth/register", json={"username": "adm_inv", "email": "new@example.org",
                                            "password": base.PASSWORD, "invite": invite_code})
    assert r.status_code == 201
    assert "used" in run("invite", "list")[1]

    text = run("invite", "create")[1]
    with database.SessionLocal() as db:
        open_id = db.query(models.Invite).filter(models.Invite.used_at.is_(None)).order_by(
            models.Invite.created_at.desc()).first().id
    assert run("invite", "revoke", open_id)[0] == 0
    assert run("invite", "revoke", open_id)[0] == 1
    r = client.post("/auth/register", json={"username": "adm_inv2", "email": "x@example.org",
                                            "password": base.PASSWORD, "invite": text.splitlines()[0].split(": ", 1)[1]})
    assert r.json()["detail"] == "INVITE_INVALID"
