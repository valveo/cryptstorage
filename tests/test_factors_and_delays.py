"""
A password alone must not give access: the server can require a second factor, sensitive
actions ask for it again, and a new SSH key or an account deletion waits and can be cancelled.
"""
from datetime import datetime, timedelta

import pytest

import config
import database
import main
import models
import pending
import totp
from throttle import FailureTracker

import test_api_security as base
from test_api_security import PASSWORD, bearer, make_user

client = base.client      # reuse the fixture

NEW_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKkyGJlmV6LVYPJdvSO8ClDc8yXLrCyZBtakMaNUh+2z"


@pytest.fixture
def c(client, monkeypatch):
    """The API with a 24-hour delay, recording the daemon calls and the notices with their links."""
    monkeypatch.setattr(main, "_totp_failures", FailureTracker(5, 900))
    monkeypatch.setenv("CHANGE_DELAY_HOURS", "24")
    calls, mails = [], []
    provision = lambda user, key=None, quota=None: calls.append(("provision", user, key)) or "sdabc"  # noqa: E731
    monkeypatch.setattr(main, "daemon_e2ee_provision", provision)
    monkeypatch.setattr(pending, "daemon_e2ee_provision", provision)
    monkeypatch.setattr(pending, "daemon_e2ee_delete", lambda user: calls.append(("delete", user)))
    monkeypatch.setattr(main, "daemon_e2ee_usage", lambda user, quota: {"used_bytes": 0})
    monkeypatch.setattr(pending, "send_security_notice_email",
                        lambda email, user, what, action="": mails.append((user, what, action)))
    client.calls, client.mails = calls, mails
    return client


def _user(name):
    with database.SessionLocal() as db:
        return db.query(models.User).filter_by(username=name).one()


def _code(name):
    """A fresh code for `name` (forgets the last used step, so tests need not wait 30 s)."""
    with database.SessionLocal() as db:
        u = db.query(models.User).filter_by(username=name).one()
        u.totp_last_step = None
        db.commit()
        return totp.code_for_step(totp.decrypt_secret(u.totp_secret_enc, u.id), totp.current_step())


def _enrol(c, name, h=None):
    h = h or bearer(c, name)
    assert c.post("/users/me/totp/setup", json={"password": PASSWORD}, headers=h).status_code == 200
    r = c.post("/users/me/totp/enable", json={"code": _code(name), "email_code": c.enrol_codes[-1]}, headers=h)
    assert r.status_code == 200, r.text


def _login_with_code(c, name):
    r = c.post("/auth/login", json={"username": name, "password": PASSWORD, "totp_code": _code(name)})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make_due(change_id):
    with database.SessionLocal() as db:
        db.query(models.PendingChange).filter_by(id=change_id).one().due_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()


def _cancel_token(mail):
    return mail[2].split("token=", 1)[1].strip()


# ---------- REQUIRED_FACTORS ----------

def test_password_alone_reaches_only_the_second_factor_setup(c, monkeypatch):
    monkeypatch.setenv("REQUIRED_FACTORS", "password,totp")
    make_user(c, "fa_pw_only")
    h = bearer(c, "fa_pw_only")
    for method, path, body in (("GET", "/storage/e2ee", None), ("GET", "/storage/usage", None),
                               ("PUT", "/users/me/ssh-key", {"password": PASSWORD, "ssh_public_key": NEW_KEY}),
                               ("DELETE", "/storage", {"password": PASSWORD}),
                               ("PUT", "/users/me/recovery-verifier", {"proof": "9f" * 32})):
        r = c.request(method, path, json=body, headers=h)
        assert r.status_code == 403 and r.json()["detail"] == "SECOND_FACTOR_SETUP_REQUIRED", (path, r.text)
    assert c.get("/users/me", headers=h).status_code == 200
    assert c.get("/users/me/pending-changes", headers=h).status_code == 200
    assert not c.calls

    _enrol(c, "fa_pw_only", h)
    assert c.get("/storage/e2ee", headers=h).status_code == 200        # the same session, now with the factor
    r = c.post("/users/me/totp/disable", json={"password": PASSWORD, "code": _code("fa_pw_only")}, headers=h)
    assert r.status_code == 409 and _user("fa_pw_only").totp_enabled


def test_enrolment_needs_the_code_sent_by_email(c):
    make_user(c, "fa_enrol")
    h = bearer(c, "fa_enrol")
    assert c.post("/users/me/totp/setup", json={"password": PASSWORD}, headers=h).status_code == 200
    first = c.enrol_codes[-1]
    assert len(first) == 8 and first.isdigit()
    r = c.post("/users/me/totp/enable", json={"code": _code("fa_enrol"), "email_code": "12345678"}, headers=h)
    assert r.status_code == 401 and not _user("fa_enrol").totp_enabled
    # a new setup makes the old e-mail code useless
    assert c.post("/users/me/totp/setup", json={"password": PASSWORD}, headers=h).status_code == 200
    assert c.enrol_codes[-1] != first
    r = c.post("/users/me/totp/enable", json={"code": _code("fa_enrol"), "email_code": first}, headers=h)
    assert r.status_code == 401
    r = c.post("/users/me/totp/enable", json={"code": _code("fa_enrol"), "email_code": c.enrol_codes[-1]}, headers=h)
    assert r.status_code == 200 and _user("fa_enrol").totp_enabled


def test_enrolment_fails_closed_without_email(c, monkeypatch):
    def broken(*a):
        raise RuntimeError("smtp down")
    monkeypatch.setattr(main, "send_enrolment_code_email", broken)
    make_user(c, "fa_nomail")
    r = c.post("/users/me/totp/setup", json={"password": PASSWORD}, headers=bearer(c, "fa_nomail"))
    assert r.status_code == 503 and _user("fa_nomail").totp_secret_enc is None


@pytest.mark.parametrize("value", ["totp", "password,sms", "password,totp,"])
def test_factor_setting_is_checked_at_startup(monkeypatch, value):
    monkeypatch.setenv("REQUIRED_FACTORS", value)
    if value == "password,totp,":
        config.validate()                     # a trailing comma is harmless
        return
    with pytest.raises(config.ConfigError):
        config.validate()


def test_totp_policy_needs_the_encryption_key(monkeypatch):
    monkeypatch.setenv("REQUIRED_FACTORS", "password,totp")
    monkeypatch.delenv("TOTP_ENCRYPTION_KEY")
    with pytest.raises(config.ConfigError):
        config.validate()


# ---------- the second factor again for sensitive actions ----------

def test_sensitive_actions_ask_for_the_second_factor_again(c, monkeypatch):
    make_user(c, "fa_stepup")
    _enrol(c, "fa_stepup")
    h = _login_with_code(c, "fa_stepup")
    body = {"password": PASSWORD, "ssh_public_key": NEW_KEY}
    # right after a login with a code, no second code is needed
    assert c.put("/users/me/ssh-key", json=body, headers=h).status_code == 200

    monkeypatch.setattr(main, "STEP_UP_WINDOW", -1)       # that login is now too old
    for method, path, b in (("PUT", "/users/me/ssh-key", body), ("DELETE", "/storage", {"password": PASSWORD}),
                            ("POST", "/users/me/password", {"current_password": PASSWORD, "new_password": "cd" * 32})):
        r = c.request(method, path, json=b, headers=h)
        assert r.status_code == 401 and r.json()["detail"] == "TOTP_REQUIRED", path
        r = c.request(method, path, json={**b, "totp_code": "000000"}, headers=h)
        assert r.status_code == 401 and r.json()["detail"] == "Invalid verification code.", path
    r = c.put("/users/me/ssh-key", json={**body, "totp_code": _code("fa_stepup")}, headers=h)
    assert r.status_code == 200 and r.json()["pending"]


def test_a_refreshed_session_has_no_recent_second_factor(c):
    make_user(c, "fa_refresh")
    _enrol(c, "fa_refresh")
    r = c.post("/auth/login", json={"username": "fa_refresh", "password": PASSWORD, "totp_code": _code("fa_refresh")})
    fresh = c.post("/auth/refresh", json={"refresh_token": r.json()["refresh_token"]}).json()["access_token"]
    r = c.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": NEW_KEY},
              headers={"Authorization": f"Bearer {fresh}"})
    assert r.status_code == 401 and r.json()["detail"] == "TOTP_REQUIRED"


# ---------- delayed SSH key replacement ----------

def test_new_ssh_key_waits_and_the_old_one_keeps_working(c):
    make_user(c, "fa_delay")
    old = _user("fa_delay").ssh_public_key
    h = bearer(c, "fa_delay")
    r = c.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": NEW_KEY}, headers=h)
    assert r.status_code == 200 and r.json()["pending"], r.text
    change_id = r.json()["change_id"]
    assert _user("fa_delay").ssh_public_key == old and not c.calls
    # the owner is told at once, with a cancel link
    (who, what, action), = c.mails
    assert who == "fa_delay" and "new SSH key" in what and "/cancel.php?token=" in action
    # asking again for the same key does not restart the wait or send more mail
    again = c.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": NEW_KEY}, headers=h)
    assert again.json()["change_id"] == change_id and len(c.mails) == 1

    assert c.get("/storage/e2ee", headers=h).status_code == 200
    assert c.calls[-1] == ("provision", "fa_delay", old)       # still the old key
    with database.SessionLocal() as db:
        assert pending.apply_due(db) == 0

    _make_due(change_id)
    assert c.get("/storage/e2ee", headers=h).status_code == 200    # connecting applies what is due
    assert ("provision", "fa_delay", NEW_KEY) in c.calls and _user("fa_delay").ssh_public_key == NEW_KEY
    assert c.get("/users/me/pending-changes", headers=h).json() == []
    assert "now active" in c.mails[-1][1]


def test_the_cancel_link_stops_the_change(c):
    make_user(c, "fa_cancel")
    old = _user("fa_cancel").ssh_public_key
    h = bearer(c, "fa_cancel")
    change_id = c.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": NEW_KEY},
                      headers=h).json()["change_id"]
    token = _cancel_token(c.mails[-1])
    assert c.post("/auth/cancel-change", json={"token": change_id + ".wrong"}).status_code == 404
    assert c.post("/auth/cancel-change", json={"token": token}).status_code == 200
    assert c.post("/auth/cancel-change", json={"token": token}).status_code == 404      # only once
    _make_due(change_id)
    with database.SessionLocal() as db:
        assert pending.apply_due(db) == 0
    assert _user("fa_cancel").ssh_public_key == old and not c.calls


def test_a_session_can_cancel_but_only_its_own_changes(c):
    make_user(c, "fa_own")
    make_user(c, "fa_other")
    h = bearer(c, "fa_own")
    change_id = c.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": NEW_KEY},
                      headers=h).json()["change_id"]
    listed = c.get("/users/me/pending-changes", headers=h).json()
    assert [(x["id"], x["kind"]) for x in listed] == [(change_id, "ssh_key")]
    assert c.delete(f"/users/me/pending-changes/{change_id}", headers=bearer(c, "fa_other")).status_code == 404
    assert c.delete(f"/users/me/pending-changes/{change_id}", headers=h).status_code == 200
    assert c.get("/users/me/pending-changes", headers=h).json() == []


def test_no_change_is_stored_when_the_owner_cannot_be_told(c, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("smtp down")
    monkeypatch.setattr(pending, "send_security_notice_email", broken)
    make_user(c, "fa_quiet")
    h = bearer(c, "fa_quiet")
    r = c.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": NEW_KEY}, headers=h)
    assert r.status_code == 503
    with database.SessionLocal() as db:
        assert db.query(models.PendingChange).filter_by(user_id=_user("fa_quiet").id).count() == 0


def test_the_first_key_of_a_new_account_needs_no_wait(c):
    make_user(c, "fa_first", ssh=None)
    r = c.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": NEW_KEY}, headers=bearer(c, "fa_first"))
    assert r.status_code == 200 and not r.json()["pending"]
    assert _user("fa_first").ssh_public_key == NEW_KEY and c.calls == [("provision", "fa_first", NEW_KEY)]


def test_a_failed_apply_is_retried(c, monkeypatch):
    make_user(c, "fa_retry")
    change_id = c.put("/users/me/ssh-key", json={"password": PASSWORD, "ssh_public_key": NEW_KEY},
                      headers=bearer(c, "fa_retry")).json()["change_id"]
    _make_due(change_id)

    def down(*a, **k):
        raise main.DaemonError("daemon down")
    monkeypatch.setattr(pending, "daemon_e2ee_provision", down)
    with database.SessionLocal() as db:
        assert pending.apply_due(db) == 0
    monkeypatch.setattr(pending, "daemon_e2ee_provision", lambda *a, **k: "sdabc")
    with database.SessionLocal() as db:
        assert pending.apply_due(db) == 1
    assert _user("fa_retry").ssh_public_key == NEW_KEY


# ---------- delayed deletion ----------

def test_account_deletion_waits_and_can_be_cancelled(c):
    make_user(c, "fa_del")
    h = bearer(c, "fa_del")
    r = c.request("DELETE", "/storage", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 200 and r.json()["pending"], r.text
    assert c.post("/auth/cancel-change", json={"token": _cancel_token(c.mails[-1])}).status_code == 200
    with database.SessionLocal() as db:
        pending.apply_due(db)
    assert _user("fa_del") and not c.calls

    change_id = c.request("DELETE", "/storage", json={"password": PASSWORD}, headers=h).json()["change_id"]
    _make_due(change_id)
    with database.SessionLocal() as db:
        assert pending.apply_due(db) == 1
        assert db.query(models.User).filter_by(username="fa_del").first() is None
    assert c.calls == [("delete", "fa_del")]


# ---------- recovery ----------

def test_recovery_code_does_not_replace_the_second_factor(c, monkeypatch):
    monkeypatch.setattr(main, "_recover_by_ip_user", FailureTracker(5, 900))
    monkeypatch.setattr(main, "_recover_by_user", FailureTracker(10, 3600))
    make_user(c, "fa_recover")
    _enrol(c, "fa_recover")
    h = _login_with_code(c, "fa_recover")
    proof = "9e" * 32
    assert c.put("/users/me/recovery-verifier", json={"proof": proof}, headers=h).status_code == 200
    body = {"username": "fa_recover", "proof": proof, "new_password": "ef" * 32}
    r = c.post("/auth/recover-e2ee", json=body)
    assert r.status_code == 401 and r.json()["detail"] == "TOTP_REQUIRED"
    assert c.post("/auth/recover-e2ee", json={**body, "totp_code": "000000"}).status_code == 401
    r = c.post("/auth/recover-e2ee", json={**body, "totp_code": _code("fa_recover")})
    assert r.status_code == 200, r.text


def test_replacing_the_recovery_verifier_tells_the_owner(c, monkeypatch):
    """A new verifier makes the old recovery code useless; the owner must hear about it."""
    notices = []
    monkeypatch.setattr(main, "_notify", lambda user, what: notices.append((user.username, what)))
    make_user(c, "fa_verifier")
    _enrol(c, "fa_verifier")
    h = _login_with_code(c, "fa_verifier")
    assert c.put("/users/me/recovery-verifier", json={"proof": "9d" * 32}, headers=h).status_code == 200
    assert not [n for n in notices if "recovery code" in n[1]]          # the first one is the setup
    assert c.put("/users/me/recovery-verifier", json={"proof": "9c" * 32}, headers=h).status_code == 200
    assert [n for n in notices if n[0] == "fa_verifier" and "recovery code" in n[1]]


def test_replacing_the_recovery_verifier_needs_a_recent_second_factor(c, monkeypatch):
    """A session whose second factor is older than the step-up window (e.g. one renewed with the refresh
    token) may store the first verifier but not replace it."""
    make_user(c, "fa_verifier_old")
    _enrol(c, "fa_verifier_old")
    h = _login_with_code(c, "fa_verifier_old")
    assert c.put("/users/me/recovery-verifier", json={"proof": "9b" * 32}, headers=h).status_code == 200
    later = main.time.time() + main.STEP_UP_WINDOW + 60
    monkeypatch.setattr(main.time, "time", lambda: later)
    r = c.put("/users/me/recovery-verifier", json={"proof": "9a" * 32}, headers=h)
    assert r.status_code == 401 and r.json()["detail"] == "TOTP_REQUIRED", r.text
