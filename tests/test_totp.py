"""TOTP second factor: RFC 6238 vectors, enrolment and the two-step login."""
import pytest

import database
import main
import models
import totp
from throttle import FailureTracker

import test_api_security as base
from test_api_security import PASSWORD, bearer, login, make_user

client = base.client      # reuse the fixture (pytest finds it by this module-level name)

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # base32 of "12345678901234567890"


@pytest.mark.parametrize("t,expected", [
    (59, "287082"), (1111111109, "081804"), (1111111111, "050471"),
    (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130"),
])
def test_rfc6238_vectors(t, expected):
    assert totp.code_for_step(RFC_SECRET, t // 30) == expected


def test_replay_and_window():
    now = 1234567890
    step = totp.verify(RFC_SECRET, "005924", now=now)
    assert step == now // 30
    assert totp.verify(RFC_SECRET, "005924", last_step=step, now=now) is None
    assert totp.verify(RFC_SECRET, "000000", now=now) is None
    assert totp.verify(RFC_SECRET, "abc123", now=now) is None


def test_secret_is_bound_to_user():
    blob = totp.encrypt_secret(RFC_SECRET, "user-a")
    assert totp.decrypt_secret(blob, "user-a") == RFC_SECRET
    with pytest.raises(Exception):
        totp.decrypt_secret(blob, "user-b")


def test_backup_codes_are_single_use():
    codes = totp.generate_backup_codes()
    stored = totp.hash_backup_codes(codes)
    rest = totp.consume_backup_code(stored, codes[0].lower())
    assert rest is not None
    assert totp.consume_backup_code(rest, codes[0]) is None
    assert totp.consume_backup_code(rest, codes[1]) is not None


@pytest.fixture
def tc(client, monkeypatch):
    monkeypatch.setattr(main, "_totp_failures", FailureTracker(5, 900))
    return client


def _enrol(c, name):
    h = bearer(c, name)
    r = c.post("/users/me/totp/setup", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")
    code = totp.code_for_step(secret, totp.current_step())
    r = c.post("/users/me/totp/enable", json={"code": code, "email_code": c.enrol_codes[-1]}, headers=h)
    assert r.status_code == 200, r.text
    return secret, r.json()["backup_codes"]


def test_login_requires_code_once_enabled(tc):
    make_user(tc, "alice")
    secret, backups = _enrol(tc, "alice")
    r = login(tc, "alice")
    assert r.status_code == 401 and r.json()["detail"] == "TOTP_REQUIRED"
    r = tc.post("/auth/login", json={"username": "alice", "password": PASSWORD, "totp_code": "000000"})
    assert r.status_code == 401 and "access_token" not in r.text
    # the code used for enabling is spent; the next step is accepted
    step = totp.current_step() + 1
    with database.SessionLocal() as db:
        db.query(models.User).filter_by(username="alice").one().totp_last_step = step - 1
        db.commit()
    code = totp.code_for_step(secret, step)
    r = tc.post("/auth/login", json={"username": "alice", "password": PASSWORD, "totp_code": code})
    assert r.status_code == 200 and r.json()["access_token"]
    r = tc.post("/auth/login", json={"username": "alice", "password": PASSWORD, "totp_code": code})
    assert r.status_code == 401        # replay
    r = tc.post("/auth/login", json={"username": "alice", "password": PASSWORD, "totp_code": backups[0]})
    assert r.status_code == 200
    r = tc.post("/auth/login", json={"username": "alice", "password": PASSWORD, "totp_code": backups[0]})
    assert r.status_code == 401        # backup code is single use


def test_wrong_password_never_reveals_totp(tc):
    make_user(tc, "bob")
    _enrol(tc, "bob")
    r = login(tc, "bob", "wrong password!!")
    assert r.status_code == 401 and r.json()["detail"] != "TOTP_REQUIRED"


def test_code_guessing_is_throttled(tc):
    make_user(tc, "carol")
    _enrol(tc, "carol")
    body = {"username": "carol", "password": PASSWORD, "totp_code": "000000"}
    codes = [tc.post("/auth/login", json=body).status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_enable_with_bad_code_and_disable(tc):
    make_user(tc, "dave")
    h = bearer(tc, "dave")
    assert tc.post("/users/me/totp/setup", json={"password": PASSWORD}, headers=h).status_code == 200
    email_code = tc.enrol_codes[-1]
    assert tc.post("/users/me/totp/enable", json={"code": "000000", "email_code": email_code},
                   headers=h).status_code == 401
    # finish properly
    with database.SessionLocal() as db:
        u = db.query(models.User).filter_by(username="dave").one()
        secret = totp.decrypt_secret(u.totp_secret_enc, u.id)
    tc.post("/users/me/totp/enable", json={"code": totp.code_for_step(secret, totp.current_step()),
                                           "email_code": email_code}, headers=h)
    r = tc.post("/users/me/totp/disable", json={"password": PASSWORD, "code": "000000"}, headers=h)
    assert r.status_code == 401
    code = tc.post("/users/me/totp/disable", json={"password": PASSWORD, "code": "x"}, headers=h)
    assert code.status_code == 401
