"""TOTP second factor: RFC 6238 vectors, enrolment and the two-step login."""
import pytest

import database
import main
import models
import totp
from throttle import EscalatingLockout

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
    monkeypatch.setattr(main, "_totp_failures", EscalatingLockout())
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
    # marked as a step of the sign-in, so fail2ban does not count it (tests/test_fail2ban_filter.py)
    assert r.headers.get("X-Auth-Step") == "second-factor"
    r = tc.post("/auth/login", json={"username": "alice", "password": PASSWORD, "totp_code": "000000"})
    assert r.status_code == 401 and "access_token" not in r.text
    assert "X-Auth-Step" not in r.headers        # a wrong code is a failure
    r = tc.post("/auth/login", json={"username": "alice", "password": "wrong " + PASSWORD})
    assert r.status_code == 401 and "X-Auth-Step" not in r.headers
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


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_lockout_grows_and_a_success_does_not_start_it_over():
    clock = Clock()
    t = EscalatingLockout(limit=3, window=900, lockouts=(900, 3600, 86400), calm=86400, clock=clock)
    assert [t.record_failure("u") for _ in range(3)] == [0, 0, 900]
    assert 890 < t.blocked("u") <= 901 and t.blocked("other") == 0
    clock.now += 901
    assert t.blocked("u") == 0
    t.reset("u")                                          # the owner signs in: the level stays
    assert [t.record_failure("u") for _ in range(3)] == [0, 0, 3600]
    clock.now += 3601
    assert [t.record_failure("u") for _ in range(3)] == [0, 0, 86400]
    clock.now += 86401
    assert [t.record_failure("u") for _ in range(3)] == [0, 0, 86400]      # stays at the longest
    clock.now += 86400 + 86401                            # a quiet day after the lock ended
    assert [t.record_failure("u") for _ in range(3)] == [0, 0, 900]


def test_lockout_counts_only_failures_inside_the_window_and_bounds_memory():
    clock = Clock()
    t = EscalatingLockout(limit=3, window=900, max_keys=2, clock=clock)
    t.record_failure("u"); t.record_failure("u")
    clock.now += 901
    assert t.record_failure("u") == 0 and t.blocked("u") == 0     # the two old ones no longer count
    for _ in range(3):
        t.record_failure("locked")
    for i in range(10):
        t.record_failure(f"noise{i}")
    assert len(t._state) <= 2 and t.blocked("locked") > 0         # a locked key is not pushed out


def test_owner_is_told_when_the_code_is_locked_and_the_lock_grows(tc, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(main, "_totp_failures", EscalatingLockout(clock=clock))
    told = []
    monkeypatch.setattr(main, "send_security_notice_email", lambda email, user, what, action="": told.append((email, what)))
    make_user(tc, "totp_locked")
    secret, _ = _enrol(tc, "totp_locked")
    told.clear()
    bad = {"username": "totp_locked", "password": PASSWORD, "totp_code": "000000"}
    assert [tc.post("/auth/login", json=bad).status_code for _ in range(4)] == [401] * 4
    assert told == []
    assert tc.post("/auth/login", json=bad).status_code == 401
    assert len(told) == 1 and told[0][0] == "totp_locked@example.com"
    assert "15 minutes" in told[0][1] and "password" in told[0][1]
    # locked: even the right code waits, and nothing more is sent
    good = dict(bad, totp_code=totp.code_for_step(secret, totp.current_step()))
    r = tc.post("/auth/login", json=good)
    assert r.status_code == 429 and 890 < int(r.headers["Retry-After"]) <= 901
    assert len(told) == 1
    with database.SessionLocal() as db:
        uid = db.query(models.User).filter_by(username="totp_locked").one().id
        assert db.query(models.SecurityEvent).filter_by(user_id=uid, event_type="totp_locked").count() == 1

    clock.now += 901
    assert [tc.post("/auth/login", json=bad).status_code for _ in range(5)] == [401] * 5
    assert len(told) == 2 and "1 hour" in told[1][1]
    assert int(tc.post("/auth/login", json=good).headers["Retry-After"]) > 3500


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
