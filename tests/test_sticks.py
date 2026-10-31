"""
The server's half of the stick's key: released only after the full login, revocable, and gone with
the account.
"""
import database
import models

import test_api_security as base
import test_factors_and_delays as fa
from test_api_security import PASSWORD, bearer, make_user

client = base.client      # reuse the fixtures
c = fa.c


def _create(c, h, name="laptop"):
    r = c.post("/users/me/sticks", json={"name": name}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


def test_secret_after_full_login_only(c, monkeypatch):
    monkeypatch.setenv("REQUIRED_FACTORS", "password,totp")
    make_user(c, "st_alice")
    # password alone: the server requires the second factor first, so no secret
    assert c.post("/users/me/sticks", json={"name": "x"}, headers=bearer(c, "st_alice")).status_code == 403
    fa._enrol(c, "st_alice")
    h = fa._login_with_code(c, "st_alice")
    made = _create(c, h)
    assert len(bytes.fromhex(made["secret"])) == 32

    h = fa._login_with_code(c, "st_alice")
    r = c.post(f"/users/me/sticks/{made['stick_id']}/secret", headers=h)
    assert r.status_code == 200 and r.json()["secret"] == made["secret"]
    with database.SessionLocal() as db:
        row = db.query(models.StickSecret).one()
        assert made["secret"] not in row.secret_enc          # stored encrypted
        assert row.last_used_at is not None


def test_another_users_stick_is_not_found(c):
    make_user(c, "st_one")
    make_user(c, "st_two")
    fa._enrol(c, "st_one")
    fa._enrol(c, "st_two")
    made = _create(c, fa._login_with_code(c, "st_one"))
    r = c.post(f"/users/me/sticks/{made['stick_id']}/secret", headers=fa._login_with_code(c, "st_two"))
    assert r.status_code == 404 and r.json()["detail"] == "STICK_REVOKED"


def _secret(c, h, sid):
    return c.post(f"/users/me/sticks/{sid}/secret", headers=h)


def test_removal_locks_at_once_and_removes_after_the_delay(c):
    make_user(c, "st_lost")
    fa._enrol(c, "st_lost")
    h = fa._login_with_code(c, "st_lost")
    made = _create(c, h, "old laptop")
    assert [s["name"] for s in c.get("/users/me/sticks", headers=h).json()] == ["old laptop"]
    sid = made["stick_id"]
    assert c.request("DELETE", f"/users/me/sticks/{sid}", json={"password": "wrong" * 4}, headers=h).status_code == 401
    r = c.request("DELETE", f"/users/me/sticks/{sid}", json={"password": PASSWORD, "totp_code": fa._code("st_lost")}, headers=h)
    assert r.status_code == 200 and r.json()["pending"], r.text
    change_id = r.json()["change_id"]
    assert any("USB stick" in what and "cancel" in action for _, what, action in c.mails)
    # locked at once
    r = _secret(c, h, sid)
    assert r.status_code == 403 and r.json()["detail"] == "STICK_LOCKED"
    listed = c.get("/users/me/sticks", headers=h).json()[0]
    assert listed["locked_at"] and listed["removal_due"]
    # asking again does not start a second removal
    r = c.request("DELETE", f"/users/me/sticks/{sid}", json={"password": PASSWORD, "totp_code": fa._code("st_lost")}, headers=h)
    assert r.json()["change_id"] == change_id
    # gone for good once the delay has passed
    fa._make_due(change_id)
    with database.SessionLocal() as db:
        import pending
        assert pending.apply_due(db) == 1
    r = _secret(c, h, sid)
    assert r.status_code == 404 and r.json()["detail"] == "STICK_REVOKED"
    with database.SessionLocal() as db:
        assert db.query(models.StickLock).count() == 0
    assert any("was removed" in what for _, what, _a in c.mails)


def test_cancelled_removal_stays_locked_until_the_app_unlocks(c):
    make_user(c, "st_back")
    fa._enrol(c, "st_back")
    h = fa._login_with_code(c, "st_back")
    sid = _create(c, h)["stick_id"]
    r = c.request("DELETE", f"/users/me/sticks/{sid}", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 200, r.text
    r = c.post("/auth/cancel-change", json={"token": fa._cancel_token(c.mails[-1])})
    assert r.status_code == 200, r.text
    assert _secret(c, h, sid).status_code == 403
    listed = c.get("/users/me/sticks", headers=h).json()[0]
    assert listed["locked_at"] and listed["removal_due"] is None
    r = c.post(f"/users/me/sticks/{sid}/unlock", json={}, headers=h)
    assert r.status_code == 200, r.text
    assert _secret(c, h, sid).status_code == 200


def test_unlock_stops_a_waiting_removal(c):
    make_user(c, "st_undo")
    fa._enrol(c, "st_undo")
    h = fa._login_with_code(c, "st_undo")
    sid = _create(c, h)["stick_id"]
    change_id = c.request("DELETE", f"/users/me/sticks/{sid}", json={"password": PASSWORD}, headers=h).json()["change_id"]
    assert c.post(f"/users/me/sticks/{sid}/unlock", json={}, headers=h).status_code == 200
    fa._make_due(change_id)
    with database.SessionLocal() as db:
        import pending
        assert pending.apply_due(db) == 0
    assert _secret(c, h, sid).status_code == 200


def test_lock_needs_only_a_session_and_unlock_the_full_sign_in(c, monkeypatch):
    make_user(c, "st_lock")
    fa._enrol(c, "st_lock")
    h = fa._login_with_code(c, "st_lock")
    sid = _create(c, h)["stick_id"]
    other = _create(c, h, "other")["stick_id"]
    r = c.post(f"/users/me/sticks/{sid}/lock", headers=h)
    assert r.status_code == 200, r.text
    assert any("locked" in what for _, what in c.notices)
    assert _secret(c, h, sid).status_code == 403
    assert _secret(c, h, other).status_code == 200          # only that stick
    assert c.post(f"/users/me/sticks/{sid}/lock", headers=h).status_code == 200    # again: harmless
    # the second factor must be recent to unlock
    import main
    import time
    real = time.time
    monkeypatch.setattr(main.time, "time", lambda: real() + main.STEP_UP_WINDOW + 1)
    r = c.post(f"/users/me/sticks/{sid}/unlock", json={}, headers=h)
    assert r.status_code == 401 and r.json()["detail"] == "TOTP_REQUIRED"
    monkeypatch.setattr(main.time, "time", real)
    assert c.post(f"/users/me/sticks/{sid}/unlock", json={}, headers=fa._login_with_code(c, "st_lock")).status_code == 200


def test_unknown_stick_cannot_be_locked(c):
    make_user(c, "st_none")
    fa._enrol(c, "st_none")
    h = fa._login_with_code(c, "st_none")
    assert c.post("/users/me/sticks/nope/lock", headers=h).status_code == 404
    assert c.post("/users/me/sticks/nope/unlock", json={}, headers=h).status_code == 404


def test_limit_and_unused_secrets_lapse(c):
    make_user(c, "st_many")
    fa._enrol(c, "st_many")
    h = fa._login_with_code(c, "st_many")
    for i in range(10):
        _create(c, h, f"s{i}")
    assert c.post("/users/me/sticks", json={"name": "one more"}, headers=h).status_code == 409
    with database.SessionLocal() as db:   # never used and older than an hour: does not count any more
        from datetime import datetime, timedelta
        db.query(models.StickSecret).update({models.StickSecret.created_at: datetime.utcnow() - timedelta(hours=2)})
        db.commit()
    _create(c, h, "after")


def test_off_without_the_instance_key(c, monkeypatch):
    make_user(c, "st_off")
    fa._enrol(c, "st_off")
    h = fa._login_with_code(c, "st_off")
    monkeypatch.delenv("TOTP_ENCRYPTION_KEY")
    assert c.post("/users/me/sticks", json={"name": "x"}, headers=h).status_code == 503


def test_account_deletion_removes_sticks(c, monkeypatch):
    monkeypatch.setenv("CHANGE_DELAY_HOURS", "0")
    make_user(c, "st_gone")
    fa._enrol(c, "st_gone")
    h = fa._login_with_code(c, "st_gone")
    _create(c, h)
    uid = fa._user("st_gone").id
    r = c.request("DELETE", "/storage", json={"password": PASSWORD}, headers=fa._login_with_code(c, "st_gone"))
    assert r.status_code == 200, r.text
    with database.SessionLocal() as db:
        assert db.query(models.StickSecret).filter_by(user_id=uid).count() == 0


def test_server_id_follows_the_stick_secret_key(c, monkeypatch):
    """#99: the id the client binds a stick to stays as long as the key the stick secrets need."""
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", "11" * 32)
    first = c.get("/server-info").json()["server_id"]
    assert first and len(first) == 36 and first == c.get("/server-info").json()["server_id"]
    monkeypatch.setenv("TOTP_ENCRYPTION_KEY", "22" * 32)
    assert c.get("/server-info").json()["server_id"] not in (None, first)
    monkeypatch.delenv("TOTP_ENCRYPTION_KEY")
    assert c.get("/server-info").json()["server_id"] is None
