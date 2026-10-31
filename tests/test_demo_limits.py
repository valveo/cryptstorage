"""
Limits for a public demo or trial server (all off by default): the quota of new accounts,
a cap on the number of accounts, and accounts that delete themselves after a lifetime.
"""
from datetime import datetime, timedelta

import database
import models
import pending

import test_api_security as base
from test_api_security import make_user

client = base.client      # reuse the fixture


def _user(name):
    with database.SessionLocal() as db:
        return db.query(models.User).filter_by(username=name).one_or_none()


def test_defaults_change_nothing(client):
    make_user(client, "dl_default")
    assert _user("dl_default").quota_bytes == 10 * 1024 ** 3
    assert client.get("/server-info").json()["account_lifetime_hours"] is None
    with database.SessionLocal() as db:
        assert pending.expire_accounts(db) == 0


def test_quota_of_new_accounts(client, monkeypatch):
    monkeypatch.setenv("DEFAULT_QUOTA_MB", "1024")
    make_user(client, "dl_quota")
    assert _user("dl_quota").quota_bytes == 1024 ** 3


def test_registration_stops_at_the_user_limit(client, monkeypatch):
    with database.SessionLocal() as db:
        existing = db.query(models.User).count()
    monkeypatch.setenv("MAX_USERS", str(existing + 1))
    make_user(client, "dl_last_one")
    r = client.post("/auth/register", json={
        "username": "dl_too_many", "email": "dl_too_many@example.com", "password": base.PASSWORD})
    assert r.status_code == 503
    assert _user("dl_too_many") is None


def test_old_accounts_are_deleted_through_the_normal_path(client, monkeypatch):
    deleted = []
    monkeypatch.setattr(pending, "daemon_e2ee_delete", lambda user: deleted.append(user))
    monkeypatch.setenv("ACCOUNT_LIFETIME_HOURS", "3")
    make_user(client, "dl_old")
    make_user(client, "dl_young")
    with database.SessionLocal() as db:
        db.query(models.User).filter_by(username="dl_old").one().created_at = datetime.utcnow() - timedelta(hours=4)
        db.commit()
    assert client.get("/server-info").json()["account_lifetime_hours"] == 3
    with database.SessionLocal() as db:
        # an older own deletion request is brought forward instead of doubled
        u = db.query(models.User).filter_by(username="dl_old").one()
        db.add(models.PendingChange(user_id=u.id, kind="delete", state="pending", cancel_hash="x" * 64,
                                    due_at=datetime.utcnow() + timedelta(hours=24)))
        db.commit()
        assert pending.expire_accounts(db) >= 1
        pending.apply_due(db)
    assert _user("dl_old") is None
    assert _user("dl_young") is not None
    assert deleted == ["dl_old"]


def test_a_failing_deletion_is_not_logged_again_every_round(client, monkeypatch):
    def fail(user):
        raise pending.DaemonError("daemon down")
    monkeypatch.setattr(pending, "daemon_e2ee_delete", fail)
    monkeypatch.setenv("ACCOUNT_LIFETIME_HOURS", "3")
    make_user(client, "dl_stuck")
    with database.SessionLocal() as db:
        u = db.query(models.User).filter_by(username="dl_stuck").one()
        u.created_at = datetime.utcnow() - timedelta(hours=4)
        db.commit()
        uid = u.id

    def expired_lines():
        with database.SessionLocal() as db:
            return db.query(models.SecurityEvent).filter_by(user_id=uid, event_type="account_expired").count()

    with database.SessionLocal() as db:
        pending.expire_accounts(db)
        pending.apply_due(db)          # the daemon fails: the deletion goes back to pending
        pending.expire_accounts(db)
        pending.apply_due(db)
        pending.expire_accounts(db)
        deletes = db.query(models.PendingChange).filter_by(user_id=uid, kind="delete").count()
    assert expired_lines() == 1
    assert deletes == 1
    assert _user("dl_stuck") is not None
    # leave nothing due behind for the tests that run apply_due later
    with database.SessionLocal() as db:
        db.query(models.PendingChange).filter_by(user_id=uid).update({"state": "cancelled"})
        db.commit()
