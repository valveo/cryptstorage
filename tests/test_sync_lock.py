"""
One synchronisation at a time per volume (docs/design-features.md section 5.1): the sync lock is
taken, renewed and released by one device; another device waits until it is released or lapses.
"""
from datetime import datetime, timedelta

import database
import models

import test_api_security as base
from test_api_security import bearer, make_user

client = base.client      # reuse the fixture

LAPTOP = "laptop-0123456789abcdef"
DESKTOP = "desktop-0123456789abcdef"


def _take(c, h, holder, name=None):
    return c.post("/storage/sync-lock", json={"holder": holder, "holder_name": name}, headers=h)


def _lapse(name):
    with database.SessionLocal() as db:
        user = db.query(models.User).filter_by(username=name).one()
        db.get(models.SyncLock, (user.id, "personal")).expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()


def test_one_device_at_a_time(client):
    make_user(client, "sl_one")
    h = bearer(client, "sl_one")
    r = _take(client, h, LAPTOP, "Laptop")
    assert r.status_code == 200, r.text
    assert r.json()["ttl_seconds"] == 120
    busy = _take(client, h, DESKTOP, "Desktop")
    assert busy.status_code == 409
    assert busy.json()["detail"] == "SYNC_LOCKED"
    assert busy.json()["holder_name"] == "Laptop"
    assert 0 < busy.json()["expires_in"] <= 120


def test_holder_renews_and_releases(client):
    make_user(client, "sl_renew")
    h = bearer(client, "sl_renew")
    first = _take(client, h, LAPTOP).json()["expires_at"]
    assert _take(client, h, LAPTOP).json()["expires_at"] >= first        # renewal
    # Only the holder's release counts
    assert client.delete("/storage/sync-lock", params={"holder": DESKTOP}, headers=h).status_code == 200
    assert _take(client, h, DESKTOP).status_code == 409
    assert client.delete("/storage/sync-lock", params={"holder": LAPTOP}, headers=h).status_code == 200
    assert _take(client, h, DESKTOP).status_code == 200


def test_lapsed_lock_can_be_taken_over(client):
    make_user(client, "sl_lapse")
    h = bearer(client, "sl_lapse")
    assert _take(client, h, LAPTOP).status_code == 200
    _lapse("sl_lapse")                     # the laptop crashed and stopped renewing
    assert _take(client, h, DESKTOP).status_code == 200
    assert _take(client, h, LAPTOP).status_code == 409


def test_locks_are_per_user(client):
    make_user(client, "sl_alice")
    make_user(client, "sl_bob")
    assert _take(client, bearer(client, "sl_alice"), LAPTOP).status_code == 200
    assert _take(client, bearer(client, "sl_bob"), DESKTOP).status_code == 200
    # Bob cannot release Alice's lock even with her holder id
    client.delete("/storage/sync-lock", params={"holder": LAPTOP}, headers=bearer(client, "sl_bob"))
    assert _take(client, bearer(client, "sl_alice"), DESKTOP).status_code == 409


def test_needs_login_and_valid_input(client):
    make_user(client, "sl_input")
    assert client.post("/storage/sync-lock", json={"holder": LAPTOP}).status_code == 401
    h = bearer(client, "sl_input")
    assert _take(client, h, "short").status_code == 422
    assert _take(client, h, "bad holder with spaces!!").status_code == 422
    r = client.post("/storage/sync-lock", json={"holder": LAPTOP, "volume": "someone-else"}, headers=h)
    assert r.status_code == 422
