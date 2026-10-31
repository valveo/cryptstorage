"""The hash-chained record of the escrow settings: a change between starts is noticed and reported."""
import hashlib

import pytest

import database
import escrow_state
import models


@pytest.fixture
def db():
    database.init_db()
    s = database.SessionLocal()
    s.query(models.ConfigLog).delete()
    s.commit()
    yield s
    s.query(models.ConfigLog).delete()
    s.commit()
    s.close()


def start(db, sent):
    return escrow_state.check_at_startup(db, sent.append)


def test_first_start_records_without_notice(db, monkeypatch):
    monkeypatch.setenv("RECOVERY_POLICY", "user")
    sent = []
    st = start(db, sent)
    assert st["chain_ok"] and sent == []
    rows = db.query(models.ConfigLog).all()
    assert [(r.seq, r.recovery_policy, r.escrow_key_fingerprint) for r in rows] == [(1, "user", None)]


def test_unchanged_restart_adds_nothing(db, monkeypatch):
    monkeypatch.setenv("RECOVERY_POLICY", "user")
    sent = []
    start(db, sent)
    start(db, sent)
    assert db.query(models.ConfigLog).count() == 1 and sent == []


def test_change_between_starts_is_logged_and_mailed(db, monkeypatch):
    monkeypatch.setenv("RECOVERY_POLICY", "user")
    sent = []
    start(db, sent)
    monkeypatch.setenv("RECOVERY_POLICY", "both")
    monkeypatch.setenv("ESCROW_PUBLIC_KEY", "cd" * 32)
    st = start(db, sent)
    assert st["chain_ok"] and st["changed_at"] is not None
    assert len(sent) == 1 and "escrow is now ON" in sent[0]
    last = db.query(models.ConfigLog).order_by(models.ConfigLog.seq.desc()).first()
    assert last.seq == 2 and last.escrow_key_fingerprint == hashlib.sha256(bytes.fromhex("cd" * 32)).hexdigest()
    events = [e.event_type for e in db.query(models.SecurityEvent).all()]
    assert "escrow_config_changed" in events
    # a new key with the same policy is a change too
    monkeypatch.setenv("ESCROW_PUBLIC_KEY", "ef" * 32)
    start(db, sent)
    assert len(sent) == 2 and db.query(models.ConfigLog).count() == 3


def test_edited_row_breaks_the_chain(db, monkeypatch):
    monkeypatch.setenv("RECOVERY_POLICY", "user")
    sent = []
    start(db, sent)
    monkeypatch.setenv("RECOVERY_POLICY", "both")
    monkeypatch.setenv("ESCROW_PUBLIC_KEY", "cd" * 32)
    start(db, sent)
    # someone hides that escrow was ever on by rewriting the second row
    row = db.get(models.ConfigLog, 2)
    row.recovery_policy = "user"
    db.commit()
    sent.clear()
    st = start(db, sent)
    assert st["chain_ok"] is False
    assert any("tampered" in m for m in sent)


def test_deleted_row_breaks_the_chain(db, monkeypatch):
    monkeypatch.setenv("RECOVERY_POLICY", "user")
    sent = []
    start(db, sent)
    monkeypatch.setenv("RECOVERY_POLICY", "escrow")
    monkeypatch.setenv("ESCROW_PUBLIC_KEY", "cd" * 32)
    start(db, sent)
    monkeypatch.setenv("RECOVERY_POLICY", "user")
    start(db, sent)
    db.query(models.ConfigLog).filter(models.ConfigLog.seq == 2).delete()
    db.commit()
    assert escrow_state.verify_chain(db.query(models.ConfigLog).order_by(models.ConfigLog.seq).all()) is False
