"""
Who may register (REGISTRATION = open / invite / closed, REGISTRATION_EMAIL_DOMAINS), invitations,
and the removal of accounts whose e-mail address was never confirmed.
"""
from datetime import datetime, timedelta

import pytest

import config
import database
import models
import pending
import registration

import test_api_security as base

client = base.client


def _register(client, name, **extra):
    return client.post("/auth/register", json={
        "username": name, "email": extra.pop("email", f"{name}@example.com"), "password": base.PASSWORD, **extra})


def _user(name):
    with database.SessionLocal() as db:
        return db.query(models.User).filter_by(username=name).one_or_none()


def _make_young(*names):
    """The database is shared by the test modules: leave no old accounts for the lifetime tests."""
    with database.SessionLocal() as db:
        db.query(models.User).filter(models.User.username.in_(names)).update(
            {models.User.created_at: datetime.utcnow()}, synchronize_session=False)
        db.commit()


def _invite(**kw):
    with database.SessionLocal() as db:
        invite, code = registration.create_invite(db, **kw)
        return invite.id, code


def test_open_is_the_default_and_server_info_says_so(client):
    assert client.get("/server-info").json()["registration"] == "open"
    assert _register(client, "reg_open").status_code == 201


def test_closed_refuses_everyone(client, monkeypatch):
    monkeypatch.setenv("REGISTRATION", "closed")
    assert client.get("/server-info").json()["registration"] == "closed"
    _, code = _invite()
    r = _register(client, "reg_closed", invite=code)
    assert (r.status_code, r.json()["detail"]) == (403, "REGISTRATION_CLOSED")
    assert _user("reg_closed") is None


def test_invite_mode_needs_a_code_that_works_once(client, monkeypatch):
    monkeypatch.setenv("REGISTRATION", "invite")
    r = _register(client, "reg_inv_none")
    assert (r.status_code, r.json()["detail"]) == (403, "INVITE_REQUIRED")
    r = _register(client, "reg_inv_bad", invite="not-a-code")
    assert (r.status_code, r.json()["detail"]) == (403, "INVITE_INVALID")

    invite_id, code = _invite()
    assert _register(client, "reg_inv_ok", invite=f" {code} ").status_code == 201
    with database.SessionLocal() as db:
        row = db.get(models.Invite, invite_id)
        assert row.used_by == _user("reg_inv_ok").id and row.used_at is not None
        assert code not in (row.code_hash, row.note or "")          # only its HMAC is stored
    r = _register(client, "reg_inv_again", invite=code)
    assert (r.status_code, r.json()["detail"]) == (403, "INVITE_INVALID")


def test_invite_for_one_address_and_expiry(client, monkeypatch):
    monkeypatch.setenv("REGISTRATION", "invite")
    _, code = _invite(email="Bob@Example.org")
    assert _register(client, "reg_inv_other", invite=code).json()["detail"] == "INVITE_INVALID"
    assert _register(client, "reg_inv_bob", invite=code, email="bob@example.org").status_code == 201

    invite_id, code = _invite()
    with database.SessionLocal() as db:
        db.get(models.Invite, invite_id).expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()
    assert _register(client, "reg_inv_late", invite=code).json()["detail"] == "INVITE_INVALID"


def test_without_an_invite_the_answer_does_not_say_which_names_exist(client, monkeypatch):
    base.make_user(client, "reg_taken")
    monkeypatch.setenv("REGISTRATION", "invite")
    assert _register(client, "reg_taken").json()["detail"] == "INVITE_REQUIRED"
    assert _register(client, "reg_taken", invite="guess").json()["detail"] == "INVITE_INVALID"


def test_a_registration_that_fails_does_not_use_up_the_invite(client, monkeypatch):
    import main
    base.make_user(client, "reg_dup")
    monkeypatch.setenv("REGISTRATION", "invite")
    invite_id, code = _invite()
    assert _register(client, "reg_dup", invite=code).status_code == 409        # name taken
    with database.SessionLocal() as db:
        assert db.get(models.Invite, invite_id).used_at is None

    def no_mail(*a):
        raise main.EmailError("smtp down")
    monkeypatch.setattr(main, "send_verification_email", no_mail)
    assert _register(client, "reg_nomail", invite=code).status_code == 500
    assert _user("reg_nomail") is None
    with database.SessionLocal() as db:
        assert db.get(models.Invite, invite_id).used_at is None
        assert db.query(models.UserKdf).count() == db.query(models.UserKdf).join(
            models.User, models.User.id == models.UserKdf.user_id).count()     # no row left behind


def test_email_domains(client, monkeypatch):
    monkeypatch.setenv("REGISTRATION_EMAIL_DOMAINS", "Example.org, @corp.example")
    r = _register(client, "reg_dom_no")
    assert (r.status_code, r.json()["detail"]) == (403, "EMAIL_DOMAIN_REFUSED")
    assert _register(client, "reg_dom_evil", email="x@example.org.evil.com").status_code == 403
    assert _register(client, "reg_dom_ok", email="a@EXAMPLE.org").status_code == 201
    assert _register(client, "reg_dom_ok2", email="a@corp.example").status_code == 201


def test_bad_registration_setting_stops_the_start(monkeypatch):
    monkeypatch.setenv("REGISTRATION", "friends")
    with pytest.raises(config.ConfigError):
        config.validate()


def test_unconfirmed_accounts_are_removed_after_a_day(client):
    for name in ("unv_old", "unv_new", "unv_old_with_data"):
        assert _register(client, name).status_code == 201
    base.make_user(client, "unv_confirmed")
    with database.SessionLocal() as db:
        long_ago = datetime.utcnow() - timedelta(hours=25)
        for name in ("unv_old", "unv_old_with_data", "unv_confirmed"):
            db.query(models.User).filter_by(username=name).one().created_at = long_ago
        db.query(models.User).filter_by(username="unv_old_with_data").one().storage_created = True
        db.commit()
        old_id = db.query(models.User).filter_by(username="unv_old").one().id
        assert pending.remove_unverified(db) == 1
        assert db.query(models.UserKdf).filter_by(user_id=old_id).count() == 0
    assert _user("unv_old") is None
    assert all(_user(n) is not None for n in ("unv_new", "unv_old_with_data", "unv_confirmed"))
    assert _register(client, "unv_old").status_code == 201       # the name and address are free again
    _make_young("unv_old_with_data", "unv_confirmed")


def test_unconfirmed_accounts_stay_when_verification_is_off(client, monkeypatch):
    assert _register(client, "unv_keep").status_code == 201
    with database.SessionLocal() as db:
        db.query(models.User).filter_by(username="unv_keep").one().created_at = datetime.utcnow() - timedelta(days=9)
        db.commit()
        monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
        assert pending.remove_unverified(db) == 0
        monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "true")
        monkeypatch.setenv("UNVERIFIED_ACCOUNT_HOURS", "0")
        assert pending.remove_unverified(db) == 0
    assert _user("unv_keep") is not None
    _make_young("unv_keep")


def test_minimum_client_version_is_published_and_checked(client, monkeypatch):
    monkeypatch.setenv("MIN_CLIENT_VERSION", "v0.1.2")
    assert client.get("/server-info").json()["min_client_version"] == "0.1.2"
    config.validate()
    monkeypatch.setenv("MIN_CLIENT_VERSION", "newest")
    with pytest.raises(config.ConfigError):
        config.validate()
