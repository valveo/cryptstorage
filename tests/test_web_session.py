"""
Web UI sessions without the password: a passkey alone, or a sign-in the app hands over with a
one-time ticket. Such a session manages the account but never reaches what opens the storage, and it
confirms sensitive actions with a recent sign-in instead of the password.
"""
import hashlib
import time

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import auth
import database
import main
import models

import test_factors_and_delays as fa
import test_passkeys as tp
from test_api_security import PASSWORD, make_user

client = tp.client      # reuse the fixtures
c = tp.c
pk = tp.pk


def _web_passkey_login(c, name, authn):
    r = c.post("/auth/web/passkey/begin", json={"username": name})
    assert r.status_code == 200, r.text
    return c.post("/auth/web/passkey/finish", json={"session": r.json()["session"],
                                                     "credential": authn.get(r.json()["options"])})


def _h(r):
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _account_with_passkey(c, name):
    make_user(c, name)
    fa._enrol(c, name)
    return tp._add_passkey(c, name)


def test_passkey_alone_gives_a_web_session_without_refresh_token(pk):
    authn = _account_with_passkey(pk, "web_alice")
    r = _web_passkey_login(pk, "web_alice", authn)
    assert r.status_code == 200, r.text
    assert r.json().get("refresh_token") is None
    claims = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert claims["scope"] == "web" and isinstance(claims["auth"], int) and isinstance(claims["mfa"], int)
    h = _h(r)
    assert pk.get("/users/me", headers=h).status_code == 200
    assert pk.get("/users/me/passkeys", headers=h).status_code == 200


def test_web_passkey_needs_user_verification(pk):
    authn = _account_with_passkey(pk, "web_uv")
    r = pk.post("/auth/web/passkey/begin", json={"username": "web_uv"})
    options = r.json()["options"]
    assert options["userVerification"] == "required"
    # an answer whose authenticator only saw a touch (user present, not verified)
    authn.count += 1
    auth_data = hashlib.sha256(authn.rp_id.encode()).digest() + bytes([0x01]) + authn.count.to_bytes(4, "big")
    cd = authn._client_data("webauthn.get", options["challenge"])
    sig = authn.key.sign(auth_data + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    cred = {"id": tp.b64u(authn.cred_id), "rawId": tp.b64u(authn.cred_id), "type": "public-key",
            "response": {"clientDataJSON": tp.b64u(cd), "authenticatorData": tp.b64u(auth_data),
                         "signature": tp.b64u(sig), "userHandle": None}, "clientExtensionResults": {}}
    r = pk.post("/auth/web/passkey/finish", json={"session": r.json()["session"], "credential": cred})
    assert r.status_code == 401


def test_unknown_names_get_options_too(pk):
    make_user(pk, "web_nopk")
    for name in ("web_nopk", "nobody_here"):
        r = pk.post("/auth/web/passkey/begin", json={"username": name})
        assert r.status_code == 200 and len(r.json()["options"]["allowCredentials"]) == 1
        r = pk.post("/auth/web/passkey/finish", json={"session": r.json()["session"],
                                                       "credential": tp.Authenticator().get(r.json()["options"])})
        assert r.status_code == 401


def test_the_second_factor_session_of_the_app_is_not_a_web_session(pk):
    """/auth/passkey/begin needs the password; its session cannot finish a web sign-in, nor the reverse."""
    authn = _account_with_passkey(pk, "web_mix")
    r = pk.post("/auth/passkey/begin", json={"username": "web_mix", "password": PASSWORD})
    bad = pk.post("/auth/web/passkey/finish", json={"session": r.json()["session"], "credential": authn.get(r.json()["options"])})
    assert bad.status_code == 401
    r = pk.post("/auth/web/passkey/begin", json={"username": "web_mix"})
    bad = pk.post("/auth/passkey/finish", json={"session": r.json()["session"], "credential": authn.get(r.json()["options"])})
    assert bad.status_code == 401


def test_a_web_session_never_reaches_the_storage_or_the_keys(pk):
    authn = _account_with_passkey(pk, "web_scope")
    h = _h(_web_passkey_login(pk, "web_scope", authn))
    refused = [
        ("post", "/users/me/sticks", {"name": "x"}),
        ("post", "/users/me/sticks/abc/secret", None),
        ("put", "/users/me/ssh-key", {"ssh_public_key": tp.base.SSH, "password": PASSWORD}),
        ("post", "/users/me/password", {"current_password": PASSWORD, "new_password": PASSWORD}),
        ("get", "/storage/e2ee", None),
        ("post", "/storage/sync-lock", {"holder": "h" * 16, "holder_name": "x"}),
        ("put", "/users/me/recovery-verifier", {"proof": "00" * 32}),
        ("put", "/users/me/escrow", {"blob": "x"}),
        ("post", "/auth/web/ticket", None),
    ]
    for method, path, body in refused:
        r = getattr(pk, method)(path, headers=h, **({"json": body} if body is not None else {}))
        assert r.status_code == 403 and r.json()["detail"] == "WEB_SESSION_REFUSED", (path, r.status_code, r.text)


def test_web_session_confirms_with_a_recent_sign_in(pk, monkeypatch):
    authn = _account_with_passkey(pk, "web_confirm")
    h = _h(_web_passkey_login(pk, "web_confirm", authn))
    # no password needed right after signing in
    r = pk.post("/users/me/passkeys/register/begin", json={}, headers=h)
    assert r.status_code == 200, r.text
    # ten minutes later: sign in again
    later = time.time() + main.REAUTH_WINDOW + 1
    monkeypatch.setattr(main.time, "time", lambda: later)
    r = pk.post("/users/me/passkeys/register/begin", json={}, headers=h)
    assert r.status_code == 401 and r.json()["detail"] == "REAUTH_REQUIRED"
    # a password does not stand in for it: the web UI does not ask for one
    r = pk.post("/users/me/passkeys/register/begin", json={"password": PASSWORD}, headers=h)
    assert r.json()["detail"] == "REAUTH_REQUIRED"


def test_the_app_still_needs_the_password(pk):
    make_user(pk, "web_app")
    fa._enrol(pk, "web_app")
    h = fa._login_with_code(pk, "web_app")
    assert pk.post("/users/me/passkeys/register/begin", json={}, headers=h).status_code == 401


def test_web_session_can_delete_the_account_and_a_stick(pk, monkeypatch):
    authn = _account_with_passkey(pk, "web_del")
    h = _h(_web_passkey_login(pk, "web_del", authn))
    r = pk.request("DELETE", "/storage", json={}, headers=h)
    assert r.status_code == 200 and r.json()["pending"], r.text
    r = pk.request("DELETE", "/users/me/sticks/none", json={}, headers=h)
    assert r.status_code in (404, 503)       # got past the confirmation


def test_app_hands_its_sign_in_to_the_web_ui(pk, monkeypatch):
    monkeypatch.setenv("BASE_URL", "https://cryptstorage.test/app")
    make_user(pk, "web_ticket")
    fa._enrol(pk, "web_ticket")
    h = fa._login_with_code(pk, "web_ticket")
    r = pk.post("/auth/web/ticket", headers=h)
    assert r.status_code == 200, r.text
    ticket = r.json()["ticket"]
    assert r.json()["url"] == f"https://cryptstorage.test/app/index.php#ticket={ticket}"
    r = pk.post("/auth/web/ticket/redeem", json={"ticket": ticket})
    assert r.status_code == 200 and r.json().get("refresh_token") is None
    claims = jwt.decode(r.json()["access_token"], options={"verify_signature": False})
    assert claims["scope"] == "web"
    # once only
    assert pk.post("/auth/web/ticket/redeem", json={"ticket": ticket}).status_code == 401


def test_ticket_needs_a_fresh_full_sign_in(pk, monkeypatch):
    make_user(pk, "web_stale")
    fa._enrol(pk, "web_stale")
    h = fa._login_with_code(pk, "web_stale")
    later = time.time() + main.STEP_UP_WINDOW + 1
    monkeypatch.setattr(main.time, "time", lambda: later)
    r = pk.post("/auth/web/ticket", headers=h)
    assert r.status_code == 401 and r.json()["detail"] == "TOTP_REQUIRED"


def test_ticket_expires_and_dies_with_a_password_change(pk):
    make_user(pk, "web_old")
    fa._enrol(pk, "web_old")
    with database.SessionLocal() as db:
        uid = db.query(models.User).filter_by(username="web_old").one().id
    expired = jwt.encode({"sub": uid, "type": "web-ticket", "tv": 0, "jti": "x" * 32,
                          "iat": int(time.time()) - 300, "exp": int(time.time()) - 60}, auth.SECRET_KEY, "HS256")
    assert pk.post("/auth/web/ticket/redeem", json={"ticket": expired}).status_code == 401
    ticket = auth.create_web_ticket(uid, 0)
    with database.SessionLocal() as db:
        db.query(models.User).filter_by(id=uid).one().token_version = 1
        db.commit()
    assert pk.post("/auth/web/ticket/redeem", json={"ticket": ticket}).status_code == 401
    # an access token is not a ticket
    h = fa._login_with_code(pk, "web_old")
    token = h["Authorization"].split()[1]
    assert pk.post("/auth/web/ticket/redeem", json={"ticket": token}).status_code == 401


def test_password_login_can_ask_for_a_web_session(pk):
    make_user(pk, "web_pw")
    fa._enrol(pk, "web_pw")
    r = pk.post("/auth/login", json={"username": "web_pw", "password": PASSWORD,
                                     "totp_code": fa._code("web_pw"), "web": True})
    assert r.status_code == 200 and r.json().get("refresh_token") is None
    h = _h(r)
    assert pk.get("/storage/e2ee", headers=h).status_code == 403


@pytest.mark.parametrize("path", ["/auth/web/passkey/begin"])
def test_web_passkey_off_without_configuration(pk, monkeypatch, path):
    monkeypatch.delenv("WEBAUTHN_RP_ID")
    monkeypatch.delenv("WEBAUTHN_ORIGIN")
    monkeypatch.delenv("BASE_URL", raising=False)
    assert pk.post(path, json={"username": "x"}).status_code == 503


def test_web_session_can_lock_a_stick_but_not_unlock_it(pk):
    authn = _account_with_passkey(pk, "web_stick")
    app = fa._login_with_code(pk, "web_stick")
    r = pk.post("/users/me/sticks", json={"name": "laptop"}, headers=app)
    assert r.status_code == 201, r.text
    sid = r.json()["stick_id"]
    h = _h(_web_passkey_login(pk, "web_stick", authn))
    assert pk.post(f"/users/me/sticks/{sid}/lock", headers=h).status_code == 200
    r = pk.post(f"/users/me/sticks/{sid}/unlock", json={}, headers=h)
    assert r.status_code == 403 and r.json()["detail"] == "WEB_SESSION_REFUSED"
    assert pk.post(f"/users/me/sticks/{sid}/secret", headers=app).json()["detail"] == "STICK_LOCKED"
    assert pk.post(f"/users/me/sticks/{sid}/unlock", json={}, headers=app).status_code == 200
