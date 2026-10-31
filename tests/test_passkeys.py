"""
Passkeys (WebAuthn) as the second factor, with a software authenticator that builds the same
answers a phone or a FIDO2 key sends. TOTP stays required next to passkeys (decided 2026-10-26).
"""
import base64
import hashlib
import json
import os

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import database
import models
import passkeys

import test_api_security as base
import test_factors_and_delays as fa
from test_api_security import PASSWORD, bearer, make_user

client = base.client      # reuse the fixtures
c = fa.c

ORIGIN = "https://cryptstorage.test"
RP_ID = "cryptstorage.test"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Authenticator:
    """One passkey: an EC P-256 key, as phones and FIDO2 keys use (COSE alg -7)."""

    def __init__(self, rp_id=RP_ID, origin=ORIGIN):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0
        self.rp_id, self.origin = rp_id, origin

    def _client_data(self, typ, challenge):
        return json.dumps({"type": typ, "challenge": challenge, "origin": self.origin,
                           "crossOrigin": False}).encode()

    def create(self, options):
        assert options["rp"]["id"] == RP_ID
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth_data = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big")
                     + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(self._client_data("webauthn.create", options["challenge"])),
                             "attestationObject": b64u(att), "transports": ["internal", "hybrid"]},
                "clientExtensionResults": {}}

    def get(self, options, cred_id=None):
        self.count += 1
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05]) + self.count.to_bytes(4, "big")
        cd = self._client_data("webauthn.get", options["challenge"])
        sig = self.key.sign(auth_data + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        cid = cred_id or self.cred_id
        return {"id": b64u(cid), "rawId": b64u(cid), "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig), "userHandle": None},
                "clientExtensionResults": {}}


@pytest.fixture
def pk(c, monkeypatch):
    monkeypatch.setenv("WEBAUTHN_RP_ID", RP_ID)
    monkeypatch.setenv("WEBAUTHN_ORIGIN", ORIGIN)
    return c


def _add_passkey(c, name, auth=None, h=None):
    auth = auth or Authenticator()
    h = h or fa._login_with_code(c, name)
    r = c.post("/users/me/passkeys/register/begin", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 200, r.text
    r = c.post("/users/me/passkeys/register/finish",
               json={"session": r.json()["session"], "name": "iPhone", "credential": auth.create(r.json()["options"])},
               headers=h)
    assert r.status_code == 201, r.text
    return auth


def _passkey_login(c, name, auth):
    r = c.post("/auth/passkey/begin", json={"username": name, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return c.post("/auth/passkey/finish", json={"session": r.json()["session"], "credential": auth.get(r.json()["options"])})


def test_register_and_log_in_with_a_passkey(pk):
    make_user(pk, "pk_alice")
    fa._enrol(pk, "pk_alice")
    auth = _add_passkey(pk, "pk_alice")
    assert any("passkey" in what for _, what in pk.notices)

    r = _passkey_login(pk, "pk_alice", auth)
    assert r.status_code == 200, r.text
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    # the passkey counts as the second factor for sensitive actions right after login, like a code
    r = pk.post("/users/me/password", json={"current_password": PASSWORD, "new_password": PASSWORD}, headers=h)
    assert r.status_code == 200, r.text
    with database.SessionLocal() as db:
        cred = db.query(models.WebAuthnCredential).one()
        assert cred.sign_count == 1 and cred.last_used_at is not None


def test_passkey_needs_the_authenticator_app_first(pk):
    make_user(pk, "pk_nototp")
    r = pk.post("/users/me/passkeys/register/begin", json={"password": PASSWORD}, headers=bearer(pk, "pk_nototp"))
    assert r.status_code == 409


def test_adding_a_passkey_needs_password_and_second_factor(pk):
    make_user(pk, "pk_step")
    fa._enrol(pk, "pk_step")
    h = fa._login_with_code(pk, "pk_step")
    assert pk.post("/users/me/passkeys/register/begin", json={"password": "wrong" * 4}, headers=h).status_code == 401


def test_begin_does_not_work_without_the_password_or_a_passkey(pk):
    make_user(pk, "pk_begin")
    fa._enrol(pk, "pk_begin")
    assert pk.post("/auth/passkey/begin", json={"username": "pk_begin", "password": "x" * 20}).status_code == 401
    r = pk.post("/auth/passkey/begin", json={"username": "pk_begin", "password": PASSWORD})
    assert r.status_code == 404 and r.json()["detail"] == "NO_PASSKEY"


def test_wrong_key_wrong_origin_and_replay_are_refused(pk):
    make_user(pk, "pk_bad")
    fa._enrol(pk, "pk_bad")
    auth = _add_passkey(pk, "pk_bad")

    # a different key claiming the registered credential id
    other = Authenticator()
    r = pk.post("/auth/passkey/begin", json={"username": "pk_bad", "password": PASSWORD}).json()
    bad = other.get(r["options"], cred_id=auth.cred_id)
    assert pk.post("/auth/passkey/finish", json={"session": r["session"], "credential": bad}).status_code == 401

    # a phishing site: the browser puts its own origin in the signed data
    phish = Authenticator(origin="https://cryptstorage-login.example")
    phish.key, phish.cred_id = auth.key, auth.cred_id
    r = pk.post("/auth/passkey/begin", json={"username": "pk_bad", "password": PASSWORD}).json()
    assert pk.post("/auth/passkey/finish", json={"session": r["session"], "credential": phish.get(r["options"])}).status_code == 401

    # one session, one login
    r = pk.post("/auth/passkey/begin", json={"username": "pk_bad", "password": PASSWORD}).json()
    answer = auth.get(r["options"])
    assert pk.post("/auth/passkey/finish", json={"session": r["session"], "credential": answer}).status_code == 200
    assert pk.post("/auth/passkey/finish", json={"session": r["session"], "credential": answer}).status_code == 401


def test_a_passkey_of_another_account_does_not_log_in(pk):
    make_user(pk, "pk_one")
    make_user(pk, "pk_two")
    fa._enrol(pk, "pk_one")
    fa._enrol(pk, "pk_two")
    _add_passkey(pk, "pk_one")
    auth_two = _add_passkey(pk, "pk_two")
    r = pk.post("/auth/passkey/begin", json={"username": "pk_one", "password": PASSWORD}).json()
    assert pk.post("/auth/passkey/finish", json={"session": r["session"], "credential": auth_two.get(r["options"])}).status_code == 401


def test_list_remove_and_totp_stays_required(pk):
    make_user(pk, "pk_list")
    fa._enrol(pk, "pk_list")
    _add_passkey(pk, "pk_list")
    h = fa._login_with_code(pk, "pk_list")
    keys = pk.get("/users/me/passkeys", headers=h).json()
    assert [k["name"] for k in keys] == ["iPhone"]

    # TOTP cannot be switched off while a passkey depends on it as the fallback
    r = pk.post("/users/me/totp/disable", json={"password": PASSWORD, "code": fa._code("pk_list")}, headers=h)
    assert r.status_code == 409

    r = pk.request("DELETE", f"/users/me/passkeys/{keys[0]['id']}", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 200, r.text
    assert pk.get("/users/me/passkeys", headers=h).json() == []


def test_passkeys_off_without_configuration(pk, monkeypatch):
    monkeypatch.delenv("WEBAUTHN_RP_ID")
    monkeypatch.delenv("WEBAUTHN_ORIGIN")
    monkeypatch.delenv("BASE_URL", raising=False)
    make_user(pk, "pk_off")
    assert pk.post("/auth/passkey/begin", json={"username": "pk_off", "password": PASSWORD}).status_code == 503


def test_rp_defaults_come_from_base_url(monkeypatch):
    monkeypatch.delenv("WEBAUTHN_RP_ID", raising=False)
    monkeypatch.delenv("WEBAUTHN_ORIGIN", raising=False)
    monkeypatch.setenv("BASE_URL", "https://files.example.eu/")
    assert passkeys.rp_id() == "files.example.eu"
    assert passkeys.origins() == ["https://files.example.eu"]
    assert passkeys.approve_url() == "https://files.example.eu/passkey-approve.php"


def test_begin_tells_the_app_where_to_approve(pk, monkeypatch):
    monkeypatch.setenv("BASE_URL", "https://cryptstorage.test/storage/")
    make_user(pk, "pk_app")
    fa._enrol(pk, "pk_app")
    _add_passkey(pk, "pk_app")
    r = pk.post("/auth/passkey/begin", json={"username": "pk_app", "password": PASSWORD})
    assert r.json()["approve_url"] == "https://cryptstorage.test/storage/passkey-approve.php"


def test_account_deletion_removes_passkeys(pk, monkeypatch):
    monkeypatch.setenv("CHANGE_DELAY_HOURS", "0")
    make_user(pk, "pk_gone")
    fa._enrol(pk, "pk_gone")
    _add_passkey(pk, "pk_gone")
    uid = fa._user("pk_gone").id
    h = fa._login_with_code(pk, "pk_gone")
    r = pk.request("DELETE", "/storage", json={"password": PASSWORD}, headers=h)
    assert r.status_code == 200, r.text
    with database.SessionLocal() as db:
        assert db.query(models.User).filter_by(id=uid).first() is None
        assert db.query(models.WebAuthnCredential).filter_by(user_id=uid).count() == 0
