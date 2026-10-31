"""Phase 2 security behaviour of the API (no daemon needed)."""
import bcrypt
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi.testclient import TestClient

import audit
import auth
import config
import database
import main
import models
import pending
import ssh_keys
from throttle import FailureTracker

PASSWORD = "correct horse battery staple"
SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@host"


def _openssh_public(key) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main.limiter, "enabled", False)       # slowapi's own per-minute limits
    monkeypatch.setattr(main, "_login_by_ip_user", FailureTracker(5, 900))
    monkeypatch.setattr(main, "_login_by_user", FailureTracker(30, 3600))
    monkeypatch.setattr(main, "_pw_failures", FailureTracker(5, 900))
    notices = []
    notify = lambda email, user, what, action="": notices.append((user, what))   # noqa: E731
    monkeypatch.setattr(main, "send_security_notice_email", notify)
    monkeypatch.setattr(pending, "send_security_notice_email", notify)
    monkeypatch.setattr(main, "send_verification_email", lambda *a, **k: None)
    monkeypatch.setattr(main, "daemon_e2ee_provision", lambda *a, **k: "sdtest0000000")
    monkeypatch.setattr(pending, "daemon_e2ee_provision", lambda *a, **k: "sdtest0000000")
    enrol_codes = []
    monkeypatch.setattr(main, "send_enrolment_code_email", lambda email, user, code: enrol_codes.append(code))
    with TestClient(main.app) as c:
        c.notices = notices
        c.enrol_codes = enrol_codes
        yield c


def make_user(client, name, ssh=SSH):
    r = client.post("/auth/register", json={
        "username": name, "email": f"{name}@example.com", "password": PASSWORD, "ssh_public_key": ssh})
    assert r.status_code == 201, r.text
    with database.SessionLocal() as db:
        db.query(models.User).filter_by(username=name).one().email_verified = True
        db.commit()


def login(client, name, password=PASSWORD):
    return client.post("/auth/login", json={"username": name, "password": password})


def bearer(client, name):
    return {"Authorization": f"Bearer {login(client, name).json()['access_token']}"}


# ---------- brute force ----------

def test_login_is_blocked_after_five_failures(client):
    make_user(client, "thr_user")
    for _ in range(5):
        assert login(client, "thr_user", "wrong password!!").status_code == 401
    blocked = login(client, "thr_user")                       # even the right password
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0


def test_unknown_users_are_throttled_the_same_way(client):
    for _ in range(5):
        assert login(client, "no_such_user").status_code == 401
    assert login(client, "no_such_user").status_code == 429    # no enumeration via lockout


def test_successful_login_resets_the_counter(client):
    make_user(client, "reset_user")
    for _ in range(3):
        login(client, "reset_user", "wrong password!!")
    assert login(client, "reset_user").status_code == 200
    for _ in range(3):
        assert login(client, "reset_user", "wrong password!!").status_code == 401


def test_unknown_user_still_costs_a_password_hash(client, monkeypatch):
    seen = []
    real = main.verify_password
    monkeypatch.setattr(main, "verify_password", lambda p, h: (seen.append(h), real(p, h))[1])
    login(client, "ghost_user")
    assert seen == [auth.DUMMY_HASH]


# ---------- input rules ----------

@pytest.mark.parametrize("body,field", [
    ({"username": "root"}, "reserved name"),
    ({"username": "Admin"}, "reserved name, any case"),
    ({"password": "x" * 129}, "password too long"),
    ({"password": "short"}, "password too short"),
    ({"username": "alicecooper", "password": "my-ALICEcooper-123"}, "password contains username"),
    ({"ssh_public_key": "ssh-ed25519 AAAA\nssh-rsa AAAA"}, "key with newline"),
])
def test_registration_rejects(client, body, field):
    payload = {"username": "newuser", "email": "n@example.com", "password": PASSWORD, "ssh_public_key": SSH}
    payload.update(body)
    assert client.post("/auth/register", json=payload).status_code == 422, field


def test_login_input_is_bounded(client):
    assert client.post("/auth/login", json={"username": "u" * 65, "password": "x"}).status_code == 422
    assert client.post("/auth/login", json={"username": "u", "password": "x" * 129}).status_code == 422


# ---------- SSH key change ----------

def test_ssh_key_change_needs_the_password_and_notifies(client):
    make_user(client, "key_user")
    h = bearer(client, "key_user")
    new_key = _openssh_public(ed25519.Ed25519PrivateKey.generate())

    assert client.put("/users/me/ssh-key", json={"ssh_public_key": new_key}, headers=h).status_code == 422
    assert client.put("/users/me/ssh-key", json={"ssh_public_key": new_key, "password": "wrong password!!"},
                      headers=h).status_code == 401
    r = client.put("/users/me/ssh-key", json={"ssh_public_key": new_key, "password": PASSWORD}, headers=h)
    assert r.status_code == 200, r.text
    with database.SessionLocal() as db:
        assert db.query(models.User).filter_by(username="key_user").one().ssh_public_key == new_key
    assert client.notices and client.notices[-1][0] == "key_user"


def test_password_guessing_via_ssh_key_endpoint_is_throttled(client):
    make_user(client, "guess_user")
    h = bearer(client, "guess_user")
    body = {"ssh_public_key": SSH, "password": "wrong password!!"}
    for _ in range(5):
        assert client.put("/users/me/ssh-key", json=body, headers=h).status_code == 401
    body["password"] = PASSWORD
    assert client.put("/users/me/ssh-key", json=body, headers=h).status_code == 429


# ---------- sessions ----------

def test_password_change_invalidates_existing_access_tokens(client):
    make_user(client, "pw_user")
    old = bearer(client, "pw_user")
    assert client.get("/users/me", headers=old).status_code == 200

    r = client.post("/users/me/password", headers=old,
                    json={"current_password": PASSWORD, "new_password": "another long passphrase 42"})
    assert r.status_code == 200, r.text

    assert client.get("/users/me", headers=old).status_code == 401
    assert login(client, "pw_user").status_code == 401
    fresh = login(client, "pw_user", "another long passphrase 42")
    assert fresh.status_code == 200
    ok = {"Authorization": f"Bearer {fresh.json()['access_token']}"}
    assert client.get("/users/me", headers=ok).status_code == 200
    assert any("password" in what for _, what in client.notices)


def test_legacy_bcrypt_hash_is_upgraded_to_argon2(client):
    make_user(client, "old_user")
    with database.SessionLocal() as db:
        u = db.query(models.User).filter_by(username="old_user").one()
        u.password_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
        db.commit()
    assert login(client, "old_user").status_code == 200
    with database.SessionLocal() as db:
        assert db.query(models.User).filter_by(username="old_user").one().password_hash.startswith("$argon2")
    assert login(client, "old_user").status_code == 200


def test_tokens_without_required_claims_or_with_alg_none_are_rejected():
    uid = "11111111-1111-1111-1111-111111111111"
    assert auth.decode_access_token(auth.create_access_token(uid)) == uid
    no_iat = jwt.encode({"sub": uid, "type": "access", "exp": 9999999999}, auth.SECRET_KEY, algorithm="HS256")
    assert auth.decode_access_token(no_iat) is None
    unsigned = jwt.encode({"sub": uid, "type": "access", "exp": 9999999999, "iat": 1}, None, algorithm="none")
    assert auth.decode_access_token(unsigned) is None
    wrong_type = jwt.encode({"sub": uid, "type": "refresh", "exp": 9999999999, "iat": 1},
                            auth.SECRET_KEY, algorithm="HS256")
    assert auth.decode_access_token(wrong_type) is None


# ---------- exposure ----------

def test_docs_are_off_and_cors_is_not_enabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    r = client.get("/health", headers={"Origin": "https://evil.example"})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in r.headers


# ---------- client IP ----------

class _Req:
    def __init__(self, peer, xff=None):
        self.client = types_ns(peer)
        self.headers = {"X-Forwarded-For": xff} if xff is not None else {}


def types_ns(host):
    import types
    return types.SimpleNamespace(host=host)


@pytest.fixture
def proxies(monkeypatch):
    monkeypatch.setattr(audit, "_TRUSTED_PROXIES", audit._parse_networks("127.0.0.0/8,172.16.0.0/12"))


@pytest.mark.parametrize("peer,xff,expected", [
    ("203.0.113.9", "198.51.100.1", "203.0.113.9"),                # not a proxy: header ignored
    ("172.18.0.3", "198.51.100.1", "198.51.100.1"),                # proxy sets the client address
    ("172.18.0.3", "6.6.6.6, 198.51.100.1", "198.51.100.1"),       # client prepends junk: rightmost wins
    ("172.18.0.3", "198.51.100.1, 172.18.0.2", "198.51.100.1"),    # skips our own proxy hops
    ("172.18.0.3", "not-an-ip", "172.18.0.3"),                     # malformed is never trusted
    ("172.18.0.3", "198.51.100.1\nX: y", "172.18.0.3"),            # no log injection through the header
    ("172.18.0.3", None, "172.18.0.3"),
])
def test_client_ip(proxies, peer, xff, expected):
    assert audit.get_client_ip(_Req(peer, xff)) == expected


def test_audit_log_neutralizes_control_characters():
    assert audit._clean("a\nb\x00c\r") == "a?b?c?"
    assert len(audit._clean("x" * 1000)) == 500


# ---------- fail-fast configuration ----------

def test_config_rejects_missing_placeholder_short_and_non_hex(monkeypatch):
    monkeypatch.delenv("X_SECRET", raising=False)
    with pytest.raises(config.ConfigError, match="not set"):
        config.require("X_SECRET")
    monkeypatch.setenv("X_SECRET", "CHANGE_ME_very_long_random_string_here_please")
    with pytest.raises(config.ConfigError, match="placeholder"):
        config.require("X_SECRET", min_len=32)
    monkeypatch.setenv("X_SECRET", "short")
    with pytest.raises(config.ConfigError, match="at least 32"):
        config.require("X_SECRET", min_len=32)
    monkeypatch.setenv("X_SECRET", "zz" * 32)
    with pytest.raises(config.ConfigError, match="hex"):
        config.require("X_SECRET", hex_bytes=32)
    monkeypatch.setenv("X_SECRET", "ab" * 16)
    with pytest.raises(config.ConfigError, match="at least 32 bytes"):
        config.require("X_SECRET", hex_bytes=32)


def test_validate_catches_each_required_setting(monkeypatch):
    config.validate()                                            # the test environment is valid
    for name in ("JWT_SECRET_KEY", "REFRESH_TOKEN_HMAC_KEY", "DAEMON_AUTH_KEY", "DATABASE_URL"):
        monkeypatch.delenv(name)
        with pytest.raises(config.ConfigError, match=name):
            config.validate()
        monkeypatch.undo()


# ---------- SSH key validation ----------

def test_ssh_key_validation():
    assert ssh_keys.validate_ssh_public_key(SSH + "\n") == SSH
    rsa3072 = _openssh_public(rsa.generate_private_key(65537, 3072))
    assert ssh_keys.validate_ssh_public_key(rsa3072).startswith("ssh-rsa ")
    for bad in (
        _openssh_public(rsa.generate_private_key(65537, 2048)),           # too small
        'command="rm -rf /" ' + SSH,                                      # options
        SSH + "\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvilEvilEvilEvilEvilEvilEvilEvilEvil1",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLs",   # truncated blob
        "ssh-rsa " + SSH.split()[1],                                      # type does not match blob
        "ssh-dss AAAAB3NzaC1kc3MAAACBAPlenglenglenglenglen",
        SSH + " " + "x" * 3000,
    ):
        with pytest.raises(ssh_keys.InvalidSSHKey):
            ssh_keys.validate_ssh_public_key(bad)


# ---------- SMTP ----------

def test_smtp_starttls_verifies_certificates(monkeypatch):
    import ssl
    import email_verification as ev

    seen = {}

    class FakeSMTP:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self): pass
        def starttls(self, context=None): seen["context"] = context
        def login(self, *a): pass
        def sendmail(self, *a): pass

    monkeypatch.setattr(ev, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(ev.smtplib, "SMTP", FakeSMTP)
    ev.send_security_notice_email("a@example.com", "alice", "something changed")
    ctx = seen["context"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


def test_smtp_port_465_uses_implicit_tls_and_verifies(monkeypatch):
    import ssl
    import email_verification as ev

    seen = {}

    class FakeSMTPSSL:
        def __init__(self, host, port, timeout=None, context=None):
            seen["port"], seen["context"] = port, context
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def ehlo(self): pass
        def login(self, *a): seen["login"] = a
        def sendmail(self, *a): seen["sent"] = True

    monkeypatch.setattr(ev, "SMTP_HOST", "ssl0.example.net")
    monkeypatch.setattr(ev, "SMTP_PORT", 465)
    monkeypatch.setattr(ev, "SMTP_SECURITY", "ssl")
    monkeypatch.setattr(ev, "SMTP_USER", "info@example.net")
    monkeypatch.setattr(ev, "SMTP_PASSWORD", "pw")
    monkeypatch.setattr(ev.smtplib, "SMTP_SSL", FakeSMTPSSL)
    monkeypatch.setattr(ev.smtplib, "SMTP", lambda *a, **k: pytest.fail("plain SMTP used on 465"))
    ev.send_security_notice_email("a@example.com", "alice", "something changed")
    assert seen["port"] == 465 and seen["sent"] and seen["login"] == ("info@example.net", "pw")
    assert seen["context"].verify_mode == ssl.CERT_REQUIRED and seen["context"].check_hostname
