"""Key derivation version 2 (api/kdf.py): the per-server salt, and moving accounts over from version 1."""
import database
import kdf
import models
import test_api_security as base
from test_api_security import SSH

client = base.client      # reuse the fixture

V1 = "a1" * 32            # login keys are 64 hex; which version made them does not matter to the server
V2 = "b2" * 32


def register(c, name, key, version=None):
    body = {"username": name, "email": f"{name}@example.com", "password": key, "ssh_public_key": SSH}
    if version:
        body["kdf_version"] = version
    assert c.post("/auth/register", json=body).status_code == 201
    with database.SessionLocal() as db:
        db.query(models.User).filter_by(username=name).one().email_verified = True
        db.commit()


def login(c, name, key, legacy=None):
    body = {"username": name, "password": key}
    if legacy:
        body["legacy_password"] = legacy
    return c.post("/auth/login", json=body)


def me(c, token):
    return c.get("/users/me", headers={"Authorization": f"Bearer {token}"}).json()


def test_salt_is_created_once_and_published(client):
    a = client.get("/server-info").json()
    kdf._reset_cache_for_tests()
    b = client.get("/server-info").json()
    assert a["kdf_version"] == 2 and len(a["kdf_salt"]) == 64
    assert a["kdf_salt"] == b["kdf_salt"]                      # read back from the database, not made again
    with database.SessionLocal() as db:
        assert db.get(models.ServerSetting, "kdf_salt").value == a["kdf_salt"]


def test_old_client_keeps_working_on_a_version_1_account(client):
    register(client, "kdf_old", V1)                              # no kdf_version: an older client
    r = login(client, "kdf_old", V1)
    assert r.status_code == 200
    assert me(client, r.json()["access_token"])["kdf_version"] == 1


def test_new_client_logs_in_to_a_version_1_account_with_its_legacy_key(client):
    register(client, "kdf_mix", V1)
    assert login(client, "kdf_mix", V2).status_code == 401       # the v2 key alone is not the account's key
    r = login(client, "kdf_mix", V2, legacy=V1)
    assert r.status_code == 200
    assert me(client, r.json()["access_token"])["kdf_version"] == 1


def test_upgrade_moves_the_account_and_the_old_key_stops_working(client):
    register(client, "kdf_up", V1)
    tok = login(client, "kdf_up", V2, legacy=V1).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    bad = client.post("/users/me/kdf-upgrade", json={"current_password": "c3" * 32, "new_password": V2}, headers=h)
    assert bad.status_code == 401
    r = client.post("/users/me/kdf-upgrade", json={"current_password": V1, "new_password": V2}, headers=h)
    assert r.status_code == 200, r.text
    assert me(client, tok)["kdf_version"] == 2                  # same session goes on
    assert login(client, "kdf_up", V1).status_code == 401       # an older client is now refused
    assert login(client, "kdf_up", "d4" * 32, legacy=V1).status_code == 401   # the legacy key is ignored
    assert login(client, "kdf_up", V2, legacy=V1).status_code == 200
    again = client.post("/users/me/kdf-upgrade", json={"current_password": V2, "new_password": V2}, headers=h)
    assert again.status_code == 200 and again.json()["message"] == "Already up to date."


def test_new_account_password_change_and_recovery_record_the_version(client):
    register(client, "kdf_new", V2, version=2)
    tok = login(client, "kdf_new", V2).json()["access_token"]
    assert me(client, tok)["kdf_version"] == 2
    h = {"Authorization": f"Bearer {tok}"}
    # an older client changing the password writes a version 1 key
    r = client.post("/users/me/password", json={"current_password": V2, "new_password": V1}, headers=h)
    assert r.status_code == 200
    r = login(client, "kdf_new", V2, legacy=V1)
    assert r.status_code == 200 and me(client, r.json()["access_token"])["kdf_version"] == 1
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.post("/users/me/password", json={"current_password": V1, "new_password": V2, "kdf_version": 2},
                       headers=h).status_code == 200
    assert login(client, "kdf_new", V2).status_code == 200


def test_version_is_validated(client):
    body = {"username": "kdf_bad", "email": "kdf_bad@example.com", "password": V2, "kdf_version": 3}
    assert client.post("/auth/register", json=body).status_code == 422


def test_account_deletion_removes_the_version_row(client, monkeypatch):
    import pending
    monkeypatch.setattr(pending, "daemon_e2ee_delete", lambda user: None)
    register(client, "kdf_del", V2, version=2)
    with database.SessionLocal() as db:
        uid = db.query(models.User).filter_by(username="kdf_del").one().id
        assert db.get(models.UserKdf, uid).version == 2
    tok = login(client, "kdf_del", V2).json()["access_token"]
    r = client.request("DELETE", "/storage", json={"password": V2}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    with database.SessionLocal() as db:
        assert db.get(models.UserKdf, uid) is None
