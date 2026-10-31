"""
sftpgo_client.py - Manages the users of the SFTPGo service that stores the ciphertext.

The server only stores ciphertext: no master key, no gocryptfs, no container per user. Each user is a
virtual SFTPGo user (public-key login only, no shell, no forwarding) whose root is a directory of its own.
SFTPGo enforces the quota. Nothing here touches system accounts, so moving the service to another host
means copying the data directory and the SFTPGo database (or recreating the users from the API's).

Layout (the user name is derived from the user id, so it never contains user input):

    <DATA_BASE>/<acct>/        the user's home and SFTP root, owned by the SFTPGo service user
    <DATA_BASE>/<acct>/data/   the ciphertext (the client mounts /data)

SFTPGo's REST API is only reachable from this host (127.0.0.1); the admin account is created at the
first start from the environment of the service (ansible / deploy script).
"""

import hashlib
import json
import logging
import os
import re
import shutil
import threading
import time
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

API_URL = os.getenv("SFTPGO_API_URL", "http://127.0.0.1:8080").rstrip("/")
ADMIN_USER = os.getenv("SFTPGO_ADMIN_USER", "cryptstorage")
DATA_BASE = os.getenv("CRYPTSTORAGE_DATA_BASE", "/srv/cryptstorage")
# The service user inside the SFTPGo container / of the SFTPGo package; the data must belong to it.
DATA_UID = int(os.getenv("SFTPGO_UID", os.getuid()))
DATA_GID = int(os.getenv("SFTPGO_GID", os.getgid()))
DEFAULT_QUOTA = 10 * 1024 ** 3
TIMEOUT = 15

_ACCOUNT = re.compile(r"sd[0-9a-f]{12}")

# Public-key login over SFTP only: everything else is switched off for every user.
_DENIED_LOGIN = ["password", "password-over-SSH", "keyboard-interactive", "publickey+password",
                 "publickey+keyboard-interactive", "TLSCertificate", "TLSCertificate+password"]
_DENIED_PROTOCOLS = ["FTP", "DAV", "HTTP"]


class ProvisionError(Exception):
    pass


def account_name(user_id: str) -> str:
    """Stable, short, collision-resistant user name."""
    return "sd" + hashlib.sha256(b"secdisk/account/v1\x00" + user_id.encode()).hexdigest()[:12]


def _home(acct: str) -> str:
    assert _ACCOUNT.fullmatch(acct)
    return os.path.join(DATA_BASE, acct)


def _admin_password() -> str:
    path = os.getenv("SFTPGO_ADMIN_PASSWORD_FILE")
    if path:
        with open(path) as f:
            return f.read().strip()
    pw = os.getenv("SFTPGO_ADMIN_PASSWORD")
    if not pw:
        raise ProvisionError("SFTPGO_ADMIN_PASSWORD(_FILE) is not set")
    return pw


_token = {"value": None, "expires": 0.0}
_token_lock = threading.Lock()


def _get_token(force: bool = False) -> str:
    with _token_lock:
        if force or not _token["value"] or time.time() > _token["expires"]:
            import base64
            basic = base64.b64encode(f"{ADMIN_USER}:{_admin_password()}".encode()).decode()
            req = urllib.request.Request(f"{API_URL}/api/v2/token", headers={"Authorization": f"Basic {basic}"})
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                    body = json.load(r)
            except (urllib.error.URLError, OSError, ValueError) as e:
                raise ProvisionError(f"SFTPGo login failed: {e}")
            _token["value"] = body["access_token"]
            _token["expires"] = time.time() + 600      # tokens last 20 minutes
        return _token["value"]


def _call(method: str, path: str, body: dict | None = None, ok_missing: bool = False):
    """One REST call; a rejected token is renewed once. Returns the decoded JSON ({} if empty)."""
    for attempt in (0, 1):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{API_URL}/api/v2{path}", data=data, method=method, headers={
            "Authorization": f"Bearer {_get_token(force=attempt == 1)}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 401 and attempt == 0:
                continue
            if e.code == 404 and ok_missing:
                return None
            raise ProvisionError(f"SFTPGo {method} {path} -> {e.code}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ProvisionError(f"SFTPGo {method} {path} failed: {e}")
    raise ProvisionError("SFTPGo refused the token")


def _user_doc(acct: str, ssh_public_key: str | None, quota_bytes: int) -> dict:
    return {
        "status": 1, "username": acct, "home_dir": _home(acct), "uid": DATA_UID, "gid": DATA_GID,
        "public_keys": [ssh_public_key] if ssh_public_key else [],
        "permissions": {"/": ["*"]},
        "quota_size": quota_bytes, "quota_files": 0,
        "filters": {"denied_login_methods": _DENIED_LOGIN, "denied_protocols": _DENIED_PROTOCOLS},
    }


def _make_dirs(acct: str) -> None:
    home = _home(acct)
    data = os.path.join(home, "data")
    os.makedirs(data, mode=0o700, exist_ok=True)
    try:
        for d in (home, data):
            os.chown(d, DATA_UID, DATA_GID)
            os.chmod(d, 0o700)
    except PermissionError as e:
        raise ProvisionError(f"could not set owners: {e}")


def provision(user_id: str, ssh_public_key: str | None, quota_bytes: int | None = None) -> str:
    """Create the user (or refresh its settings). Idempotent. Returns the user name."""
    acct = account_name(user_id)
    quota = quota_bytes if quota_bytes else DEFAULT_QUOTA     # 0 would mean "tracked but unlimited"
    existing = _call("GET", f"/users/{acct}", ok_missing=True)
    doc = _user_doc(acct, ssh_public_key, quota)
    if existing is None:
        _make_dirs(acct)
        _call("POST", "/users", doc)
    else:
        if not ssh_public_key:                     # keep the registered key when only the quota changes
            doc["public_keys"] = existing.get("public_keys", [])
        _make_dirs(acct)
        _call("PUT", f"/users/{acct}", doc)
    logger.info(f"Provisioned SFTP user {acct}.")
    return acct


def set_key(user_id: str, ssh_public_key: str) -> None:
    acct = account_name(user_id)
    user = _call("GET", f"/users/{acct}", ok_missing=True)
    if user is None:
        raise ProvisionError("storage does not exist")
    _call("PUT", f"/users/{acct}", _user_doc(acct, ssh_public_key, user.get("quota_size") or DEFAULT_QUOTA))


def delete(user_id: str) -> None:
    """Remove the user first (no more logins), then the data. Idempotent."""
    acct = account_name(user_id)
    _call("DELETE", f"/users/{acct}", ok_missing=True)
    home = _home(acct)
    if os.path.isdir(home) and not os.path.islink(home):
        shutil.rmtree(home)


def usage_bytes(user_id: str) -> int:
    acct = account_name(user_id)
    user = _call("GET", f"/users/{acct}", ok_missing=True)
    return int(user.get("used_quota_size", 0)) if user else 0
