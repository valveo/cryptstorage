"""
handler.py - Validates a command and carries it out.

The daemon manages the SFTP accounts that hold users' ciphertext (sftpgo_client.py). It never
receives a key or a password: the files are encrypted by the client (docs/design-e2ee.md).
"""

import logging
import threading

from validator import validate_command, ValidationError
import sftpgo_client

_audit = logging.getLogger("cryptstorage.daemon.audit")
logger = logging.getLogger(__name__)

# The daemon handles connections in parallel. Commands for the SAME user must not overlap
# (provision racing delete); different users run concurrently.
_locks_guard = threading.Lock()
_user_locks: dict[str, threading.Lock] = {}


def _user_lock(user_id: str) -> threading.Lock:
    with _locks_guard:
        return _user_locks.setdefault(user_id, threading.Lock())


def handle_command(command: dict) -> dict:
    """
    Validate and execute a command.

    Returns: {"status": "ok", ...} or {"status": "error", "message": "..."}
    """
    try:
        validate_command(command)
    except ValidationError as e:
        logger.warning(f"Validation failed: {e}")
        return {"status": "error", "message": str(e)}

    action  = command["action"]
    user_id = command["user_id"]

    try:
        with _user_lock(user_id):
            return _run(action, user_id, command)
    except sftpgo_client.ProvisionError as e:
        logger.error(f"Command '{action}' failed for user '{user_id}': {e}")
        return {"status": "error", "message": str(e)}


def _run(action: str, user_id: str, command: dict) -> dict:
    _audit.warning(f"DAEMON_AUDIT action={action} user={user_id}")
    if action == "e2ee_provision":
        acct = sftpgo_client.provision(user_id, command.get("ssh_public_key"), command.get("quota_bytes"))
        return {"status": "ok", "ssh_user": acct}
    if action == "e2ee_set_key":
        sftpgo_client.set_key(user_id, command["ssh_public_key"])
        return {"status": "ok", "ssh_user": sftpgo_client.account_name(user_id)}
    if action == "e2ee_delete":
        sftpgo_client.delete(user_id)
        return {"status": "ok"}
    if action == "e2ee_usage":
        used = sftpgo_client.usage_bytes(user_id)
        quota = command["quota_bytes"]
        return {"status": "ok", "used_bytes": used, "quota_bytes": quota,
                "free_bytes": max(0, quota - used),
                "percent": round(used / quota * 100, 1) if quota > 0 else 0}
    return {"status": "error", "message": f"Unknown action: {action}"}
