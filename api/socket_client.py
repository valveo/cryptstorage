"""
socket_client.py - Communicates with the host cryptdaemon via Unix socket.

Protocol: one newline-terminated JSON object per request and per response.
Signing is done by socket_auth.sign_command (shared with the daemon).
"""

import json
import logging
import os
import socket

from socket_auth import sign_command

logger = logging.getLogger(__name__)

# Directory (not the socket file) is bind-mounted into the container so the
# socket keeps working when the daemon restarts and recreates it.
SOCKET_PATH = os.getenv("CRYPTDAEMON_SOCKET", "/run/cryptdaemon/cryptdaemon.sock")
SOCKET_TIMEOUT = 60   # seconds; mounting (scrypt + docker start) can take a while
MAX_RESPONSE_SIZE = 8192


class DaemonError(Exception):
    """Raised when the daemon returns an error or is unreachable."""
    pass


_AUTH_KEY: bytes | None = None


def _get_auth_key() -> bytes:
    global _AUTH_KEY
    if _AUTH_KEY is None:
        key_hex = os.getenv("DAEMON_AUTH_KEY")
        if not key_hex:
            raise DaemonError("DAEMON_AUTH_KEY not set.")
        _AUTH_KEY = bytes.fromhex(key_hex.strip())
    return _AUTH_KEY


def _send_command(command: dict) -> dict:
    """
    Send a command to the daemon and return the response dict.
    Raises DaemonError on any failure.
    """
    signed = sign_command(command, _get_auth_key())
    payload = json.dumps(signed).encode("utf-8") + b"\n"

    response_data = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            sock.connect(SOCKET_PATH)
            sock.sendall(payload)

            while b"\n" not in response_data:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) > MAX_RESPONSE_SIZE:
                    raise DaemonError("Response from daemon too large.")

    except FileNotFoundError:
        raise DaemonError("Daemon socket not found. Is cryptdaemon running?")
    except ConnectionRefusedError:
        raise DaemonError("Daemon refused connection.")
    except PermissionError:
        raise DaemonError("No permission to use the daemon socket.")
    except socket.timeout:
        raise DaemonError("Daemon did not respond in time.")
    except OSError as e:
        raise DaemonError(f"Socket error: {e}")

    try:
        response = json.loads(response_data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise DaemonError(f"Invalid response from daemon: {e}")

    if not isinstance(response, dict) or response.get("status") != "ok":
        message = response.get("message") if isinstance(response, dict) else None
        raise DaemonError(message or "Unknown daemon error.")

    return response


# --- End-to-end encrypted mode: the daemon only manages an SFTP chroot of ciphertext ---

def daemon_e2ee_provision(user_id: str, ssh_public_key: str | None = None,
                          quota_bytes: int | None = None) -> str:
    """Create (or confirm) the user's SFTP account. Returns the system account name to log in as."""
    command = {"action": "e2ee_provision", "user_id": user_id}
    if ssh_public_key:
        command["ssh_public_key"] = ssh_public_key
    if quota_bytes is not None:
        command["quota_bytes"] = quota_bytes
    ssh_user = _send_command(command).get("ssh_user")
    if not ssh_user:
        raise DaemonError("Daemon did not return an account name.")
    return ssh_user


def daemon_e2ee_set_key(user_id: str, ssh_public_key: str) -> None:
    _send_command({"action": "e2ee_set_key", "user_id": user_id, "ssh_public_key": ssh_public_key})


def daemon_e2ee_delete(user_id: str) -> None:
    _send_command({"action": "e2ee_delete", "user_id": user_id})


def daemon_e2ee_usage(user_id: str, quota_bytes: int) -> dict:
    return _send_command({"action": "e2ee_usage", "user_id": user_id, "quota_bytes": quota_bytes})
