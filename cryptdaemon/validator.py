"""
validator.py - Validates commands received from the API container.

Ensures all commands are well-formed and contain only safe values
before any system operations are performed.
"""

import re
import logging

logger = logging.getLogger(__name__)

# Allowed actions: the daemon only manages an SFTP chroot of ciphertext and never receives a key
# (docs/design-e2ee.md).
VALID_ACTIONS = {"e2ee_provision", "e2ee_set_key", "e2ee_delete", "e2ee_usage"}

# NOTE: all patterns are used with fullmatch(). With match() and a trailing "$",
# Python would accept a value followed by a single newline ("bob\n").

# user_id: only alphanumeric and underscores, 3-32 chars
USER_ID_PATTERN = re.compile(r"[a-zA-Z0-9_]{3,32}")

# Names that look official or collide with system accounts.
# Must match api/schemas.py RESERVED_USERNAMES (a test enforces it).
RESERVED_USER_IDS = frozenset({
    "root", "admin", "administrator", "sshd", "daemon", "bin", "sys", "sync",
    "games", "man", "lp", "mail", "news", "uucp", "proxy", "nobody", "www",
    "operator", "ftp", "backup", "list", "irc", "gnats", "systemd", "support",
    "security", "postmaster", "abuse", "cryptstorage", "cryptdaemon", "cryptuser",
})

# ssh_public_key: single-line OpenSSH public key (type, base64 blob, optional comment).
# No newlines or option prefixes (e.g. command="...") can get through.
SSH_KEY_MAX_LEN = 2048
SSH_KEY_PATTERN = re.compile(
    r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) "
    r"[A-Za-z0-9+/]{20,}={0,3}"
    r"(?: [\x21-\x7e][\x20-\x7e]{0,127})?"
)

# Exactly which fields each action may carry ("auth", "ts" and "nonce" are added by socket_auth.py).
_BASE_FIELDS = {"action", "user_id", "auth", "ts", "nonce"}
ALLOWED_FIELDS = {
    "e2ee_provision": _BASE_FIELDS | {"ssh_public_key", "quota_bytes"},
    "e2ee_set_key":   _BASE_FIELDS | {"ssh_public_key"},
    "e2ee_delete":    _BASE_FIELDS,
    "e2ee_usage":     _BASE_FIELDS | {"quota_bytes"},
}

MAX_QUOTA_BYTES = 2 ** 63 - 1


class ValidationError(Exception):
    """Raised when a command fails validation."""
    pass


def validate_command(command: dict) -> None:
    """
    Validate a command dict received via Unix socket.

    Expected format:
        { "action": "e2ee_provision", "user_id": "bob", "ssh_public_key": "ssh-ed25519 AAAA...", "quota_bytes": 5 }
        { "action": "e2ee_set_key", "user_id": "bob", "ssh_public_key": "ssh-ed25519 AAAA..." }
        { "action": "e2ee_delete", "user_id": "bob" }
        { "action": "e2ee_usage", "user_id": "bob", "quota_bytes": 10737418240 }

    Raises ValidationError if anything is invalid.
    """

    if not isinstance(command, dict):
        raise ValidationError("Command must be a JSON object.")

    # Validate action
    action = command.get("action")
    if not action:
        raise ValidationError("Missing required field: action.")
    if not isinstance(action, str) or action not in VALID_ACTIONS:
        raise ValidationError(f"Invalid action. Must be one of: {sorted(VALID_ACTIONS)}.")

    # Ensure no unexpected extra fields for this action
    extra_fields = set(command.keys()) - ALLOWED_FIELDS[action]
    if extra_fields:
        raise ValidationError(f"Unexpected fields in command: {sorted(extra_fields)}.")

    # Validate user_id
    user_id = command.get("user_id")
    if not user_id:
        raise ValidationError("Missing required field: user_id.")
    if not isinstance(user_id, str):
        raise ValidationError("user_id must be a string.")
    if not USER_ID_PATTERN.fullmatch(user_id):
        raise ValidationError(
            "user_id must be 3-32 characters, alphanumeric and underscores only."
        )
    if user_id.lower() in RESERVED_USER_IDS:
        raise ValidationError("user_id is reserved.")

    # e2ee_set_key needs the user's SSH public key; e2ee_provision may carry one
    if action == "e2ee_set_key" or (action == "e2ee_provision" and "ssh_public_key" in command):
        ssh_key = command.get("ssh_public_key")
        if not ssh_key:
            raise ValidationError(f"Action '{action}' requires ssh_public_key.")
        if not isinstance(ssh_key, str):
            raise ValidationError("ssh_public_key must be a string.")
        if len(ssh_key) > SSH_KEY_MAX_LEN or not SSH_KEY_PATTERN.fullmatch(ssh_key):
            raise ValidationError("ssh_public_key is not a valid single-line OpenSSH public key.")

    # e2ee_usage needs the quota; e2ee_provision may carry it
    if action == "e2ee_usage" or (action == "e2ee_provision" and "quota_bytes" in command):
        quota = command.get("quota_bytes")
        if isinstance(quota, bool) or not isinstance(quota, int) or not (0 <= quota <= MAX_QUOTA_BYTES):
            raise ValidationError("quota_bytes must be a non-negative integer.")

    logger.debug(f"Command validated: action={action}, user_id={user_id}")
