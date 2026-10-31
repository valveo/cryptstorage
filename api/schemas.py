"""
schemas.py - Pydantic schemas for request validation and response serialization.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
import re

from ssh_keys import InvalidSSHKey, validate_ssh_public_key

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128

# Names that exist as system accounts or look official. Must match
# cryptdaemon/validator.py RESERVED_USER_IDS (a test enforces it).
RESERVED_USERNAMES = frozenset({
    "root", "admin", "administrator", "sshd", "daemon", "bin", "sys", "sync",
    "games", "man", "lp", "mail", "news", "uucp", "proxy", "nobody", "www",
    "operator", "ftp", "backup", "list", "irc", "gnats", "systemd", "support",
    "security", "postmaster", "abuse", "cryptstorage", "cryptdaemon", "cryptuser",
})


def _check_password(v: str) -> str:
    if len(v) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")
    if len(v) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters.")
    return v


def _check_ssh_key(v: str) -> str:
    try:
        return validate_ssh_public_key(v)
    except InvalidSSHKey as e:
        raise ValueError(str(e))


# --- Auth ---

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    ssh_public_key: Optional[str] = None

    @field_validator("username")
    @classmethod
    def username_valid(cls, v):
        if not re.fullmatch(r"[a-zA-Z0-9_]{3,32}", v):
            raise ValueError(
                "Username must be 3-32 characters, alphanumeric and underscores only."
            )
        if v.lower() in RESERVED_USERNAMES:
            raise ValueError("This username is reserved.")
        return v

    @field_validator("password")
    @classmethod
    def password_strong(cls, v):
        return _check_password(v)

    @field_validator("ssh_public_key")
    @classmethod
    def ssh_key_valid(cls, v):
        return None if v is None else _check_ssh_key(v)

    @model_validator(mode="after")
    def password_not_username(self):
        if self.username.lower() in self.password.lower():
            raise ValueError("Password must not contain the username.")
        return self


class LoginRequest(BaseModel):
    # Upper bounds: unauthenticated input must not make the hashing expensive
    username: str = Field(max_length=64)
    password: str = Field(max_length=PASSWORD_MAX_LENGTH)
    # Needed when the account has a second factor: a 6-digit code or a backup code.
    totp_code: Optional[str] = Field(default=None, max_length=32)
    # A web UI session: limited to account management, no refresh token
    web: bool = False


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    # None for a web UI session, which ends with its access token
    refresh_token: Optional[str] = None


# --- User ---

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    email_verified: bool
    storage_created: bool
    quota_bytes: int
    created_at: datetime
    last_login: Optional[datetime]
    totp_enabled: bool = False

    model_config = {"from_attributes": True}


class SSHKeyUpdate(BaseModel):
    ssh_public_key: str
    # The SSH key is what grants access to the files, so changing it needs the password and
    # the second factor, not just a (possibly stolen) access token, and it waits.
    password: str = Field(max_length=PASSWORD_MAX_LENGTH)
    totp_code: Optional[str] = Field(default=None, max_length=32)

    @field_validator("ssh_public_key")
    @classmethod
    def ssh_key_valid(cls, v):
        return _check_ssh_key(v)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(max_length=PASSWORD_MAX_LENGTH)
    new_password: str
    totp_code: Optional[str] = Field(default=None, max_length=32)

    @field_validator("new_password")
    @classmethod
    def password_strong(cls, v):
        return _check_password(v)


# --- Generic ---

class MessageResponse(BaseModel):
    message: str


class DeleteRequest(BaseModel):
    # empty from a web session, which confirms with a recent sign-in instead
    password: str = Field(default="", max_length=PASSWORD_MAX_LENGTH)
    totp_code: Optional[str] = Field(default=None, max_length=32)


class ChangeResponse(BaseModel):
    """Answer to a change that may wait (SSH key, account deletion, stick removal)."""
    message: str
    pending: bool = False
    change_id: Optional[str] = None
    effective_at: Optional[datetime] = None


class PendingChangeResponse(BaseModel):
    id: str
    kind: str
    created_at: datetime
    due_at: datetime

    model_config = {"from_attributes": True}


class CancelChangeRequest(BaseModel):
    token: str = Field(max_length=128)


# --- Second factor (TOTP) ---

class TotpSetupRequest(BaseModel):
    # empty from a web session, which confirms with a recent sign-in instead
    password: str = Field(default="", max_length=PASSWORD_MAX_LENGTH)


class TotpSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    message: str


class TotpEnableRequest(BaseModel):
    code: str = Field(max_length=32)
    # Sent by e-mail at setup: someone who only has the password cannot turn the factor on
    email_code: str = Field(max_length=16)


class TotpEnableResponse(BaseModel):
    message: str
    backup_codes: list[str]


class TotpDisableRequest(BaseModel):
    # empty from a web session, which confirms with a recent sign-in instead
    password: str = Field(default="", max_length=PASSWORD_MAX_LENGTH)
    code: str = Field(max_length=32)


# --- End-to-end encrypted mode ---

class ServerInfo(BaseModel):
    storage_mode: str
    version: str = "dev"        # the build the server runs (version.py)
    recovery_policy: str
    # X25519 public key (hex) the client seals the master key to, when escrow is on
    escrow_public_key: Optional[str] = None
    # SHA-256 of that key, hex; the client stores it on the stick and warns when it changes
    escrow_key_fingerprint: Optional[str] = None
    # Set on demo/trial servers that delete accounts after this many hours
    account_lifetime_hours: Optional[float] = None
    # Stays the same for as long as the stick secrets do (sticks.server_id); the client binds a stick to it
    server_id: Optional[str] = None


class E2EEStorageResponse(BaseModel):
    ssh_host: str
    ssh_port: int
    ssh_user: str
    ssh_host_keys: list[str] = []
    quota_bytes: int
    used_bytes: int


_SYNC_HOLDER = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


class SyncLockRequest(BaseModel):
    # Random id of the client installation; only the holder can renew or release the lock
    holder: str
    holder_name: Optional[str] = Field(default=None, max_length=64)
    volume: str = "personal"

    @field_validator("holder")
    @classmethod
    def _holder(cls, v: str) -> str:
        if not _SYNC_HOLDER.match(v):
            raise ValueError("holder must be 16 to 64 letters, digits, '-' or '_'.")
        return v

    @field_validator("volume")
    @classmethod
    def _volume(cls, v: str) -> str:
        if v != "personal":
            raise ValueError("Only the personal volume can be synchronised.")
        return v


class SyncLockResponse(BaseModel):
    expires_at: datetime
    ttl_seconds: int


class RecoveryVerifierRequest(BaseModel):
    # HKDF(master key, "secdisk/recover-auth/v1"), 32 bytes hex. Proves possession of the recovery
    # code without revealing the master key; the server stores only a slow hash of it.
    proof: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class E2EERecoverRequest(BaseModel):
    username: str = Field(max_length=64)
    proof: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    new_password: str = Field(max_length=PASSWORD_MAX_LENGTH)   # the new login key (64 hex)
    # Needed when the account has a second factor (a code or a backup code)
    totp_code: Optional[str] = Field(default=None, max_length=32)


class EscrowRequest(BaseModel):
    # ephemeral X25519 public key (32) | nonce (12) | ciphertext (32) | tag (16), hex
    blob: str = Field(min_length=184, max_length=184, pattern=r"^[0-9a-f]{184}$")


# --- Passkeys (WebAuthn) ---

class PasskeyLoginBegin(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=PASSWORD_MAX_LENGTH)


class PasskeyOptions(BaseModel):
    """`options` go to navigator.credentials (base64url fields); `session` comes back with the answer."""
    options: dict
    session: str
    # Where the cryptclient app sends the user to approve its sign-in (webui/passkey-approve.php)
    approve_url: Optional[str] = None


class PasskeyLoginFinish(BaseModel):
    session: str = Field(max_length=2048)
    credential: dict
    web: bool = False


class WebPasskeyBegin(BaseModel):
    username: str = Field(max_length=64)


class WebTicketResponse(BaseModel):
    ticket: str
    # the web UI page that takes the ticket, or None when the server does not know its address
    url: Optional[str] = None
    expires_in: int


class WebTicketRedeem(BaseModel):
    ticket: str = Field(max_length=2048)


class PasskeyRegisterBegin(BaseModel):
    # empty from a web session, which confirms with a recent sign-in instead
    password: str = Field(default="", max_length=PASSWORD_MAX_LENGTH)
    totp_code: Optional[str] = Field(default=None, max_length=32)


class PasskeyRegisterFinish(BaseModel):
    session: str = Field(max_length=2048)
    name: str = Field(min_length=1, max_length=64)
    credential: dict


class PasskeyResponse(BaseModel):
    id: str
    name: str
    created_at: datetime
    last_used_at: Optional[datetime] = None


class PasskeyDeleteRequest(BaseModel):
    # empty from a web session, which confirms with a recent sign-in instead
    password: str = Field(default="", max_length=PASSWORD_MAX_LENGTH)
    totp_code: Optional[str] = Field(default=None, max_length=32)


class StickCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class StickSecretResponse(BaseModel):
    """The stick secret, hex. Only for a session that passed the full login."""
    stick_id: str
    secret: str


class StickResponse(BaseModel):
    id: str
    name: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    locked_at: Optional[datetime] = None        # locked: its secret is not released
    removal_due: Optional[datetime] = None      # removal for good waits until then


class StickDeleteRequest(BaseModel):
    # empty from a web session, which confirms with a recent sign-in instead
    password: str = Field(default="", max_length=PASSWORD_MAX_LENGTH)
    totp_code: Optional[str] = Field(default=None, max_length=32)
