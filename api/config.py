"""
config.py - Startup configuration with fail-fast checks.

Secrets must come from the environment. A missing or placeholder secret stops the
service at startup with an explanation, instead of silently running with a
publicly known default (as JWT_SECRET_KEY used to) or a value that changes on
every restart (as REFRESH_TOKEN_HMAC_KEY did).
"""

import os


class ConfigError(RuntimeError):
    """Raised at startup when required configuration is missing or insecure."""


_PLACEHOLDERS = ("change_me", "changeme", "change-this", "replace_me", "your_secret")


def require(name: str, *, min_len: int = 1, hex_bytes: int | None = None) -> str:
    """Return the value of environment variable `name` or raise ConfigError."""
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is not set.")
    if any(p in value.lower() for p in _PLACEHOLDERS):
        raise ConfigError(f"{name} still contains a placeholder value. Generate a real secret.")
    if hex_bytes is not None:
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            raise ConfigError(
                f"{name} must be a hex string. Generate one with: openssl rand -hex {hex_bytes}"
            )
        if len(raw) < hex_bytes:
            raise ConfigError(
                f"{name} must be at least {hex_bytes} bytes ({hex_bytes * 2} hex characters). "
                f"Generate one with: openssl rand -hex {hex_bytes}"
            )
    elif len(value) < min_len:
        raise ConfigError(f"{name} must be at least {min_len} characters long.")
    return value


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


RECOVERY_POLICIES = ("user", "escrow", "both")


def recovery_policy() -> str:
    return os.getenv("RECOVERY_POLICY", "user").strip().lower()


def escrow_public_key() -> str:
    return os.getenv("ESCROW_PUBLIC_KEY", "").strip().lower()


# Factors every login must present (docs/design-factors.md, tier 1). "password,totp" makes the
# authenticator app mandatory: an account without one can only sign in to enrol it.
SECOND_FACTORS = ("password", "totp")


def required_factors() -> set[str]:
    raw = os.getenv("REQUIRED_FACTORS", "password,totp")
    return {f.strip().lower() for f in raw.split(",") if f.strip()}


def totp_required() -> bool:
    return "totp" in required_factors()


# ---------------------------------------------------------------------------------------------
# DEMO SERVER SETTINGS. Meant for a public demo or trial server only (e.g. demo.venomia.fi), not
# for real use: ACCOUNT_LIFETIME_HOURS deletes accounts *and their data*. All are off by default,
# so a normal installation behaves exactly as before. Set them in the Ansible inventory
# (demo_quota_mb, demo_max_users, demo_account_lifetime_hours).
# ---------------------------------------------------------------------------------------------
def default_quota_bytes() -> int:
    """Storage quota of a new account (DEFAULT_QUOTA_MB, default 10 GiB)."""
    return int(float(os.getenv("DEFAULT_QUOTA_MB", "10240")) * 1024 * 1024)


def max_users() -> int:
    """No new registrations once this many accounts exist. 0 = no limit."""
    return int(os.getenv("MAX_USERS", "0") or 0)


def account_lifetime_hours() -> float:
    """Accounts older than this are deleted (with all their data). 0 = they are kept."""
    return float(os.getenv("ACCOUNT_LIFETIME_HOURS", "0") or 0)


def change_delay_hours() -> float:
    """How long a new SSH key or an account deletion waits before it takes effect."""
    return float(os.getenv("CHANGE_DELAY_HOURS", "24"))


def sync_lock_seconds() -> int:
    """How long a sync lock lasts unless its holder renews it (a crashed client blocks no longer)."""
    return int(os.getenv("SYNC_LOCK_SECONDS", "120"))


def validate() -> None:
    """Check every required setting. Called at application startup."""
    require("JWT_SECRET_KEY", min_len=32)
    require("REFRESH_TOKEN_HMAC_KEY", hex_bytes=32)
    require("DAEMON_AUTH_KEY", hex_bytes=32)
    require("DATABASE_URL")
    # Optional unless REQUIRED_FACTORS includes totp: without it the TOTP endpoints answer 503.
    if os.getenv("TOTP_ENCRYPTION_KEY", "").strip():
        require("TOTP_ENCRYPTION_KEY", hex_bytes=32)
    factors = required_factors()
    if "password" not in factors or not factors <= set(SECOND_FACTORS):
        raise ConfigError(f"REQUIRED_FACTORS must be 'password' or 'password,totp', not {sorted(factors)}.")
    if "totp" in factors:
        require("TOTP_ENCRYPTION_KEY", hex_bytes=32)
    try:
        if change_delay_hours() < 0:
            raise ValueError
    except ValueError:
        raise ConfigError("CHANGE_DELAY_HOURS must be a number of hours, 0 or more.")
    if recovery_policy() not in RECOVERY_POLICIES:
        raise ConfigError(f"RECOVERY_POLICY must be one of {RECOVERY_POLICIES}.")
    if recovery_policy() != "user":
        require("ESCROW_PUBLIC_KEY", hex_bytes=32)
