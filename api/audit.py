"""
audit.py - Audit log for security-relevant events.

All writes go to:
  1. The security_events database table (queryable, persistent)
  2. The application logger at WARNING level (picked up by log aggregation)

Events logged:
  login_success       - Successful login (IP, username)
  login_failed        - Failed login attempt (IP, username)
  register            - New user registered
  email_verified      - Email address verified
  password_changed    - Password changed (all sessions revoked)
  storage_mounted     - Storage mounted (IP)
  storage_umounted    - Storage umounted
  account_deleted     - Account and storage permanently deleted
  refresh_token_reuse - Revoked refresh token presented (possible theft)
  ssh_key_updated     - SSH public key changed
"""

import logging
import uuid
from datetime import datetime
import ipaddress
import re
from typing import Optional

from sqlalchemy.orm import Session

from models import SecurityEvent

logger = logging.getLogger("cryptstorage.audit")


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value: Optional[str], max_len: int = 500) -> Optional[str]:
    """Strip control characters so user-supplied text cannot forge log lines."""
    if value is None:
        return None
    return _CONTROL_CHARS.sub("?", str(value))[:max_len]


def log(
    db: Session,
    event_type: str,
    user_id: Optional[str] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """Write an audit event to the database and logger."""
    detail = _clean(detail)
    ip_address = _clean(ip_address, 64)
    ev = SecurityEvent(
        id         = str(uuid.uuid4()),
        user_id    = user_id,
        event_type = event_type,
        detail     = detail,
        ip_address = ip_address,
        created_at = datetime.utcnow(),
    )
    try:
        db.add(ev)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to write audit event to DB: {e}")
        db.rollback()

    # Always log to file/stdout even if DB write fails
    logger.warning(
        f"AUDIT event={event_type} user={user_id or '-'} "
        f"ip={ip_address or '-'} detail={detail or '-'}"
    )


# Trusted reverse proxies: CIDRs or addresses, comma separated (TRUSTED_PROXIES).
# X-Forwarded-For is only believed when the direct peer is one of these.
# Default: loopback only. The shipped compose file sets the Docker private ranges.
import os as _os


def _parse_networks(value: str) -> list:
    nets = []
    for item in value.split(","):
        item = item.strip()
        if item:
            nets.append(ipaddress.ip_network(item, strict=False))
    return nets


_TRUSTED_PROXIES = _parse_networks(_os.getenv("TRUSTED_PROXIES", "127.0.0.0/8,::1/128"))


def _is_trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _TRUSTED_PROXIES)


def get_client_ip(request) -> str:
    """
    Real client IP of a FastAPI Request.

    X-Forwarded-For is only used when the direct peer is a trusted proxy, and it
    is read from the right: hops that are trusted proxies themselves are skipped
    and the first address that is not one is the client. This is correct whether
    a proxy overwrites the header or appends to it, and a client cannot spoof it
    by sending its own X-Forwarded-For. Malformed entries are never trusted.
    """
    direct_ip = request.client.host if request.client else "unknown"
    if not _is_trusted(direct_ip):
        return direct_ip

    hops = [h.strip() for h in request.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
    for hop in reversed(hops):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return direct_ip
        if not _is_trusted(hop):
            return hop
    return hops[0] if hops else direct_ip
