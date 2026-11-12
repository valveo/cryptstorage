"""
admin.py - The administrator's commands: accounts, quotas and invitations.

Run it on the server, inside the API container (Ansible installs the wrapper cryptstorage-admin):

    cryptstorage-admin users
    cryptstorage-admin lock alice
    cryptstorage-admin invite create --email bob@example.org

It works directly on the database and the storage daemon, so whoever can run it already controls the
server. It never sees a password or a key: the data stays encrypted with keys only the users have.
Nothing here can open a user's files or reset a forgotten password. Every change is written to the
audit log (security_events) as admin_*.
"""

import argparse
import re
import secrets
import sys
from datetime import datetime

import config
import pending
import registration
from audit import log as audit_log
from auth import _hash_token, revoke_all_refresh_tokens
from database import SessionLocal, init_db
from email_verification import send_security_notice_email
from models import Invite, PendingChange, User, WebAuthnCredential
from socket_client import DaemonError, daemon_e2ee_provision, daemon_e2ee_set_enabled, daemon_e2ee_usage


class AdminError(Exception):
    """Shown to the administrator as it is; the command ends with status 1."""


def _user(db, username: str) -> User:
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise AdminError(f"No account named '{username}'.")
    return user


def _size(n: int) -> str:
    for unit, div in (("GB", 1024 ** 3), ("MB", 1024 ** 2)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} B"


def parse_size(text: str) -> int:
    """"20G", "500M" or a plain number of gigabytes -> bytes."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([gGmM]?)[bB]?", text.strip())
    if not m or float(m.group(1)) <= 0:
        raise AdminError("Give the quota as e.g. 20G or 500M.")
    return int(float(m.group(1)) * (1024 ** 2 if m.group(2).lower() == "m" else 1024 ** 3))


def _state(user: User) -> str:
    if not user.is_active:
        return "locked"
    if not user.email_verified:
        return "unverified"
    return "active"


def _end_sessions(db, user: User) -> None:
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    revoke_all_refresh_tokens(user.id, db)


def cmd_users(db, args) -> str:
    q = db.query(User).order_by(User.username)
    rows = [u for u in q.all() if not args.state or _state(u) == args.state]
    lines = [f"{'USER':<32} {'STATE':<10} {'2FA':<4} {'QUOTA':>9}  {'CREATED':<10}  {'LAST LOGIN':<16}  E-MAIL"]
    for u in rows:
        lines.append(f"{u.username:<32} {_state(u):<10} {'yes' if u.totp_enabled else 'no':<4} "
                     f"{_size(u.quota_bytes):>9}  {u.created_at:%Y-%m-%d}  "
                     f"{(u.last_login.strftime('%Y-%m-%d %H:%M') if u.last_login else '-'):<16}  {u.email}")
    lines.append(f"{len(rows)} account(s).")
    return "\n".join(lines)


def cmd_show(db, args) -> str:
    u = _user(db, args.username)
    passkeys = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == u.id).count()
    waiting = db.query(PendingChange).filter(PendingChange.user_id == u.id, PendingChange.state == "pending").all()
    used = "-"
    if u.storage_created:
        try:
            used = _size(int(daemon_e2ee_usage(u.username, u.quota_bytes).get("used_bytes", 0)))
        except DaemonError as e:
            used = f"unknown ({e})"
    lines = [
        f"User:        {u.username}",
        f"E-mail:      {u.email} ({'confirmed' if u.email_verified else 'not confirmed'})",
        f"State:       {_state(u)}",
        f"Created:     {u.created_at:%Y-%m-%d %H:%M} UTC",
        f"Last login:  {u.last_login:%Y-%m-%d %H:%M} UTC" if u.last_login else "Last login:  never",
        f"Storage:     {used} of {_size(u.quota_bytes)}" if u.storage_created else
        f"Storage:     not created yet (quota {_size(u.quota_bytes)})",
        f"Second factor: {'authenticator app' if u.totp_enabled else 'none'}, {passkeys} passkey(s)",
    ]
    for c in waiting:
        lines.append(f"Waiting:     {c.kind} on {c.due_at:%Y-%m-%d %H:%M} UTC")
    return "\n".join(lines)


def cmd_lock(db, args) -> str:
    u = _user(db, args.username)
    u.is_active = False
    _end_sessions(db, u)
    audit_log(db, "admin_lock", user_id=u.id)
    if u.storage_created:
        try:
            daemon_e2ee_set_enabled(u.username, False)
        except DaemonError as e:
            raise AdminError(f"'{u.username}' can no longer sign in, but the storage account could not be "
                             f"locked: {e}\nRun the command again when the daemon answers.")
    return (f"'{u.username}' is locked: no sign-in, sessions ended, storage connections closed. "
            "The data is kept. Undo with: unlock")


def cmd_unlock(db, args) -> str:
    u = _user(db, args.username)
    if u.storage_created:
        try:
            daemon_e2ee_set_enabled(u.username, True)
        except DaemonError as e:
            raise AdminError(f"The storage account could not be unlocked, nothing was changed: {e}")
    u.is_active = True
    db.commit()
    audit_log(db, "admin_unlock", user_id=u.id)
    return f"'{u.username}' can sign in again."


def cmd_quota(db, args) -> str:
    u = _user(db, args.username)
    quota = parse_size(args.size)
    if u.storage_created:
        try:
            daemon_e2ee_provision(u.username, None, quota)      # no key given: the registered one is kept
        except DaemonError as e:
            raise AdminError(f"The quota could not be set, nothing was changed: {e}")
    old = u.quota_bytes
    u.quota_bytes = quota
    db.commit()
    audit_log(db, "admin_quota", user_id=u.id, detail=f"from={old} to={quota}")
    return f"Quota of '{u.username}': {_size(old)} -> {_size(quota)}."


def cmd_reset_2fa(db, args) -> str:
    """For a user who lost the phone and the backup codes. The administrator must be sure who is asking:
    after this the password alone signs in (and, where the server requires a second factor, sets up a new one)."""
    u = _user(db, args.username)
    u.totp_enabled = False
    u.totp_secret_enc = None
    u.totp_last_step = None
    u.totp_backup_hashes = None
    removed = db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == u.id).delete(synchronize_session=False)
    _end_sessions(db, u)
    audit_log(db, "admin_reset_2fa", user_id=u.id, detail=f"passkeys_removed={removed}")
    told = "The user was told by e-mail."
    try:
        send_security_notice_email(
            u.email, u.username,
            "The administrator of this server removed the authenticator app and the passkeys from your account.",
            "If you did not ask for this, contact the administrator at once.")
    except Exception as e:
        told = f"The user could NOT be told by e-mail ({e}); tell them yourself."
    return f"Second factor of '{u.username}' removed ({removed} passkey(s)); all sessions ended. {told}"


def cmd_verify(db, args) -> str:
    u = _user(db, args.username)
    u.email_verified = True
    db.commit()
    audit_log(db, "admin_verify_email", user_id=u.id)
    return f"The e-mail address of '{u.username}' is marked as confirmed."


def cmd_delete(db, args) -> str:
    u = _user(db, args.username)
    if not args.yes:
        raise AdminError(f"This deletes '{u.username}' and ALL its data for good. Repeat with --yes.")
    user_id, name = u.id, u.username
    db.query(PendingChange).filter(PendingChange.user_id == u.id, PendingChange.kind == "delete",
                                   PendingChange.state == "pending").update(
        {PendingChange.state: "cancelled"}, synchronize_session=False)
    db.add(PendingChange(user_id=u.id, kind="delete", state="pending", due_at=datetime.utcnow(),
                         cancel_hash=_hash_token(secrets.token_urlsafe(32))))
    db.commit()
    audit_log(db, "admin_delete", user_id=user_id)
    pending.apply_due(db, user_id)
    if db.query(User).filter(User.id == user_id).first() is not None:
        raise AdminError(f"'{name}' could not be deleted now (is the daemon running?). "
                         "The deletion is stored and the server retries it.")
    return f"'{name}' and its data are deleted."


def cmd_invite_create(db, args) -> str:
    if args.days <= 0:
        raise AdminError("--days must be more than 0.")
    invite, code = registration.create_invite(db, args.email, args.days, args.note)
    audit_log(db, "admin_invite_created", detail=f"invite={invite.id} email={invite.email or '-'}")
    lines = [f"Invitation code: {code}",
             f"Valid until {invite.expires_at:%Y-%m-%d %H:%M} UTC, for one registration"
             + (f" with the address {invite.email}." if invite.email else "."),
             "The code is shown only now."]
    if config.registration() != "invite":
        lines.append(f"Note: this server's REGISTRATION is '{config.registration()}', so codes are not asked for.")
    return "\n".join(lines)


def cmd_invite_list(db, args) -> str:
    now = datetime.utcnow()
    lines = [f"{'ID':<36}  {'STATE':<8}  {'EXPIRES':<16}  {'E-MAIL':<28}  NOTE"]
    for i in db.query(Invite).order_by(Invite.created_at).all():
        state = "used" if i.used_at else ("expired" if i.expires_at <= now else "open")
        lines.append(f"{i.id:<36}  {state:<8}  {i.expires_at:%Y-%m-%d %H:%M}  {(i.email or '-'):<28}  {i.note or ''}")
    return "\n".join(lines)


def cmd_invite_revoke(db, args) -> str:
    n = db.query(Invite).filter(Invite.id == args.id, Invite.used_at.is_(None)).delete(synchronize_session=False)
    db.commit()
    if not n:
        raise AdminError("No unused invitation with that id (see: invite list).")
    audit_log(db, "admin_invite_revoked", detail=f"invite={args.id}")
    return "Invitation revoked."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cryptstorage-admin", description="CryptStorage administration.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("users", help="list the accounts")
    s.add_argument("--state", choices=("active", "locked", "unverified"))
    s.set_defaults(func=cmd_users)

    for name, func, text in (
        ("show", cmd_show, "one account in detail"),
        ("lock", cmd_lock, "stop an account from signing in and from reaching its storage (data is kept)"),
        ("unlock", cmd_unlock, "undo lock"),
        ("reset-2fa", cmd_reset_2fa, "remove the authenticator app and passkeys of an account"),
        ("verify", cmd_verify, "mark the e-mail address as confirmed (when the e-mail did not arrive)"),
    ):
        s = sub.add_parser(name, help=text)
        s.add_argument("username")
        s.set_defaults(func=func)

    s = sub.add_parser("quota", help="set the storage quota of an account, e.g. 20G or 500M")
    s.add_argument("username")
    s.add_argument("size")
    s.set_defaults(func=cmd_quota)

    s = sub.add_parser("delete", help="delete an account and all its data, at once")
    s.add_argument("username")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(func=cmd_delete)

    inv = sub.add_parser("invite", help="invitations (REGISTRATION=invite)").add_subparsers(dest="what", required=True)
    s = inv.add_parser("create", help="make an invitation code")
    s.add_argument("--email", help="the code works only with this address")
    s.add_argument("--days", type=float, default=7, help="how long it is valid (default 7)")
    s.add_argument("--note", help="a reminder for yourself, shown in the list")
    s.set_defaults(func=cmd_invite_create)
    s = inv.add_parser("list", help="list the invitations")
    s.set_defaults(func=cmd_invite_list)
    s = inv.add_parser("revoke", help="remove an unused invitation")
    s.add_argument("id")
    s.set_defaults(func=cmd_invite_revoke)
    return p


def run(argv: list[str], session_factory=SessionLocal) -> tuple[int, str]:
    args = build_parser().parse_args(argv)
    db = session_factory()
    try:
        return 0, args.func(db, args)
    except AdminError as e:
        return 1, str(e)
    finally:
        db.close()


def main() -> int:
    init_db()
    code, text = run(sys.argv[1:])
    print(text, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())
