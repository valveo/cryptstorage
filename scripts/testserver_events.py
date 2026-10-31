#!/usr/bin/env python3
"""Prints the test server's accounts (second factors only) and recent security events, for the
deploy workflow's show_logs input. Reads the SQLite database given as the argument; prints no secrets."""
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
names = dict(db.execute("select id, username from users"))
print("users (name, totp on, passkeys):")
for uid, name, totp in db.execute("select id, username, totp_enabled from users"):
    n = db.execute("select count(*) from webauthn_credentials where user_id=?", (uid,)).fetchone()[0]
    print(" ", name, bool(totp), n)
print("last events:")
for at, uid, ev, det, ip in db.execute(
        "select created_at, user_id, event_type, detail, ip_address from security_events "
        "order by created_at desc limit 60"):
    print(" ", at, names.get(uid, "-"), ev, det or "", ip or "")
