"""Prints what the user would read on their phone or in their e-mail: `totp <user>` or `enrol <user>`."""
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(here, "..", "..", "api")]

import database  # noqa: E402
import models  # noqa: E402
import totp  # noqa: E402

kind, name = sys.argv[1], sys.argv[2]
with database.SessionLocal() as db:
    u = db.query(models.User).filter_by(username=name).one()
    if kind == "enrol":
        print(totp.enrolment_code(u.id, u.totp_secret_enc))
    else:
        u.totp_last_step = None          # so the test need not wait for the next 30-second step
        db.commit()
        print(totp.code_for_step(totp.decrypt_secret(u.totp_secret_enc, u.id), totp.current_step()))
