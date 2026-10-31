"""The real API for the browser test, with the daemon (SFTP accounts) stubbed out. Settings come from
the environment that run.sh sets; e-mail is in dev mode (logged, not sent)."""
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(here, "..", "..", "api")]

import uvicorn  # noqa: E402
import main  # noqa: E402
import pending  # noqa: E402

main.daemon_e2ee_provision = pending.daemon_e2ee_provision = lambda user, key=None, quota=None: "sdbrowser"
main.daemon_e2ee_usage = lambda user, quota: {"used_bytes": 0, "quota_bytes": quota, "percent": 0}
pending.daemon_e2ee_delete = lambda user: None

uvicorn.run(main.app, host="127.0.0.1", port=int(os.environ["API_PORT"]), log_level="warning")
