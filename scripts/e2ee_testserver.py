#!/usr/bin/env python3
"""Test server for scripts/e2ee_integration.sh (and deploy_testserver.sh, which sets HOST=0.0.0.0): the real API in end-to-end mode, with the daemon
calls answered by the real SFTP provisioner in this process (the test runs as root)."""
import os, sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(here, "..", "api"), os.path.join(here, "..", "cryptdaemon")]

# Automated clients have no authenticator app; the settings file can still turn it on
os.environ.setdefault("REQUIRED_FACTORS", "password")

import uvicorn
import main
import pending
import sftpgo_client as sp

main.daemon_e2ee_provision = pending.daemon_e2ee_provision = lambda user, key=None, quota=None: sp.provision(user, key, quota)
pending.daemon_e2ee_delete = sp.delete
main.daemon_e2ee_usage = lambda user, quota: {"used_bytes": sp.usage_bytes(user), "quota_bytes": quota}

uvicorn.run(main.app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8099")), log_level="warning")
