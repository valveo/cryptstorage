"""
daemon.py - Main entry point for the cryptdaemon.

Listens on a Unix socket for commands from the API container,
dispatches them to handler.py, and returns results.

Protocol: one newline-terminated JSON object per request and per response
(see socket_auth.py for the authentication scheme).

Usage:
    python daemon.py

The daemon runs on the host as the storage account `cryptstorage` (also the SFTPGo container's user), not as root:
it only calls SFTPGo's REST API and creates and deletes directories that user owns.
It is started as a systemd service (ansible/roles/cryptdaemon/templates/cryptdaemon.service.j2).

Environment:
    CRYPTDAEMON_SOCKET      socket path (default /run/cryptdaemon/cryptdaemon.sock)
    CRYPTDAEMON_SOCKET_GID  numeric gid that may connect (socket 0660 <daemon>:gid,
                            directory 0750); the daemon must be a member. Unset = only
                            the daemon's own user (0600).
    CRYPTDAEMON_LOG         log file (default /var/log/cryptdaemon.log)
    CRYPTDAEMON_WORKERS     connections handled in parallel (default 4)
    CRYPTDAEMON_ALLOWED_UIDS  optional comma-separated list of peer uids (as seen by
                            SO_PEERCRED) that may use the socket; unset = no uid check
"""

import json
import logging
import os
import signal
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from handler import handle_command
from socket_auth import AuthError, ReplayCache, load_auth_key, verify_command

# --- Configuration ---
SOCKET_PATH = os.getenv("CRYPTDAEMON_SOCKET", "/run/cryptdaemon/cryptdaemon.sock")
SOCKET_GID = os.getenv("CRYPTDAEMON_SOCKET_GID")
LOG_FILE = os.getenv("CRYPTDAEMON_LOG", "/var/log/cryptdaemon.log")
WORKERS = int(os.getenv("CRYPTDAEMON_WORKERS", "4"))
ALLOWED_UIDS = {int(u) for u in os.getenv("CRYPTDAEMON_ALLOWED_UIDS", "").split(",") if u.strip()}
MAX_MESSAGE_SIZE = 8192      # Bytes
CONNECTION_TIMEOUT = 10      # seconds to receive a request (a slow client must not block the daemon)

logger = logging.getLogger(__name__)

# Nonces of recently accepted commands (replay protection)
_REPLAY_CACHE = ReplayCache()


def _peer_credentials(conn: socket.socket):
    """(pid, uid, gid) of the process on the other end of the Unix socket, or None."""
    try:
        data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", data)
    except (OSError, AttributeError):
        return None


def _setup_logging() -> None:
    """Configure logging. Done at startup (not import) so tests can import this module."""
    handlers: list = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.insert(0, logging.FileHandler(LOG_FILE))
    except OSError as e:
        print(f"WARNING: cannot open log file {LOG_FILE}: {e}", file=sys.stderr)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


class _MessageTooLarge(Exception):
    pass


def _read_request(conn: socket.socket) -> bytes | None:
    """Read one newline-terminated (or EOF-terminated) request."""
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_MESSAGE_SIZE:
            raise _MessageTooLarge()
    line = data.split(b"\n", 1)[0]
    return line if line.strip() else None


def handle_connection(conn: socket.socket, auth_key: bytes,
                      replay_cache: "ReplayCache | None" = None) -> None:
    """
    Read one command, verify auth, execute, send result.

    Never raises: a malformed or hostile request must not take the daemon
    down.
    """
    cache = _REPLAY_CACHE if replay_cache is None else replay_cache
    try:
        conn.settimeout(CONNECTION_TIMEOUT)

        peer = _peer_credentials(conn)
        if ALLOWED_UIDS and (peer is None or peer[1] not in ALLOWED_UIDS):
            logger.warning(f"Rejected connection from unexpected peer {peer}")
            send_response(conn, {"status": "error", "message": "Unauthorized."})
            return

        try:
            raw = _read_request(conn)
        except _MessageTooLarge:
            send_response(conn, {"status": "error", "message": "Message too large."})
            return
        except socket.timeout:
            send_response(conn, {"status": "error", "message": "Timed out reading request."})
            return

        if raw is None:
            return

        try:
            command = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            send_response(conn, {"status": "error", "message": "Invalid JSON."})
            return

        # Verify HMAC auth before doing anything
        try:
            verify_command(command, auth_key, cache)
        except AuthError as e:
            logger.warning(f"Auth failed (peer={peer}): {e}")
            send_response(conn, {"status": "error", "message": "Unauthorized."})
            return

        logger.info(
            f"Command {command.get('action')} for {command.get('user_id')} from peer={peer}"
        )

        # The receive timeout applies to reading the request only
        conn.settimeout(None)
        result = handle_command(command)
        send_response(conn, result)

    except Exception:
        logger.exception("Unhandled error while processing a connection")
        send_response(conn, {"status": "error", "message": "Internal daemon error."})
    finally:
        try:
            conn.close()
        except OSError:
            pass


def send_response(conn: socket.socket, response: dict) -> None:
    """Send a newline-terminated JSON response back to the caller."""
    try:
        conn.sendall(json.dumps(response).encode("utf-8") + b"\n")
    except OSError as e:
        logger.error(f"Failed to send response: {e}")


def cleanup(signum=None, frame=None) -> None:
    """Graceful shutdown: remove the socket."""
    logger.info("Shutting down cryptdaemon...")
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    logger.info("Shutdown complete.")
    sys.exit(0)


def _socket_gid() -> int | None:
    if not SOCKET_GID:
        return None
    try:
        return int(SOCKET_GID)
    except ValueError:
        logger.critical(f"CRYPTDAEMON_SOCKET_GID must be numeric, got {SOCKET_GID!r}")
        sys.exit(1)


def _prepare_socket_dir(gid: int | None) -> None:
    """
    Create the dedicated socket directory. The directory (not the socket file)
    is what gets bind-mounted into the API container, so the socket survives
    daemon restarts.
    """
    sock_dir = os.path.dirname(SOCKET_PATH)
    os.makedirs(sock_dir, exist_ok=True)
    if gid is not None:
        os.chown(sock_dir, -1, gid)
        os.chmod(sock_dir, 0o750)
    else:
        os.chmod(sock_dir, 0o700)


def run() -> None:
    """Main loop: create socket and listen for commands."""

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    # Load auth key
    try:
        auth_key = load_auth_key()
        logger.info("Socket auth key loaded.")
    except Exception as e:
        logger.critical(f"Cannot load auth key: {e}")
        sys.exit(1)

    gid = _socket_gid()
    _prepare_socket_dir(gid)

    # Remove stale socket if present
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    executor = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="conn")

    try:
        # Create the socket with a restrictive umask so there is no window
        # in which it is more accessible than intended.
        old_umask = os.umask(0o177)
        try:
            server.bind(SOCKET_PATH)
        finally:
            os.umask(old_umask)

        if gid is not None:
            os.chown(SOCKET_PATH, -1, gid)
            os.chmod(SOCKET_PATH, 0o660)
        else:
            os.chmod(SOCKET_PATH, 0o600)

        server.listen(5)
        logger.info(f"cryptdaemon listening on {SOCKET_PATH}")

        while True:
            try:
                conn, _ = server.accept()
            except OSError as e:
                logger.error(f"Accept error: {e}")
                time.sleep(0.5)
                continue
            # One slow command must not block every other user: handle in a worker thread
            # (commands for the same user are serialized in handler.py)
            executor.submit(handle_connection, conn, auth_key)

    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        cleanup()
    finally:
        server.close()


if __name__ == "__main__":
    _setup_logging()
    run()
