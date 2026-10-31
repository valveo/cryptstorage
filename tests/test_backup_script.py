import gzip
import os
import stat
import subprocess
import tarfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "backup.sh")

DUMP = "-- MariaDB dump\nCREATE TABLE `users` (id varchar(36));\nINSERT INTO `users` VALUES ('1');\n"


def run(tmp_path, docker_body, letsencrypt=True):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text("#!/bin/sh\n" + docker_body)
    docker.chmod(0o755)

    enc = tmp_path / "cryptstorage"
    (enc / "sdalice" / "data").mkdir(parents=True)
    (enc / "sdalice" / "data" / "gocryptfs.conf").write_text("{}")
    state = tmp_path / "sftpgo"
    state.mkdir()
    (state / "hostkey_ed25519").write_text("key")
    etc = tmp_path / "cryptdaemon"
    etc.mkdir()
    (etc / "sftpgo-admin").write_text("admin password")
    le = tmp_path / "letsencrypt"
    if letsencrypt:
        (le / "live" / "example.com").mkdir(parents=True)
        (le / "live" / "example.com" / "privkey.pem").write_text("key")
    dest = tmp_path / "backups"

    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", STORAGE_DIR=str(enc), SFTPGO_STATE_DIR=str(state),
               ETC_DIR=str(etc), LE_DIR=str(le), COMPOSE_FILE="/nonexistent.yml")
    r = subprocess.run([SCRIPT, str(dest)], capture_output=True, text=True, env=env)
    return r, dest


def test_backup_contains_database_and_ciphertext_and_is_private(tmp_path):
    r, dest = run(tmp_path, f"printf '%s' '{DUMP}'\n")
    assert r.returncode == 0, r.stderr
    (out,) = list(dest.iterdir())

    assert DUMP.splitlines()[1] in gzip.open(out / "db.sql.gz", "rt").read()
    assert "cryptstorage/sdalice/data/gocryptfs.conf" in tarfile.open(out / "storage.tar.gz").getnames()
    assert "sftpgo/hostkey_ed25519" in tarfile.open(out / "sftpgo.tar.gz").getnames()
    # the SFTPGo admin password that the restored SFTPGo database expects
    assert "cryptdaemon/sftpgo-admin" in tarfile.open(out / "cryptdaemon-etc.tar.gz").getnames()
    # the TLS key: the clients pin it, a new one locks them all out
    assert "letsencrypt/live/example.com/privkey.pem" in tarfile.open(out / "letsencrypt.tar.gz").getnames()
    assert (out / "SHA256SUMS").read_text().count("\n") == 5

    # nobody else may read it: it holds the accounts, login hashes and the server's SSH host keys
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(out / "db.sql.gz").st_mode) == 0o600


def test_failing_database_dump_fails_the_backup(tmp_path):
    r, _ = run(tmp_path, "echo 'cannot connect' >&2\nexit 1\n")
    assert r.returncode != 0
    assert "Backup written" not in r.stdout


def test_a_dump_without_the_users_table_is_rejected(tmp_path):
    r, _ = run(tmp_path, "printf 'nothing useful'\n")
    assert r.returncode != 0
    assert "no users table" in r.stderr


def test_plain_http_server_without_letsencrypt_is_backed_up(tmp_path):
    r, dest = run(tmp_path, f"printf '%s' '{DUMP}'\n", letsencrypt=False)
    assert r.returncode == 0, r.stderr
    (out,) = list(dest.iterdir())
    assert not (out / "letsencrypt.tar.gz").exists()
    assert (out / "SHA256SUMS").read_text().count("\n") == 4
