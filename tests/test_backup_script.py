import gzip
import os
import stat
import subprocess
import tarfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "backup.sh")

DUMP = "-- MariaDB dump\nCREATE TABLE `users` (id varchar(36));\nINSERT INTO `users` VALUES ('1');\n"


def run(tmp_path, docker_body, letsencrypt=True, args=()):
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
               ETC_DIR=str(etc), LE_DIR=str(le), CONF_DIR=str(tmp_path / "conf"), COMPOSE_FILE="/nonexistent.yml")
    r = subprocess.run([SCRIPT, *args, str(dest)], capture_output=True, text=True, env=env)
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


def test_without_files_leaves_only_the_ciphertext_out_and_says_so(tmp_path):
    r, dest = run(tmp_path, f"printf '%s' '{DUMP}'\n", args=["--without-files"])
    assert r.returncode == 0, r.stderr
    (out,) = list(dest.iterdir())
    assert out.name.endswith("-without-files") and "WITHOUT the users' files" in r.stdout
    assert not (out / "storage.tar.gz").exists()
    assert "NOT the users' encrypted files" in (out / "WITHOUT-FILES.txt").read_text()
    for part in ("db.sql.gz", "sftpgo.tar.gz", "cryptdaemon-etc.tar.gz", "letsencrypt.tar.gz"):
        assert (out / part).stat().st_size > 0
    sums = (out / "SHA256SUMS").read_text()
    assert sums.count("\n") == 4 and "storage.tar.gz" not in sums
    assert subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=out, capture_output=True).returncode == 0


def test_usage_error_for_missing_or_unknown_arguments(tmp_path):
    for args in ([], ["--full"], ["--without-files"]):
        r = subprocess.run([SCRIPT, *args], capture_output=True, text=True)
        assert r.returncode == 2 and "usage" in r.stderr


def test_settings_of_a_server_installed_with_install_sh_are_in_the_backup(tmp_path):
    (tmp_path / "conf").mkdir()
    (tmp_path / "conf" / "inventory.yml").write_text("all: {}\n")
    r, dest = run(tmp_path, f"printf '%s' '{DUMP}'\n", args=("--without-files",))
    assert r.returncode == 0, r.stderr
    (out,) = list(dest.iterdir())
    assert "conf/inventory.yml" in tarfile.open(out / "settings.tar.gz").getnames()
    assert "settings.tar.gz" in (out / "SHA256SUMS").read_text()
