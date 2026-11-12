"""install.sh and scripts/update.sh (cryptstorage-update), as far as they go without a real server.

The real installation and a real update run in CI (.github/workflows/ci.yml, job "install"). Here the
programs around them are stand-ins, to pin the decisions: what is refused, what is written, and that
nothing is changed before the backup exists.
"""
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile

import pytest
import yaml


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL = os.path.join(ROOT, "install.sh")
UPDATE = os.path.join(ROOT, "scripts", "update.sh")


def script(path, body):
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)


# ---------------------------------------------------------------------------------------------
# install.sh
# ---------------------------------------------------------------------------------------------

def install(tmp_path, *args, os_release='ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n',
            listening=""):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    # `ss -ltnpH "sport = :80"`: what listens on that port
    script(bin_dir / "ss", f'case "$2" in {listening} esac\n')
    (tmp_path / "os-release").write_text(os_release)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", CRYPTSTORAGE_ETC=str(tmp_path / "etc"),
               CRYPTSTORAGE_OS_RELEASE=str(tmp_path / "os-release"), CRYPTSTORAGE_SKIP_SYSTEM_CHECKS="1",
               CRYPTSTORAGE_INSTALL_DIR=str(tmp_path / "opt"))
    return subprocess.run([INSTALL, *args], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)


FIRST = ("--write-settings-only", "--yes", "--domain", "storage.example.com", "--email", "admin@example.com",
         "--tls", "selfsigned")


def test_first_run_writes_private_settings_the_playbook_accepts(tmp_path):
    pw = tmp_path / "smtp.pw"
    pw.write_text('p"a\\ss: word\n')
    r = install(tmp_path, *FIRST, "--smtp-host", "smtp.example.com", "--smtp-user", "mailer",
                "--smtp-password-file", str(pw), "--registration", "invite")
    assert r.returncode == 0, r.stdout + r.stderr

    inv = tmp_path / "etc" / "inventory.yml"
    assert stat.S_IMODE(os.stat(inv).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(inv.parent).st_mode) == 0o700
    data = yaml.safe_load(inv.read_text())
    assert data["all"]["hosts"]["cryptstorage"]["ansible_connection"] == "local"
    v = data["all"]["vars"]
    assert v["domain"] == "storage.example.com" and v["letsencrypt_email"] == "admin@example.com"
    assert v["tls_mode"] == "selfsigned" and v["registration"] == "invite"
    assert v["smtp_password"] == 'p"a\\ss: word' and v["smtp_from"] == "mailer" and v["smtp_port"] == 587
    assert v["require_email_verification"] == "true" and "required_factors" not in v
    # a local run must not lock the administrator out of a server reached with a password
    assert v["ssh_keys_only"] is False
    # what site.yml demands of the secrets
    assert len(v["db_root_password"]) >= 16 and len(v["db_password"]) >= 16
    for key in ("jwt_secret_key", "refresh_token_hmac_key", "totp_encryption_key"):
        assert re.fullmatch(r"[0-9a-f]{64}", v[key]), key
    assert len({v["db_root_password"], v["db_password"], v["jwt_secret_key"], v["refresh_token_hmac_key"],
                v["totp_encryption_key"]}) == 5


def test_without_a_mail_server_the_second_factor_is_optional_and_the_settings_say_why(tmp_path):
    r = install(tmp_path, *FIRST, "--no-smtp")
    assert r.returncode == 0, r.stdout + r.stderr
    text = (tmp_path / "etc" / "inventory.yml").read_text()
    v = yaml.safe_load(text)["all"]["vars"]
    assert v["smtp_host"] == "" and v["require_email_verification"] == "false" and v["required_factors"] == "password"
    assert v["registration"] == "open"
    assert "No mail server was given" in text


def test_a_second_run_keeps_the_saved_settings_and_secrets(tmp_path):
    assert install(tmp_path, *FIRST, "--no-smtp").returncode == 0
    inv = tmp_path / "etc" / "inventory.yml"
    before = inv.read_text()
    r = install(tmp_path, "--write-settings-only", "--yes", "--domain", "other.example.com", "--email", "x@example.com")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Using the saved settings" in r.stdout
    assert inv.read_text() == before


@pytest.mark.parametrize("os_release, message", [
    ('ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04"\n', "Ubuntu 24.04 or newer"),
    ('ID=debian\nVERSION_ID="11"\nPRETTY_NAME="Debian 11"\n', "Debian 12 or newer"),
    ('ID=fedora\nVERSION_ID="42"\nPRETTY_NAME="Fedora 42"\n', "not supported"),
])
def test_an_unsupported_system_is_refused_before_anything_is_written(tmp_path, os_release, message):
    r = install(tmp_path, *FIRST, "--no-smtp", os_release=os_release)
    assert r.returncode == 1
    assert message in r.stdout and "Nothing was changed" in r.stderr
    assert not (tmp_path / "etc").exists()


def test_a_port_taken_by_another_program_is_a_problem_but_our_own_services_are_not(tmp_path):
    taken = """*:80) echo 'LISTEN 0 511 *:80 *:* users:(("apache2",pid=1,fd=4))' ;;"""
    r = install(tmp_path, "--check", listening=taken)
    assert r.returncode == 1 and "port 80 is used by 'apache2'" in r.stdout

    ours = """*:80) echo 'LISTEN 0 511 *:80 *:* users:(("nginx",pid=1,fd=4))' ;;"""
    r = install(tmp_path, "--check", listening=ours)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "port 80 (already ours: nginx)" in r.stdout
    assert not (tmp_path / "etc").exists()          # --check changes nothing


def test_missing_answers_with_yes_are_an_error_not_a_guess(tmp_path):
    r = install(tmp_path, "--write-settings-only", "--yes", "--email", "admin@example.com")
    assert r.returncode == 1 and "missing setting" in r.stderr
    assert not (tmp_path / "etc" / "inventory.yml").exists()


def test_a_server_installed_from_another_machine_is_not_given_new_secrets(tmp_path):
    (tmp_path / "opt").mkdir()
    (tmp_path / "opt" / "docker-compose.yml").write_text("services: {}\n")
    r = install(tmp_path, *FIRST, "--no-smtp")
    assert r.returncode == 1 and "installed from another machine" in r.stderr
    assert not (tmp_path / "etc").exists()


def test_upgrade_needs_the_saved_settings(tmp_path):
    r = install(tmp_path, "--upgrade")
    assert r.returncode == 1 and "was not installed with install.sh" in r.stderr


# ---------------------------------------------------------------------------------------------
# cryptstorage-update
# ---------------------------------------------------------------------------------------------

class Server:
    """A pretend server: saved settings, an installed version, a release to download, and
    stand-ins for the backup command and the new version's install.sh that write down their calls."""

    def __init__(self, tmp_path, installed="0.1.2 (2026-11-12)", release="9.9.9"):
        self.tmp = tmp_path
        self.log = tmp_path / "calls.log"
        self.etc = tmp_path / "etc"
        self.etc.mkdir()
        self.storage = tmp_path / "storage"
        self.storage.mkdir()
        (self.etc / "inventory.yml").write_text(f'all:\n  vars:\n    domain: "x.example.com"\n    storage_dir: "{self.storage}"\n')
        (self.etc / "installed-version").write_text(installed + "\n")
        self.health = tmp_path / "health.json"
        self.health.write_text(json.dumps({"status": "ok", "version": installed}))
        self.backups = tmp_path / "backups"
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        script(self.bin / "cryptstorage-backup", f'''
echo "backup $* STORAGE_DIR=$STORAGE_DIR" >> "{self.log}"
[ ! -e "{tmp_path}/backup-fails" ] || {{ echo "disk full" >&2; exit 1; }}
for last; do :; done
mkdir -p "$last/cryptstorage-20261112T000000Z" && touch "$last/cryptstorage-20261112T000000Z/SHA256SUMS"
echo "Backup written to $last/cryptstorage-20261112T000000Z"
''')
        self.releases = tmp_path / "releases"
        self.add_release(release)

    def add_release(self, version, date="2026-12-01"):
        d = self.releases / f"v{version}"
        src = self.tmp / "src" / f"cryptstorage-{version}"
        src.mkdir(parents=True)
        (src / "VERSION").write_text(f"{version} ({date})\n")
        script(src / "install.sh", f'''
echo "install $* from $(cat "$(dirname "$0")/VERSION")" >> "{self.log}"
[ ! -e "{self.tmp}/install-fails" ] || exit 1
if [ "$1" = --upgrade ] && [ ! -e "{self.tmp}/api-stays-old" ]; then
  cp "$(dirname "$0")/VERSION" "{self.etc}/installed-version"
  printf '{{"status": "ok", "version": "%s"}}' "$(cat "$(dirname "$0")/VERSION")" > "{self.health}"
fi
''')
        d.mkdir(parents=True)
        pkg = d / f"cryptstorage-server-{version}.tar.gz"
        with tarfile.open(pkg, "w:gz") as t:
            t.add(src, arcname=src.name)
        digest = hashlib.sha256(pkg.read_bytes()).hexdigest()
        (d / "SHA256SUMS").write_text(f"{'0' * 64}  cryptclient-{version}-linux-amd64\n{digest}  {pkg.name}\n")
        (d / "SHA256SUMS.sigstore.json").write_text("{}")
        return d

    def cosign(self, ok=True):
        script(self.bin / "cosign", f'echo "cosign $*" >> "{self.log}"\nexit {0 if ok else 1}\n')

    def update(self, *args):
        env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin", CRYPTSTORAGE_ETC=str(self.etc),
                   CRYPTSTORAGE_STATE=str(self.tmp / "state"), CRYPTSTORAGE_RELEASES=f"file://{self.releases}",
                   CRYPTSTORAGE_RELEASES_API=f"file://{self.tmp}/releases.json",
                   CRYPTSTORAGE_HEALTH_URL=f"file://{self.health}", CRYPTSTORAGE_HEALTH_WAIT="3",
                   CRYPTSTORAGE_SKIP_SYSTEM_CHECKS="1")
        return subprocess.run([UPDATE, "--backup-dir", str(self.backups), *args], capture_output=True, text=True,
                              env=env, stdin=subprocess.DEVNULL)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []


GO = ("--yes", "--version", "9.9.9", "--no-signature-check")


def test_update_backs_up_what_an_upgrade_changes_then_installs_and_checks(tmp_path):
    s = Server(tmp_path)
    r = s.update(*GO)
    assert r.returncode == 0, r.stdout + r.stderr
    assert s.calls() == [
        "install --check from 9.9.9 (2026-12-01)",
        f"backup --without-files {s.backups} STORAGE_DIR={s.storage}",
        "install --upgrade from 9.9.9 (2026-12-01)",
    ]
    assert "CryptStorage 9.9.9 (2026-12-01) is running." in r.stdout
    assert f"Backup taken before the upgrade: {s.backups}/cryptstorage-20261112T000000Z" in r.stdout
    assert "the users' files stayed in" in r.stdout
    assert "signature not checked" in r.stdout
    assert stat.S_IMODE(os.stat(s.backups).st_mode) == 0o700


def test_full_takes_a_complete_backup(tmp_path):
    s = Server(tmp_path)
    r = s.update(*GO, "--full")
    assert r.returncode == 0, r.stdout + r.stderr
    assert s.calls()[1] == f"backup {s.backups} STORAGE_DIR={s.storage}"
    assert "the users' files stayed in" not in r.stdout


def test_a_package_that_does_not_match_the_checksums_is_not_installed(tmp_path):
    s = Server(tmp_path)
    pkg = s.releases / "v9.9.9" / "cryptstorage-server-9.9.9.tar.gz"
    pkg.write_bytes(pkg.read_bytes() + b"x")
    r = s.update(*GO)
    assert r.returncode == 1 and "does not match the release's SHA256SUMS" in r.stderr
    assert s.calls() == []


def test_without_cosign_the_update_stops_unless_told_to_go_on(tmp_path):
    s = Server(tmp_path)
    r = s.update("--yes", "--version", "9.9.9")
    assert r.returncode == 1 and "cosign is not installed" in r.stderr
    assert s.calls() == []


def test_the_signature_must_come_from_the_release_workflow_of_that_tag(tmp_path):
    s = Server(tmp_path)
    s.cosign(ok=True)
    r = s.update("--yes", "--version", "9.9.9")
    assert r.returncode == 0, r.stdout + r.stderr
    cosign = s.calls()[0]
    assert "--certificate-identity https://github.com/valveo/cryptstorage/.github/workflows/release.yml@refs/tags/v9.9.9" in cosign
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in cosign
    assert "signature is valid" in r.stdout


def test_an_invalid_signature_stops_before_anything_is_touched(tmp_path):
    s = Server(tmp_path)
    s.cosign(ok=False)
    r = s.update("--yes", "--version", "9.9.9")
    assert r.returncode == 1 and "signature of SHA256SUMS is not valid" in r.stderr
    assert [c.split()[0] for c in s.calls()] == ["cosign"]


def test_a_failed_backup_stops_the_upgrade(tmp_path):
    s = Server(tmp_path)
    (tmp_path / "backup-fails").touch()
    r = s.update(*GO)
    assert r.returncode == 1 and "the backup failed, so the upgrade was not started" in r.stderr
    assert not any(c.startswith("install --upgrade") for c in s.calls())


def test_a_failed_install_or_a_server_that_stays_old_names_the_backup(tmp_path):
    s = Server(tmp_path)
    (tmp_path / "api-stays-old").touch()
    r = s.update(*GO)
    assert r.returncode == 1
    assert "does not report it" in r.stderr and "cryptstorage-20261112T000000Z" in r.stderr

    (tmp_path / "install-fails").touch()
    r = s.update(*GO)
    assert r.returncode == 1          # the stand-in's --check fails first
    assert "cannot be installed here" in r.stderr


def test_same_and_older_versions_are_not_installed(tmp_path):
    s = Server(tmp_path, installed="9.9.9 (2026-12-01)")
    r = s.update(*GO)
    assert r.returncode == 0 and "Nothing to do" in r.stdout
    s.add_release("9.9.8")
    r = s.update("--yes", "--version", "9.9.8", "--no-signature-check")
    assert r.returncode == 1 and "older than the installed 9.9.9" in r.stderr
    assert s.calls() == []


def test_check_finds_the_highest_published_release_and_changes_nothing(tmp_path):
    s = Server(tmp_path)
    (tmp_path / "releases.json").write_text(json.dumps([
        {"tag_name": "v9.9.9", "draft": False, "prerelease": True},
        {"tag_name": "v10.0.0", "draft": True},
        {"tag_name": "v9.10.0", "draft": False, "prerelease": True},
        {"tag_name": "nightly", "draft": False},
    ]))
    r = s.update("--check")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Installed: 0.1.2 (2026-11-12)" in r.stdout and "Available: 9.10.0" in r.stdout
    assert s.calls() == [] and not (tmp_path / "state").exists() and not s.backups.exists()


def test_from_a_directory_without_network(tmp_path):
    s = Server(tmp_path)
    r = s.update("--yes", "--no-signature-check", "--from", str(s.releases / "v9.9.9"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert s.calls()[-1] == "install --upgrade from 9.9.9 (2026-12-01)"


def test_a_server_managed_from_another_machine_is_told_so(tmp_path):
    s = Server(tmp_path)
    (s.etc / "inventory.yml").unlink()
    r = s.update(*GO)
    assert r.returncode == 1 and "was not installed with install.sh" in r.stderr


def test_without_yes_it_asks_and_no_answer_means_no(tmp_path):
    s = Server(tmp_path)
    r = s.update("--version", "9.9.9", "--no-signature-check")
    assert r.returncode == 1 and "nothing was changed" in r.stderr
    assert s.calls() == []
