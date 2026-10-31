"""
Web UI against a stub API, using PHP's built-in server.
Skipped when `php` is not installed.
"""
import http.client
import json
import re
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

ROOT = __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__)))
pytestmark = pytest.mark.skipif(shutil.which("php") is None, reason="php not installed")

USER = {"id": "1", "username": "alice", "email": "a@example.com", "email_verified": True,
        "storage_created": True,
        "quota_bytes": 10 * 2**30,
        "created_at": "2026-01-01T00:00:00", "last_login": None}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class StubAPI:
    def __init__(self):
        self.requests = []
        self.routes = {}
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode() if length else ""
                stub.requests.append({"method": self.command, "path": self.path,
                                      "headers": dict(self.headers), "body": body})
                status, payload = stub.routes.get((self.command, self.path.split("?")[0]),
                                                  (404, {"detail": "not found"}))
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _handle

        self.port = _free_port()
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def last(self, method, path):
        return [r for r in self.requests if r["method"] == method and r["path"].split("?")[0] == path][-1]


@pytest.fixture
def web():
    api = StubAPI()
    api.routes = {
        ("POST", "/auth/login"): (200, {"access_token": "jwt-1", "refresh_token": "r", "token_type": "bearer"}),
        ("GET", "/users/me"): (200, USER),
        ("GET", "/storage/usage"): (200, {"used_bytes": 0, "quota_bytes": 10 * 2**30, "free_bytes": 10 * 2**30,
                                          "percent_used": 0}),
        ("POST", "/auth/register"): (201, {"message": "Registered. Check your email."}),
        ("POST", "/users/me/totp/setup"): (200, {"secret": "JBSWY3DPEHPK3PXP", "otpauth_uri": "otpauth://x",
                                                 "message": "ok"}),
        ("DELETE", "/storage"): (200, {"message": "Account and storage permanently deleted."}),
        ("GET", "/users/me/escrow"): (200, {"has_escrow": False, "recovery_policy": "user",
                                            "escrow_key_fingerprint": None, "sealed_key_fingerprint": None,
                                            "settings_changed_at": "2026-10-26T20:00:00", "settings_log_ok": True}),
    }
    port = _free_port()
    env = {"PATH": __import__("os").environ["PATH"], "API_BASE_URL": f"http://127.0.0.1:{api.port}"}
    proc = subprocess.Popen(["php", "-S", f"127.0.0.1:{port}", "-t", f"{ROOT}/webui"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)

    class Browser:
        cookie = None

        def request(self, method, path, form=None, headers=None):
            h = {"X-Real-IP": "198.51.100.7"}
            h.update(headers or {})
            if self.cookie:
                h["Cookie"] = self.cookie
            body = None
            if form is not None:
                from urllib.parse import urlencode
                body = urlencode(form)
                h["Content-Type"] = "application/x-www-form-urlencoded"
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            text = r.read().decode()
            sc = r.getheader("Set-Cookie")
            if sc:
                self.cookie = sc.split(";")[0]
            return r.status, {k.lower(): v for k, v in r.getheaders()}, text

        def csrf(self, page="/index.php"):
            _, _, html = self.request("GET", page)
            return re.search(r'name="csrf_token" value="([0-9a-f]{64})"', html).group(1)

    b = Browser()
    b.api = api
    yield b
    proc.terminate()
    api.server.shutdown()


KEY = "ab" * 32      # what the browser sends instead of the password: 64 hex characters


def test_pages_send_csp_with_matching_nonce_and_no_inline_handlers(web):
    status, headers, html = web.request("GET", "/index.php")
    assert status == 200
    csp = headers["content-security-policy"]
    nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
    assert f'<script nonce="{nonce}">' in html
    assert "'unsafe-inline'" not in csp.split("style-src")[0]       # scripts never allow inline
    assert not re.search(r"\son(click|submit|load|error)=", html)
    assert headers["x-content-type-options"] == "nosniff"


def test_post_without_or_with_wrong_csrf_token_is_refused(web):
    web.csrf()
    form = {"mode": "login", "username": "alice", "password": KEY}
    assert web.request("POST", "/index.php", form)[0] == 403
    assert web.request("POST", "/index.php", dict(form, csrf_token="0" * 64))[0] == 403
    assert not [r for r in web.api.requests if r["path"] == "/auth/login"]   # never reached the API


def test_the_real_password_is_never_forwarded_to_the_api(web):
    token = web.csrf()
    for mode in ("login", "register"):
        status, _, html = web.request("POST", "/index.php", {
            "mode": mode, "username": "alice", "email": "a@example.com",
            "password": "a plain password, not a derived key", "csrf_token": token})
        assert status == 200 and "could not prepare the password" in html
    assert not [r for r in web.api.requests if r["path"] in ("/auth/login", "/auth/register")]


def test_client_ip_is_forwarded_and_cannot_be_spoofed(web):
    web.api.routes[("POST", "/auth/login")] = (401, {"detail": "Invalid username or password."})
    token = web.csrf()
    status, _, html = web.request(
        "POST", "/index.php", {"mode": "login", "username": "alice", "password": KEY, "csrf_token": token},
        headers={"X-Forwarded-For": "6.6.6.6"})
    assert status == 200 and "Invalid username or password." in html
    sent = web.api.last("POST", "/auth/login")["headers"]
    assert sent["X-Forwarded-For"] == "198.51.100.7"                  # from X-Real-IP, not the client's header


def _login(web):
    token = web.csrf()
    status, headers, _ = web.request("POST", "/index.php", {
        "mode": "login", "username": "alice", "password": KEY, "csrf_token": token})
    assert status == 302 and headers["location"] == "dashboard.php"
    assert json.loads(web.api.last("POST", "/auth/login")["body"])["password"] == KEY


def test_dashboard_shows_usage_only_and_has_no_mount_or_key_forms(web):
    _login(web)
    status, _, html = web.request("GET", "/dashboard.php")
    assert status == 200 and "never shows what is stored" in html
    for gone in ('value="mount"', 'value="umount"', 'value="update_ssh_key"', 'value="new_recovery_code"',
                 'value="change_password"'):
        assert gone not in html
    assert not [r for r in web.api.requests if r["path"] in ("/storage/status", "/storage/mount")]


def test_old_dashboard_actions_do_nothing(web):
    _login(web)
    token = web.csrf("/dashboard.php")
    for action in ("mount", "umount", "update_ssh_key", "change_password", "new_recovery_code"):
        status, _, _ = web.request("POST", "/dashboard.php", {"action": action, "password": KEY, "csrf_token": token})
        assert status == 200
    assert not [r for r in web.api.requests if r["method"] != "GET" and r["path"].startswith(("/storage", "/users/me/p", "/users/me/s", "/users/me/r"))]


def test_dashboard_actions_need_the_csrf_token(web):
    _login(web)
    for form in ({"action": "totp_setup", "password": KEY}, {"action": "delete_account", "password": KEY},
                 {"action": "delete_account", "password": KEY, "csrf_token": "0" * 64}):
        assert web.request("POST", "/dashboard.php", form)[0] == 403
    assert not [r for r in web.api.requests if r["path"] in ("/storage", "/users/me/totp/setup")
                and r["method"] in ("POST", "DELETE")]


def test_dashboard_never_asks_for_or_forwards_the_password(web):
    """#74: sensitive actions are confirmed by a recent sign-in, so the page has no password field and a
    posted password goes nowhere."""
    _login(web)
    status, _, html = web.request("GET", "/dashboard.php")
    assert status == 200 and 'type="password"' not in html and "derive.js" not in html
    token = web.csrf("/dashboard.php")
    status, _, html = web.request("POST", "/dashboard.php", {"action": "totp_setup", "password": KEY, "csrf_token": token})
    assert status == 200 and "JBSWY3DPEHPK3PXP" in html
    assert json.loads(web.api.last("POST", "/users/me/totp/setup")["body"]) == {}
    status, headers, _ = web.request("POST", "/dashboard.php", {"action": "delete_account", "password": KEY, "csrf_token": token})
    assert status == 302 and headers["location"] == "index.php?deleted=1"
    assert json.loads(web.api.last("DELETE", "/storage")["body"]) == {}


def test_an_old_sign_in_is_asked_to_sign_in_again(web):
    web.api.routes[("DELETE", "/storage")] = (401, {"detail": "REAUTH_REQUIRED"})
    _login(web)
    token = web.csrf("/dashboard.php")
    status, _, html = web.request("POST", "/dashboard.php", {"action": "delete_account", "csrf_token": token})
    assert status == 200 and "sign in again" in html and 'href="logout.php"' in html


def test_registration_sends_no_ssh_key_and_shows_no_recovery_code(web):
    token = web.csrf()
    status, _, html = web.request("POST", "/index.php", {
        "mode": "register", "username": "alice", "email": "a@example.com", "password": KEY, "csrf_token": token})
    assert status == 200 and "cryptclient setup" in html and 'id="recovery-code"' not in html
    assert json.loads(web.api.last("POST", "/auth/register")["body"]) == {
        "username": "alice", "email": "a@example.com", "password": KEY}


def test_recovery_page_only_explains_the_app_route(web):
    status, headers, html = web.request("GET", "/recover.php")
    assert status == 200 and "content-security-policy" in headers
    assert "cryptclient recover" in html and "<form" not in html
    assert web.request("POST", "/recover.php", {"username": "alice"})[0] in (200, 403)
    assert not [r for r in web.api.requests if r["path"] == "/auth/recover"]


def test_dashboard_points_to_two_factor_setup_when_the_server_requires_it(web):
    web.api.routes[("GET", "/storage/usage")] = (403, {"detail": "SECOND_FACTOR_SETUP_REQUIRED"})
    _login(web)
    status, _, html = web.request("GET", "/dashboard.php")
    assert status == 200 and "requires two-factor authentication" in html and 'value="totp_setup"' in html


def test_turning_on_two_factor_sends_the_email_code(web):
    web.api.routes[("POST", "/users/me/totp/enable")] = (200, {"message": "on", "backup_codes": ["AAAA-BBBB"]})
    _login(web)
    token = web.csrf("/dashboard.php")
    _, _, html = web.request("POST", "/dashboard.php", {"action": "totp_setup", "password": KEY, "csrf_token": token})
    assert 'name="email_code"' in html
    status, _, html = web.request("POST", "/dashboard.php", {
        "action": "totp_enable", "code": "123456", "email_code": " 87654321 ", "csrf_token": token})
    assert status == 200 and "AAAA-BBBB" in html
    assert json.loads(web.api.last("POST", "/users/me/totp/enable")["body"]) == {"code": "123456", "email_code": "87654321"}


def test_waiting_deletion_keeps_the_session_and_can_be_cancelled(web):
    web.api.routes[("DELETE", "/storage")] = (200, {"message": "Your account and all data will be deleted on X.",
                                                    "pending": True, "change_id": "c1"})
    web.api.routes[("GET", "/users/me/pending-changes")] = (200, [
        {"id": "c1", "kind": "delete", "created_at": "2026-10-25T20:00:00", "due_at": "2026-10-26T20:00:00"}])
    web.api.routes[("DELETE", "/users/me/pending-changes/c1")] = (200, {"message": "Cancelled."})
    _login(web)
    token = web.csrf("/dashboard.php")
    status, _, html = web.request("POST", "/dashboard.php", {
        "action": "delete_account", "code": "123456", "csrf_token": token})
    assert status == 200 and "will be deleted on X." in html
    assert "Waiting changes" in html and "Deletion of the account and all data" in html and "2026-10-26 20:00" in html
    assert json.loads(web.api.last("DELETE", "/storage")["body"]) == {"totp_code": "123456"}
    status, _, html = web.request("POST", "/dashboard.php", {"action": "cancel_change", "change_id": "c1", "csrf_token": token})
    assert status == 200 and "Cancelled." in html
    assert web.api.last("DELETE", "/users/me/pending-changes/c1")


def test_cancel_link_needs_a_click_and_a_csrf_token(web):
    web.api.routes[("POST", "/auth/cancel-change")] = (200, {"message": "Cancelled. Nothing was changed."})
    status, headers, html = web.request("GET", "/cancel.php?token=abc.def")
    assert status == 200 and "content-security-policy" in headers and 'value="abc.def"' in html
    assert not [r for r in web.api.requests if r["path"] == "/auth/cancel-change"]      # opening is not cancelling
    assert web.request("POST", "/cancel.php", {"token": "abc.def"})[0] == 403
    token = re.search(r'name="csrf_token" value="([0-9a-f]{64})"', html).group(1)
    status, _, html = web.request("POST", "/cancel.php", {"token": "abc.def", "csrf_token": token})
    assert status == 200 and "Nothing was changed." in html
    assert json.loads(web.api.last("POST", "/auth/cancel-change")["body"]) == {"token": "abc.def"}
    _, _, html = web.request("GET", "/cancel.php?token=<script>")
    assert "not complete" in html and "<script>" not in html.split("<body>")[1]


def test_the_link_in_the_verification_email_works(web, caplog, monkeypatch):
    import email_verification
    monkeypatch.setattr(email_verification, "SMTP_HOST", "")          # dev mode logs the link
    with caplog.at_level("INFO"):
        email_verification.send_verification_email("a@example.com", "alice", "abc.def-ghi")
    assert "/verify-email.php?token=abc.def-ghi" in caplog.text
    web.api.routes[("POST", "/auth/verify-email")] = (200, {"message": "Email verified. You can now log in."})
    status, headers, html = web.request("GET", "/verify-email.php?token=abc.def-ghi")
    assert status == 200 and "content-security-policy" in headers and "Email verified." in html
    assert json.loads(web.api.last("POST", "/auth/verify-email")["body"]) == {"token": "abc.def-ghi"}
    web.api.routes[("POST", "/auth/verify-email")] = (400, {"detail": "Invalid or expired verification token."})
    assert "Invalid or expired" in web.request("GET", "/verify-email.php?token=x")[2]
    assert "not complete" in web.request("GET", "/verify-email.php")[2]


def test_dashboard_shows_the_users_escrow_state(web):
    _login(web)
    html = web.request("GET", "/dashboard.php")[2]
    assert "Escrow is OFF for you" in html and "tampered" not in html
    fp = "ab12" * 16
    web.api.routes[("GET", "/users/me/escrow")] = (200, {
        "has_escrow": True, "recovery_policy": "both", "escrow_key_fingerprint": fp,
        "sealed_key_fingerprint": fp, "sealed_at": "2026-10-26T20:00:00",
        "settings_changed_at": "2026-10-26T20:00:00", "settings_log_ok": False})
    html = web.request("GET", "/dashboard.php")[2]
    assert "Escrow is ON for you" in html and "ab12 ab12" in html and "tampered" in html



def test_a_lost_stick_can_be_removed(web):
    sid = "0f8fad5b-d9cb-469f-a165-70867728950e"
    web.api.routes[("GET", "/users/me/sticks")] = (200, [{"id": sid, "name": "laptop", "created_at": "2026-10-26T10:00:00",
                                                          "last_used_at": "2026-10-26T11:00:00"}])
    web.api.routes[("DELETE", f"/users/me/sticks/{sid}")] = (200, {"message": "Stick removed."})
    _login(web)
    status, _, html = web.request("GET", "/dashboard.php")
    assert status == 200 and "USB sticks" in html and "laptop" in html
    token = web.csrf("/dashboard.php")
    status, _, html = web.request("POST", "/dashboard.php", {
        "action": "stick_delete", "stick_id": sid, "code": "123456", "csrf_token": token})
    assert status == 200 and "Stick removed" in html
    assert json.loads(web.api.last("DELETE", f"/users/me/sticks/{sid}")["body"]) == {"totp_code": "123456"}


def test_a_lost_stick_can_be_locked_and_shows_its_state(web):
    sid = "0f8fad5b-d9cb-469f-a165-70867728950e"
    web.api.routes[("GET", "/users/me/sticks")] = (200, [{"id": sid, "name": "laptop", "created_at": "2026-10-26T10:00:00"}])
    web.api.routes[("POST", f"/users/me/sticks/{sid}/lock")] = (200, {"message": "Stick locked."})
    _login(web)
    html = web.request("GET", "/dashboard.php")[2]
    assert "Lost? Lock it" in html and "Remove for good" in html
    token = web.csrf("/dashboard.php")
    status, _, html = web.request("POST", "/dashboard.php", {"action": "stick_lock", "stick_id": sid, "csrf_token": token})
    assert status == 200 and "Stick locked" in html
    assert web.api.last("POST", f"/users/me/sticks/{sid}/lock") is not None
    # locked: no lock button; waiting removal: the date and no remove button either
    web.api.routes[("GET", "/users/me/sticks")] = (200, [{"id": sid, "name": "laptop", "created_at": "2026-10-26T10:00:00",
                                                          "locked_at": "2026-10-29T10:00:00"}])
    html = web.request("GET", "/dashboard.php")[2]
    assert "Lost? Lock it" not in html and "unlock it by connecting" in html and "Remove for good" in html
    web.api.routes[("GET", "/users/me/sticks")] = (200, [{"id": sid, "name": "laptop", "created_at": "2026-10-26T10:00:00",
                                                          "locked_at": "2026-10-29T10:00:00",
                                                          "removal_due": "2026-10-30T10:00:00"}])
    html = web.request("GET", "/dashboard.php")[2]
    assert "removed on 2026-10-30 10:00" in html and "Remove for good" not in html


def test_password_sign_in_asks_for_a_web_session_and_is_labelled(web):
    status, _, html = web.request("GET", "/index.php")
    assert "Sign in with passkey" in html and "cryptclient web-login" in html and "trusts this server" in html
    _login(web)
    assert json.loads(web.api.last("POST", "/auth/login")["body"])["web"] is True


def test_sign_in_with_the_passkey_alone(web):
    web.api.routes[("POST", "/auth/web/passkey/begin")] = (200, {"options": {"challenge": "abc", "allowCredentials": []},
                                                                 "session": "s1"})
    web.api.routes[("POST", "/auth/web/passkey/finish")] = (200, {"access_token": "jwt-web", "token_type": "bearer"})
    token = web.csrf()
    status, _, html = web.request("POST", "/index.php", {"mode": "pk_web_begin", "username": "alice", "csrf_token": token})
    assert status == 200 and "Use passkey" in html and 'id="passkey-options"' in html
    assert json.loads(web.api.last("POST", "/auth/web/passkey/begin")["body"]) == {"username": "alice"}
    cred = json.dumps({"id": "x", "response": {}})
    status, headers, _ = web.request("POST", "/index.php", {"mode": "pk_web", "credential": cred, "csrf_token": token})
    assert status == 302 and headers["location"] == "dashboard.php"
    assert json.loads(web.api.last("POST", "/auth/web/passkey/finish")["body"])["session"] == "s1"
    assert not [r for r in web.api.requests if r["path"] == "/auth/login"]


def test_sign_in_handed_over_by_the_app(web):
    web.api.routes[("POST", "/auth/web/ticket/redeem")] = (200, {"access_token": "jwt-web", "token_type": "bearer"})
    # the ticket comes after "#" in the link; the page's script posts it, so a GET never carries it
    web.request("GET", "/index.php?ticket=t.k.n")
    assert not [r for r in web.api.requests if r["path"] == "/auth/web/ticket/redeem"]
    token = web.csrf()
    assert 'id="ticket-form"' in web.request("GET", "/index.php")[2]
    status, headers, _ = web.request("POST", "/index.php", {"mode": "ticket", "ticket": "t.k.n", "csrf_token": token})
    assert status == 302 and headers["location"] == "dashboard.php"
    assert json.loads(web.api.last("POST", "/auth/web/ticket/redeem")["body"]) == {"ticket": "t.k.n"}
    assert web.api.last("GET", "/users/me")["headers"]["Authorization"] == "Bearer jwt-web"


def test_a_bad_ticket_shows_why(web):
    web.api.routes[("POST", "/auth/web/ticket/redeem")] = (401, {"detail": "This sign-in link is invalid, used or expired."})
    token = web.csrf()
    status, _, html = web.request("POST", "/index.php", {"mode": "ticket", "ticket": "old", "csrf_token": token})
    assert status == 200 and "invalid, used or expired" in html


def test_footer_shows_the_build_version(web):
    html = web.request("GET", "/index.php")[2]
    assert "AGPL-3.0 &middot; version dev" in html


def test_storage_bar_shows_binary_units_and_free_space(web):
    web.api.routes[("GET", "/storage/usage")] = (200, {"used_bytes": int(9.5 * 2**30), "quota_bytes": 10 * 2**30})
    _login(web)
    html = web.request("GET", "/dashboard.php")[2]
    assert "9.5\u00a0GiB used" in html and "of 10\u00a0GiB" in html
    assert 'aria-valuenow="95"' in html and "quota-fill full" in html and "Storage almost full" in html


def test_dashboard_sections_and_getting_started(web):
    _login(web)
    html = web.request("GET", "/dashboard.php")[2]
    for tab in ("overview", "signin", "sticks", "account"):
        assert f'data-tab-panel="{tab}"' in html
    assert "Getting started" in html and "0 of 3 done" in html
    # escrow off: only in the account section, not as an overview panel
    assert "Escrow is on" not in html and "Escrow is OFF for you" in html


def test_two_factor_key_is_grouped_and_copyable(web):
    _login(web)
    token = web.csrf("/dashboard.php")
    html = web.request("POST", "/dashboard.php", {"csrf_token": token, "action": "totp_setup"})[2]
    assert ">JBSW Y3DP EHPK 3PXP</code>" in html and 'data-copy="JBSWY3DPEHPK3PXP"' in html
    assert 'data-uri="otpauth://x"' in html and 'src="assets/qrcode.js"' in html


def test_pages_load_no_fonts_or_styles_from_other_servers(web):
    for page in ("/index.php", "/recover.php", "/verify-email.php", "/cancel.php?token=abc", "/passkey-approve.php"):
        _, headers, html = web.request("GET", page)
        assert "googleapis" not in html and "gstatic" not in html, page
        assert 'href="assets/fonts/fonts.css"' in html, page
        assert "font-src 'self'" in headers["content-security-policy"], page


def test_finnish_from_the_browser_and_the_switch(web):
    html = web.request("GET", "/index.php", headers={"Accept-Language": "fi-FI,fi;q=0.9,en;q=0.8"})[2]
    assert '<html lang="fi">' in html and "Kirjaudu pääsyavaimella" in html and 'hreflang="en"' in html
    status, headers, html = web.request("GET", "/index.php?lang=en",
                                        headers={"Accept-Language": "fi"})
    assert '<html lang="en">' in html and "lang=en" in headers.get("set-cookie", "")


def test_every_text_has_a_finnish_translation():
    """Each t('...') text in the web UI (and the scripts' texts) is in lang/fi.php, with the same %s/%d."""
    import glob
    src = "\n".join(open(f, encoding="utf-8").read() for f in glob.glob(f"{ROOT}/webui/*.php"))
    keys = {m.replace("\\'", "'") for m in re.findall(r"\bt\(\s*'((?:[^'\\]|\\.)*)'", src)}
    keys |= {m.replace("\\'", "'") for m in re.findall(r"^\s*'((?:[^'\\]|\\.)*)',$",
             src[src.index("$keys = ["):src.index("];", src.index("$keys = ["))], re.M)}
    keys |= set(re.findall(r"action_error\(\$res, '([^']*)'\)", src))
    out = subprocess.run(["php", "-r", f"echo json_encode(require '{ROOT}/webui/lang/fi.php');"],
                         capture_output=True, text=True, check=True).stdout
    fi = json.loads(out)
    missing = sorted(k for k in keys if k not in fi)
    assert not missing, missing
    for k in keys:
        assert re.findall(r"%[sd%]", k) == re.findall(r"%[sd%]", fi[k]), k
