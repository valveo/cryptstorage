"""
The fail2ban filter against nginx access-log lines in the format the playbook sets
(ansible/roles/ssl: log_format cryptstorage, last field step=<X-Auth-Step>).

Every ordinary sign-in gets one 401 that only asks for the second factor. Counting it banned whole
offices behind one address, so it must not match; real failures must.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILTER = ROOT / "ansible/roles/fail2ban/files/cryptstorage.conf"
NGINX = ROOT / "ansible/roles/ssl/templates/nginx-https.conf.j2"


def _failregex() -> re.Pattern:
    line = next(l for l in FILTER.read_text().splitlines() if l.startswith("failregex"))
    return re.compile(line.split("=", 1)[1].strip().replace("<HOST>", r"(?P<host>\S+)"))


def _line(request: str, status: int, step: str = "-", agent: str = "cryptclient") -> str:
    return (f'203.0.113.7 - - [12/Nov/2026:09:00:01 +0000] "{request} HTTP/1.1" {status} 31 '
            f'"-" "{agent}" step={step}')


def test_second_factor_step_is_not_a_failure():
    rx = _failregex()
    assert not rx.search(_line("POST /api/auth/login", 401, "second-factor"))
    assert not rx.search(_line("POST /api/auth/recover-e2ee", 401, "second-factor"))
    assert not rx.search(_line("POST /api/auth/login", 200))


def test_real_failures_match():
    rx = _failregex()
    for path in ("login", "recover-e2ee", "passkey/begin", "passkey/finish"):
        m = rx.search(_line(f"POST /api/auth/{path}", 401))
        assert m and m.group("host") == "203.0.113.7", path
    assert rx.search(_line("POST /api/auth/login", 429))


def test_client_cannot_fake_the_step():
    """The step field is the last one and comes from the API's answer; a User-Agent that imitates it
    does not turn a failure into a step."""
    rx = _failregex()
    assert rx.search(_line("POST /api/auth/login", 401, agent='x" step=second-factor'))


def test_nginx_writes_the_field_the_filter_reads():
    conf = NGINX.read_text()
    assert "step=$upstream_http_x_auth_step'" in conf
    assert "cryptstorage-access.log cryptstorage;" in conf
