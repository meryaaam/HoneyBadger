"""HTTP honeypot tests: what the sensor answers and what it records."""

import asyncio

from aiohttp.test_utils import TestClient, TestServer

from config import Settings
from httpd import HttpHoneypot, recorded_path
from mitre import classify


class CaptureBus:
    def __init__(self):
        self.events = []

    def publish(self, event):
        self.events.append(event)


async def _request(method, path, **kwargs):
    bus = CaptureBus()
    honeypot = HttpHoneypot(Settings(), bus)
    async with TestClient(TestServer(honeypot._app)) as client:
        response = await client.request(method, path, **kwargs)
        await response.read()
        return response.status, bus.events


def request(method, path, **kwargs):
    return asyncio.run(_request(method, path, **kwargs))


def test_phpmyadmin_login_post_does_not_crash():
    # Regression: the POST route called fake_phpmyadmin(request), which takes no argument (HTTP 500).
    status, events = request("POST", "/phpmyadmin", data={"pma_username": "root", "pma_password": "x"})
    assert status == 200
    assert len(events) == 1


def test_query_string_is_recorded_so_exploits_are_classified():
    # Regression: only request.path was stored, so "/?id=1' OR 1=1--" was recorded as "/".
    status, events = request("GET", "/?id=1%27%20OR%201%3D1--")
    assert "OR 1=1" in events[0].http_path
    assert classify(events[0])[0] == "T1190"


def test_password_in_query_string_is_redacted():
    status, events = request("GET", "/login?user=admin&pwd=hunter2")
    assert "hunter2" not in events[0].model_dump_json()
    assert "pwd=REDACTED" in events[0].http_path


def test_login_form_password_is_hashed_and_classified_as_credential_attack():
    status, events = request("POST", "/wp-login.php", data={"log": "admin", "pwd": "hunter2"})
    event = events[0]
    assert event.login_info.username == "admin"
    assert event.login_info.password_hash.startswith("sha256:")
    assert "hunter2" not in event.model_dump_json()
    assert classify(event)[0] == "T1110.004"


def test_recorded_path_is_bounded():
    assert len(recorded_path("/x", "q=" + "a" * 5000)) == 2048
