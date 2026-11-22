"""REST + WebSocket API tests against a real PostgreSQL database.

The API reads events from PostgreSQL, so these tests need a database. Point
HB_TEST_DATABASE_URL at an empty, disposable database, for example:

    export HB_TEST_DATABASE_URL=postgresql+asyncpg://honeybadger:honeybadger@127.0.0.1:15432/honeybadger_test

Without it the tests are skipped. Every test empties the events table first.
"""

import asyncio
import datetime as dt
import os

import pytest
from aiohttp.test_utils import TestClient, TestServer
from sqlalchemy import delete

from api import create_app
from bus import EventBus
from db.models import Base, Event
from schemas import SSH_HANDSHAKE_KIND, EnrichedEvent, LoginInfo, Service, Severity
from sshd import hash_password
from storage import Storage

DATABASE_URL = os.getenv("HB_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="set HB_TEST_DATABASE_URL to run the API tests")


def _event(command="whoami", *, when=None, technique="T1059", severity=Severity.MEDIUM, kind="command"):
    return EnrichedEvent(
        service=Service.SSH, source_ip="203.0.113.7", destination_ip="127.0.0.1",
        timestamp=when or dt.datetime.now(dt.timezone.utc),
        login_info=LoginInfo(username="root", password_hash=hash_password("hunter2")),
        command=command, source_port=51000, destination_port=22,
        additional_info={"event_kind": kind}, technique_id=technique, severity=severity,
    )


def _handshake():
    return EnrichedEvent(
        service=Service.SSH, source_ip="198.51.100.9", destination_ip="127.0.0.1",
        timestamp=dt.datetime.now(dt.timezone.utc), source_port=52000, destination_port=22,
        additional_info={"event_kind": SSH_HANDSHAKE_KIND, "client_version": "x"},
    )


async def _scenario(fn):
    storage = Storage(DATABASE_URL)
    await storage.init()
    async with storage._engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        await connection.execute(delete(Event))
    bus: EventBus[EnrichedEvent] = EventBus("enriched-test")
    app = create_app(bus, storage)
    try:
        async with TestClient(TestServer(app)) as client:
            return await fn(client, storage, bus)
    finally:
        await storage.close()


def run(fn):
    return asyncio.run(_scenario(fn))


def test_health_reports_database_ok():
    async def scenario(client, storage, bus):
        response = await client.get("/health")
        body = await response.json()
        assert response.status == 200
        assert body["status"] == "ok" and body["db"] == "ok"
        assert body["version"] and body["uptime_s"] >= 0
    run(scenario)


def test_events_are_newest_first_and_wrapped():
    async def scenario(client, storage, bus):
        now = dt.datetime.now(dt.timezone.utc)
        await storage.events.insert(_event("pwd", when=now - dt.timedelta(seconds=2)))
        await storage.events.insert(_event("id", when=now))
        latest = await (await client.get("/events?limit=1")).json()
        assert [item["command"] for item in latest["items"]] == ["id"]
        everything = await (await client.get("/events")).json()
        assert [item["command"] for item in everything["items"]] == ["id", "pwd"]
    run(scenario)


def test_handshake_events_stay_off_the_feed():
    # Regression: after the move to PostgreSQL, SSH handshakes (no attacker action) filled the feed.
    async def scenario(client, storage, bus):
        await storage.events.insert(_handshake())
        await storage.events.insert(_event("whoami"))
        body = await (await client.get("/events")).json()
        assert [item["command"] for item in body["items"]] == ["whoami"]
    run(scenario)


def test_event_filters_and_validation():
    async def scenario(client, storage, bus):
        await storage.events.insert(_event("pwd"))
        assert (await (await client.get("/events?service=ssh")).json())["items"]
        assert (await (await client.get("/events?service=http")).json())["items"] == []
        assert (await (await client.get("/events?technique=T1110")).json())["items"] == []
        assert (await (await client.get("/events?technique=T1059")).json())["items"]
        for path in ["/events?limit=0", "/events?limit=abc", "/events?service=ftp",
                     "/events?severity=extreme", "/events?technique=T9999", "/events?since=yesterday"]:
            response = await client.get(path)
            assert response.status == 400, path
            assert "error" in await response.json()
    run(scenario)


def test_stats_count_the_window_and_reject_unknown_windows():
    async def scenario(client, storage, bus):
        now = dt.datetime.now(dt.timezone.utc)
        await storage.events.insert(_event("whoami", when=now))
        await storage.events.insert(_event("id", when=now - dt.timedelta(days=2)))
        body = await (await client.get("/stats?window=1h")).json()
        assert body["window"] == "1h"  # dashboard/src/types.ts: Stats.window is a WindowKey
        assert body["totals"]
        assert {"by_service", "by_technique", "top_credentials"} <= set(body)
        assert sum(row["count"] for row in body["by_technique"]) == 1
        for path in ["/stats?window=2h", "/stats/timeseries?window=1y"]:
            assert (await client.get(path)).status == 400, path
    run(scenario)


def test_timeseries_returns_aligned_buckets():
    async def scenario(client, storage, bus):
        await storage.events.insert(_event("pwd"))
        body = await (await client.get("/stats/timeseries?window=15m")).json()
        # Contract used by the dashboard (dashboard/src/types.ts: Timeseries)
        assert body["window"] == "15m" and body["bucket_seconds"] > 0
        buckets = body["points"]
        assert buckets and all({"ts", "total", "ssh", "http"} <= set(b) for b in buckets)
        assert sum(b["total"] for b in buckets) >= 1
    run(scenario)


def test_websocket_says_hello_and_streams_events_but_not_handshakes():
    async def scenario(client, storage, bus):
        # The app subscribes to the bus and starts it on startup.
        async with client.ws_connect("/ws/events") as socket:
            hello = await socket.receive_json(timeout=5)
            assert hello["type"] == "hello"
            bus.publish(_handshake())
            bus.publish(_event("whoami"))
            message = await socket.receive_json(timeout=5)
            assert message["type"] == "event"
            assert message["event"]["command"] == "whoami"
    run(scenario)
