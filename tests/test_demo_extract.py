"""
POST /api/demo-extract — the homepage "paste a URL, see the price" widget.

Stateless and unauthenticated: it reuses app.monitor.check_url (the same
engine the product runs on a schedule) against a single page, on demand, and
must never create a MonitoredUrl or ChangeEvent row. Covers the happy path,
the no-price-found path, fetch failure, an SSRF-unsafe URL, missing CSRF, and
the per-IP rate limit.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)

from contextlib import contextmanager  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app.main as main  # noqa: E402
from app.models import Base, ChangeEvent, MonitoredUrl, get_session  # noqa: E402


def _engine():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine, tmp.name


@contextmanager
def _client(engine):
    """TestClient against a throwaway engine, with a full demo-extract bucket."""
    real_engine = main.engine
    main.engine = engine
    real_buckets = dict(main.demo_extract_limiter._buckets)
    main.demo_extract_limiter._buckets.clear()
    try:
        with TestClient(main.app) as client:
            yield client
    finally:
        main.engine = real_engine
        main.demo_extract_limiter._buckets.clear()
        main.demo_extract_limiter._buckets.update(real_buckets)


def _csrf(client):
    page = client.get("/").text
    marker = 'name="csrf_token" value="'
    start = page.index(marker) + len(marker)
    return page[start:page.index('"', start)]


def _post(client, url, csrf=None):
    token = csrf if csrf is not None else _csrf(client)
    return client.post("/api/demo-extract", data={"url": url, "csrf_token": token})


def test_demo_extract_returns_the_first_price_found():
    engine, path = _engine()
    try:
        async def fake_check_url(url, previous_hash, previous_content):
            return {
                "changed": False,
                "new_hash": "abc",
                "new_content": "Pro plan\n$29/mo\nEnterprise\n$99/mo",
                "error": None,
                "first_check": True,
            }

        real_check = main.check_url
        main.check_url = fake_check_url
        try:
            with _client(engine) as client:
                r = _post(client, "https://example.com/pricing")
        finally:
            main.check_url = real_check

        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True
        assert data["found"] is True
        assert data["price"] == "$29"
        assert "$29" in data["context"]
    finally:
        os.unlink(path)


def test_demo_extract_reports_no_price_found_honestly():
    engine, path = _engine()
    try:
        async def fake_check_url(url, previous_hash, previous_content):
            return {
                "changed": False,
                "new_hash": "abc",
                "new_content": "Welcome to our blog. No pricing here.",
                "error": None,
                "first_check": True,
            }

        real_check = main.check_url
        main.check_url = fake_check_url
        try:
            with _client(engine) as client:
                r = _post(client, "https://example.com/blog")
        finally:
            main.check_url = real_check

        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True
        assert data["found"] is False
        assert "price" not in data or not data.get("price")
    finally:
        os.unlink(path)


def test_demo_extract_reports_fetch_failure_without_faking_a_price():
    engine, path = _engine()
    try:
        async def fake_check_url(url, previous_hash, previous_content):
            return {"changed": False, "error": "Failed to fetch page"}

        real_check = main.check_url
        main.check_url = fake_check_url
        try:
            with _client(engine) as client:
                r = _post(client, "https://example.com/down")
        finally:
            main.check_url = real_check

        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is False
        assert data.get("found") is not True
        assert data["error"]
    finally:
        os.unlink(path)


def test_demo_extract_rejects_ssrf_unsafe_url_without_fetching():
    engine, path = _engine()
    try:
        calls = []

        async def spy_check_url(url, previous_hash, previous_content):
            calls.append(url)
            return {"changed": False, "error": None, "new_hash": "x", "new_content": "$1"}

        real_check = main.check_url
        main.check_url = spy_check_url
        try:
            with _client(engine) as client:
                r = _post(client, "http://127.0.0.1/admin")
        finally:
            main.check_url = real_check

        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is False
        assert calls == [], "an unsafe URL must never reach the fetch layer"
    finally:
        os.unlink(path)


def test_demo_extract_requires_a_valid_csrf_token():
    engine, path = _engine()
    try:
        with _client(engine) as client:
            r = _post(client, "https://example.com/pricing", csrf="not-a-real-token")
        assert r.status_code == 403
    finally:
        os.unlink(path)


def test_demo_extract_is_rate_limited_per_ip():
    engine, path = _engine()
    try:
        async def fake_check_url(url, previous_hash, previous_content):
            return {
                "changed": False, "new_hash": "abc",
                "new_content": "$5/mo", "error": None, "first_check": True,
            }

        real_check = main.check_url
        main.check_url = fake_check_url
        try:
            with _client(engine) as client:
                statuses = [_post(client, "https://example.com/pricing").status_code
                            for _ in range(main.demo_extract_limiter.capacity + 1)]
        finally:
            main.check_url = real_check

        assert statuses[:-1] == [200] * main.demo_extract_limiter.capacity, statuses
        assert statuses[-1] == 429, statuses
    finally:
        os.unlink(path)


def test_demo_extract_never_writes_to_the_database():
    engine, path = _engine()
    try:
        async def fake_check_url(url, previous_hash, previous_content):
            return {
                "changed": False, "new_hash": "abc",
                "new_content": "$29/mo", "error": None, "first_check": True,
            }

        real_check = main.check_url
        main.check_url = fake_check_url
        try:
            with _client(engine) as client:
                _post(client, "https://example.com/pricing")
        finally:
            main.check_url = real_check

        db = get_session(engine)
        try:
            assert db.query(MonitoredUrl).count() == 0
            assert db.query(ChangeEvent).count() == 0
        finally:
            db.close()
    finally:
        os.unlink(path)
