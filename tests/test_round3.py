"""
Verification for the third-round review fixes.

Run from the repo root:  python3 tests/test_round3.py

Covers: H1 the paywall (unpaid/anonymous callers cannot reach the URL fetcher,
Stripe webhook flips an account to paid), H2 check-interval bounds, H3 failure
backoff and auto-pause, M1 alert-flag rollback, M4 bounded check concurrency,
plus the additive schema migration.
"""

import asyncio
import os
import sys
import tempfile
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)
# A configured Stripe price is what turns the paywall on, so set one before the
# config module is imported. Nothing here ever talks to Stripe.
os.environ["STRIPE_PRICE_ID"] = "price_test_paywall"
os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

import app.main as main  # noqa: E402
import app.security as security  # noqa: E402
from app.config import REQUIRE_PAID_ACCOUNT  # noqa: E402
from app.models import (  # noqa: E402
    Base, ChangeEvent, MonitoredUrl, User,
    FAILURE_PAUSE_THRESHOLD, InvalidIntervalError,
    MAX_CHECK_INTERVAL_HOURS, MIN_CHECK_INTERVAL_HOURS,
    clamp_check_interval_hours, get_session, migrate_schema, user_is_paid,
    validate_check_interval_hours, utcnow,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ------------------------------------------------------------------ fixtures

_tmpfiles = []


def fresh_db(paid: bool, with_url: bool = True):
    """A throwaway database holding one user and (optionally) one monitor."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = get_session(engine)
    user = User(email=f"u{len(_tmpfiles)}@test.local", password_hash="x", is_active=paid)
    db.add(user)
    db.flush()
    url_id = None
    if with_url:
        monitored = MonitoredUrl(user_id=user.id, label="Target", url="https://example.com/pricing")
        db.add(monitored)
        db.flush()
        url_id = monitored.id
    db.commit()
    user_id = user.id
    db.close()
    return engine, user_id, url_id


class FakeCheck:
    """Stand-in for check_url that records how many fetches were attempted."""

    def __init__(self, result):
        self.result = result
        self.calls = 0

    async def __call__(self, url, previous_hash, previous_content):
        self.calls += 1
        return dict(self.result)


async def _fake_validate(url):
    return url


def csrf_for(client):
    """
    A CSRF token valid for `client` right now.

    Tokens are bound to the auth cookie as well as the CSRF cookie, so this has
    to be re-minted whenever the client logs in or out.
    """
    secret = client.cookies.get(security.CSRF_COOKIE)
    binding = security.csrf_binding_for_auth(client.cookies.get("token") or "")
    return security.mint_csrf_token(secret, binding)


def client_for(engine, user_id=None):
    """A TestClient wired to `engine`, optionally logged in as `user_id`."""
    main.engine = engine
    client = TestClient(main.app)
    client.__enter__()
    client.get("/login")  # seeds the CSRF cookie
    if user_id is not None:
        client.cookies.set("token", main.make_token(user_id))
    return client, csrf_for(client)


# --------------------------------------------------------------- (H1) paywall

def test_paywall():
    print("\n[H1] unpaid and anonymous callers cannot reach the URL fetcher")
    check("paywall is enabled when a Stripe price is configured", REQUIRE_PAID_ACCOUNT is True)

    engine, user_id, url_id = fresh_db(paid=False)
    fake = FakeCheck({"changed": False, "new_hash": "H", "new_content": "C", "error": None})
    real = (main.engine, main.check_url, main.validate_url_async)
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)

        r = client.get("/urls/new", follow_redirects=False)
        check("unpaid GET /urls/new redirects to /billing",
              r.status_code == 303 and r.headers.get("location") == "/billing",
              f"{r.status_code} {r.headers.get('location')}")

        r = client.post("/urls/new", follow_redirects=False, data={
            "label": "X", "url": "https://example.com/p",
            "check_interval_hours": "24", "csrf_token": token,
        })
        check("unpaid POST /urls/new redirects to /billing",
              r.status_code == 303 and r.headers.get("location") == "/billing",
              f"{r.status_code} {r.headers.get('location')}")

        r = client.post(f"/urls/{url_id}/check", follow_redirects=False,
                        data={"csrf_token": token})
        check("unpaid POST check_now redirects to /billing",
              r.status_code == 303 and r.headers.get("location") == "/billing",
              f"{r.status_code} {r.headers.get('location')}")

        db = get_session(engine)
        check("unpaid user created no monitors",
              db.query(MonitoredUrl).count() == 1, "the fixture's row only")
        db.close()

        # Anonymous: no auth cookie at all. The CSRF token is bound to the
        # session, so an anonymous caller carries an anonymous token.
        client.cookies.delete("token")
        token = csrf_for(client)
        r = client.get("/urls/new", follow_redirects=False)
        check("anonymous GET /urls/new redirects to /login",
              r.status_code == 303 and r.headers.get("location") == "/login",
              f"{r.status_code} {r.headers.get('location')}")
        r = client.post("/urls/new", follow_redirects=False, data={
            "label": "X", "url": "http://169.254.169.254/latest/meta-data/",
            "check_interval_hours": "24", "csrf_token": token,
        })
        check("anonymous POST /urls/new redirects to /login",
              r.status_code == 303 and r.headers.get("location") == "/login",
              f"{r.status_code} {r.headers.get('location')}")
        r = client.post(f"/urls/{url_id}/check", follow_redirects=False,
                        data={"csrf_token": token})
        check("anonymous POST check_now redirects to /login",
              r.status_code == 303 and r.headers.get("location") == "/login",
              f"{r.status_code} {r.headers.get('location')}")

        check("no fetch was ever attempted for unpaid/anonymous callers",
              fake.calls == 0, f"{fake.calls} fetches")

        # Dashboard stays reachable for an unpaid account (free-tier story).
        client.cookies.set("token", main.make_token(user_id))
        token = csrf_for(client)
        r = client.get("/dashboard", follow_redirects=False)
        check("unpaid user can still view the dashboard", r.status_code == 200, str(r.status_code))
        check("dashboard shows the paywall banner", "subscription isn't active" in r.text.lower()
              or "subscription isn&#39;t active" in r.text.lower())

        # Now pay, and the same requests go through.
        db = get_session(engine)
        db.query(User).filter(User.id == user_id).one().is_active = True
        db.commit()
        db.close()

        r = client.post("/urls/new", follow_redirects=False, data={
            "label": "Paid", "url": "https://example.com/paid",
            "check_interval_hours": "24", "csrf_token": token,
        })
        check("paid POST /urls/new is accepted",
              r.status_code == 303 and r.headers.get("location") == "/dashboard",
              f"{r.status_code} {r.headers.get('location')}")
        db = get_session(engine)
        check("paid user's monitor was created", db.query(MonitoredUrl).count() == 2)
        db.close()
        check("the fetch only happened for the paid request", fake.calls == 1, f"{fake.calls}")

        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real


def test_scheduler_skips_unpaid():
    print("\n[H1] the scheduled sweep skips unpaid accounts")
    engine, user_id, url_id = fresh_db(paid=False)
    db = get_session(engine)
    db.query(MonitoredUrl).one().last_checked_at = utcnow() - timedelta(days=30)
    db.commit()
    db.close()

    fake = FakeCheck({"changed": False, "new_hash": "H", "new_content": "C", "error": None})
    real = (main.engine, main.check_url)
    main.engine, main.check_url = engine, fake
    try:
        asyncio.run(main.run_scheduled_checks())
        check("an overdue URL owned by an unpaid account is not fetched",
              fake.calls == 0, f"{fake.calls} fetches")

        db = get_session(engine)
        db.query(User).filter(User.id == user_id).one().is_active = True
        db.commit()
        db.close()
        asyncio.run(main.run_scheduled_checks())
        check("the same URL is fetched once the account is paid",
              fake.calls == 1, f"{fake.calls} fetches")
    finally:
        main.engine, main.check_url = real


def test_stripe_webhook_activates():
    print("\n[H1] the Stripe webhook flips the account to paid")
    import stripe

    engine, user_id, _ = fresh_db(paid=False, with_url=False)
    event = {
        "type": "checkout.session.completed",
        "data": {"object": {
            "metadata": {"user_id": str(user_id)},
            "customer": "cus_test123",
            "subscription": "sub_test123",
            "payment_status": "paid",
        }},
    }

    async def fake_welcome(to_email):
        return True

    real = (main.engine, main.STRIPE_WEBHOOK_SECRET, main.send_welcome_email,
            stripe.Webhook.construct_event)
    main.engine = engine
    main.STRIPE_WEBHOOK_SECRET = "whsec_test"
    main.send_welcome_email = fake_welcome
    stripe.Webhook.construct_event = staticmethod(lambda payload, sig, secret: event)
    try:
        client, _ = client_for(engine)
        r = client.post("/stripe-webhook", content=b"{}", headers={"stripe-signature": "t=1,v1=x"})
        check("webhook accepted", r.status_code == 200, str(r.status_code))

        db = get_session(engine)
        user = db.query(User).filter(User.id == user_id).one()
        check("account is now paid", user.is_active is True)
        check("stripe ids recorded",
              user.stripe_customer_id == "cus_test123" and user.stripe_subscription_id == "sub_test123")
        check("user_is_paid() agrees", user_is_paid(user) is True)
        db.close()

        # Cancellation takes it back away.
        event["type"] = "customer.subscription.deleted"
        event["data"]["object"] = {"customer": "cus_test123"}
        client.post("/stripe-webhook", content=b"{}", headers={"stripe-signature": "t=1,v1=x"})
        db = get_session(engine)
        user = db.query(User).filter(User.id == user_id).one()
        check("cancelled subscription revokes paid access",
              user.is_active is False and user_is_paid(user) is False)
        db.close()
        client.__exit__(None, None, None)
    finally:
        (main.engine, main.STRIPE_WEBHOOK_SECRET, main.send_welcome_email,
         stripe.Webhook.construct_event) = real


# ------------------------------------------------------- (H2) interval bounds

def test_interval_validation():
    print("\n[H2] check_interval_hours is bounded")
    for bad in (0, -1, -240, MAX_CHECK_INTERVAL_HOURS + 1, 100000, "abc", None, ""):
        try:
            validate_check_interval_hours(bad)
            check(f"rejects {bad!r}", False, "was accepted")
        except InvalidIntervalError:
            check(f"rejects {bad!r}", True)

    for good in (MIN_CHECK_INTERVAL_HOURS, 6, 24, MAX_CHECK_INTERVAL_HOURS):
        try:
            check(f"accepts {good}", validate_check_interval_hours(good) == good)
        except InvalidIntervalError as e:
            check(f"accepts {good}", False, str(e))

    check("read-time clamp: 0 -> min", clamp_check_interval_hours(0) == MIN_CHECK_INTERVAL_HOURS)
    check("read-time clamp: -5 -> min", clamp_check_interval_hours(-5) == MIN_CHECK_INTERVAL_HOURS)
    check("read-time clamp: 99999 -> max", clamp_check_interval_hours(99999) == MAX_CHECK_INTERVAL_HOURS)
    check("read-time clamp: None -> default", clamp_check_interval_hours(None) == 24)

    # A row already in the database with a bad value must not become a hot loop.
    engine, user_id, url_id = fresh_db(paid=True)
    db = get_session(engine)
    row = db.query(MonitoredUrl).one()
    row.check_interval_hours = 0
    row.last_checked_at = utcnow() - timedelta(minutes=5)
    db.commit()
    check("stored interval of 0 is clamped on read", row.effective_interval_hours == MIN_CHECK_INTERVAL_HOURS)
    check("a 0-interval row checked 5 min ago is not due", row.is_due() is False)
    row.last_checked_at = utcnow() - timedelta(hours=2)
    check("...and is due again after the clamped interval", row.is_due() is True)
    db.close()


def test_interval_rejected_at_submission():
    print("\n[H2] out-of-range interval is rejected by the form")
    engine, user_id, _ = fresh_db(paid=True, with_url=False)
    fake = FakeCheck({"changed": False, "new_hash": "H", "new_content": "C", "error": None})
    real = (main.engine, main.check_url, main.validate_url_async)
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        for bad in ("0", "-3", "1000", "abc"):
            r = client.post("/urls/new", follow_redirects=False, data={
                "label": "X", "url": "https://example.com/p",
                "check_interval_hours": bad, "csrf_token": token,
            })
            ok = r.status_code == 400 and (
                "must be between 1 and 168" in r.text
                or "whole number of hours" in r.text
            )
            check(f"interval {bad!r} rejected with a clear error", ok,
                  f"{r.status_code}")
        db = get_session(engine)
        check("no monitor was created by the rejected submissions",
              db.query(MonitoredUrl).count() == 0)
        db.close()
        check("no fetch was attempted for a rejected submission", fake.calls == 0)
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real


# --------------------------------------------------------- (H3) failure backoff

def test_failure_backoff_and_autopause():
    print("\n[H3] failing URLs back off and eventually auto-pause")
    engine, user_id, url_id = fresh_db(paid=True)
    db = get_session(engine)
    db.query(MonitoredUrl).one().last_checked_at = utcnow() - timedelta(days=30)
    db.commit()
    db.close()

    fake = FakeCheck({"changed": False, "error": "Failed to fetch page"})
    real = (main.engine, main.check_url)
    main.engine, main.check_url = engine, fake
    try:
        asyncio.run(main.run_scheduled_checks())
        check("first sweep attempts the fetch", fake.calls == 1, f"{fake.calls}")

        # Immediately re-running the sweep must NOT hammer the dead target.
        for _ in range(5):
            asyncio.run(main.run_scheduled_checks())
        check("subsequent ticks are skipped during the cooldown",
              fake.calls == 1, f"{fake.calls} fetches after 6 ticks")

        db = get_session(engine)
        row = db.query(MonitoredUrl).one()
        check("one failure recorded", row.consecutive_failures == 1, str(row.consecutive_failures))
        check("cooldown window is in the future", row.is_in_failure_cooldown() is True)
        db.close()

        # Fast-forward past each cooldown until the auto-pause threshold trips.
        for expected in range(2, FAILURE_PAUSE_THRESHOLD + 1):
            db = get_session(engine)
            row = db.query(MonitoredUrl).one()
            row.last_failure_at = utcnow() - timedelta(hours=48)
            db.commit()
            db.close()
            asyncio.run(main.run_scheduled_checks())
            db = get_session(engine)
            row = db.query(MonitoredUrl).one()
            got = row.consecutive_failures
            db.close()
            check(f"failure #{expected} recorded after the cooldown expired",
                  got == expected, f"got {got}")

        db = get_session(engine)
        row = db.query(MonitoredUrl).one()
        check(f"auto-paused after {FAILURE_PAUSE_THRESHOLD} failures", row.is_active is False)
        check("paused_reason is shown to the user", bool(row.paused_reason), repr(row.paused_reason))
        db.close()

        calls_at_pause = fake.calls
        for _ in range(3):
            db = get_session(engine)
            db.query(MonitoredUrl).one().last_failure_at = utcnow() - timedelta(days=7)
            db.commit()
            db.close()
            asyncio.run(main.run_scheduled_checks())
        check("an auto-paused URL is never fetched again",
              fake.calls == calls_at_pause, f"{fake.calls} vs {calls_at_pause}")

        # Resuming clears the backoff, and a good check keeps it clear.
        db = get_session(engine)
        row = db.query(MonitoredUrl).one()
        row.is_active = True
        row.record_success()
        db.commit()
        db.close()
        main.check_url = FakeCheck({"changed": False, "new_hash": "H", "new_content": "C", "error": None})
        asyncio.run(main.run_scheduled_checks())
        db = get_session(engine)
        row = db.query(MonitoredUrl).one()
        check("resume + successful check clears the failure state",
              row.consecutive_failures == 0 and row.paused_reason is None and row.last_error is None)
        db.close()
    finally:
        main.engine, main.check_url = real


# --------------------------------------------------- (M1) alert flag rollback

def test_alert_flag_not_set_on_send_failure():
    print("\n[M1] alerted stays False when the email send fails")
    changed = {"changed": True, "new_hash": "NEW", "new_content": "new",
               "diff_summary": "d", "pricing_changes": "$1", "error": None}

    for label, alert_impl, expect in (
        ("raises", "raise", False),
        ("returns False", "false", False),
        ("succeeds", "true", True),
    ):
        engine, user_id, url_id = fresh_db(paid=True)
        db = get_session(engine)
        row = db.query(MonitoredUrl).one()
        row.last_checked_at = utcnow() - timedelta(days=30)
        row.last_hash, row.last_content = "OLD", "old"
        db.commit()
        db.close()

        async def alert(**kwargs):
            if alert_impl == "raise":
                raise RuntimeError("resend is down")
            return alert_impl == "true"

        real = (main.engine, main.check_url, main.send_change_alert)
        main.engine, main.check_url, main.send_change_alert = engine, FakeCheck(changed), alert
        try:
            asyncio.run(main.run_scheduled_checks())
        finally:
            main.engine, main.check_url, main.send_change_alert = real

        db = get_session(engine)
        events = db.query(ChangeEvent).all()
        got = events[0].alerted if events else None
        check(f"send {label} -> alerted is {expect}", len(events) == 1 and got is expect,
              f"{len(events)} events, alerted={got}")
        db.close()


# ------------------------------------------------- (M4) bounded concurrency

def test_bounded_concurrency():
    print("\n[M4] concurrent checks are capped")
    state = {"live": 0, "peak": 0}

    async def slow_check(url, previous_hash, previous_content):
        state["live"] += 1
        state["peak"] = max(state["peak"], state["live"])
        await asyncio.sleep(0.02)
        state["live"] -= 1
        return {"changed": False, "new_hash": "H", "new_content": "C", "error": None}

    real = main.check_url
    main.check_url = slow_check
    try:
        async def storm():
            await asyncio.gather(*(main._bounded_check_url(f"https://e/{i}", None, None)
                                   for i in range(40)))
        asyncio.run(storm())
    finally:
        main.check_url = real

    check(f"peak in-flight fetches <= {main.MAX_CONCURRENT_CHECKS}",
          state["peak"] <= main.MAX_CONCURRENT_CHECKS, f"peak was {state['peak']}")
    check("all 40 checks still completed", state["live"] == 0)


def test_scheduler_job_config():
    print("\n[M4/M3] scheduler job is bounded and startup failure is loud")
    engine, _, _ = fresh_db(paid=True, with_url=False)
    real = main.engine
    main.engine = engine
    try:
        with TestClient(main.app):
            job = main._scheduler.get_job("check_all_urls")
            check("max_instances is 1", job.max_instances == 1, str(job.max_instances))
            check("misfire_grace_time is set", job.misfire_grace_time == 300,
                  str(job.misfire_grace_time))
            check("coalesce is on", job.coalesce is True)
    finally:
        main.engine = real

    # M3: a scheduler that cannot start must raise, not print and continue.
    import apscheduler.schedulers.asyncio as aps

    class Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("no event loop for you")

    real_cls = aps.AsyncIOScheduler
    aps.AsyncIOScheduler = Boom
    try:
        main._start_scheduler()
        check("startup failure propagates", False, "it was swallowed")
    except RuntimeError:
        check("startup failure propagates", True)
    finally:
        aps.AsyncIOScheduler = real_cls


# ------------------------------------------------------------- migration

def test_migration_adds_columns():
    print("\n[H1/H3] migration brings a pre-existing database up to date")
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    with engine.begin() as conn:
        # The original (pre-fix) shape of both tables.
        conn.execute(text("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY, email VARCHAR(255), password_hash VARCHAR(255),
                stripe_customer_id VARCHAR(255), stripe_subscription_id VARCHAR(255),
                max_urls INTEGER, created_at DATETIME
            )"""))
        conn.execute(text("""
            CREATE TABLE monitored_urls (
                id INTEGER PRIMARY KEY, user_id INTEGER, label VARCHAR(255), url VARCHAR(2048),
                check_interval_hours INTEGER, last_checked_at DATETIME, last_hash VARCHAR(64),
                last_content TEXT, is_active BOOLEAN, created_at DATETIME
            )"""))
        conn.execute(text("INSERT INTO users (id, email, password_hash, max_urls) "
                          "VALUES (1, 'old@test.local', 'x', 10)"))
        conn.execute(text("INSERT INTO monitored_urls (id, user_id, label, url, "
                          "check_interval_hours, is_active) "
                          "VALUES (1, 1, 'Legacy', 'https://example.com', 24, 1)"))

    applied = migrate_schema(engine)
    # Named rather than counted: the set grows every time a release adds a
    # column, and a bare count turns that into an unrelated test failure.
    expected = {
        "monitored_urls.consecutive_failures", "monitored_urls.last_failure_at",
        "monitored_urls.last_error", "monitored_urls.paused_reason",
        "users.is_active",
    }
    check("migration reported the columns it added",
          expected <= set(applied), str(applied))

    db = get_session(engine)
    row = db.query(MonitoredUrl).one()
    check("legacy monitor row survived", row.label == "Legacy")
    check("consecutive_failures backfilled to 0", row.consecutive_failures == 0)
    check("paused_reason defaults to NULL", row.paused_reason is None)
    user = db.query(User).one()
    check("legacy user row survived", user.email == "old@test.local")
    check("existing users default to unpaid", user.is_active is False)
    db.close()

    check("migration is idempotent", migrate_schema(engine) == [])


if __name__ == "__main__":
    try:
        test_paywall()
        test_scheduler_skips_unpaid()
        test_stripe_webhook_activates()
        test_interval_validation()
        test_interval_rejected_at_submission()
        test_failure_backoff_and_autopause()
        test_alert_flag_not_set_on_send_failure()
        test_bounded_concurrency()
        test_scheduler_job_config()
        test_migration_adds_columns()
    finally:
        for path in _tmpfiles:
            try:
                os.unlink(path)
            except OSError:
                pass

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED: " + ", ".join(FAIL))
    sys.exit(1 if FAIL else 0)
