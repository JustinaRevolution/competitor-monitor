"""
Verification for the sixth-round review fixes.

Run from the repo root:  python3 tests/test_round6.py

Covers:
  F1  Stored content is byte-bounded, so ChangeEvent rows cannot grow without
      limit — while the hash still covers the whole page.
  F2  Auto-pause survives a toggle-resume: resuming does not zero the failure
      counter, only a successful check does.
  F3  customer.subscription.updated with a past_due/unpaid/canceled status
      revokes paid access; checkout.session.completed still grants it.
  F4  Only ports 80 and 443 may be fetched, rejected before any DNS lookup.
  F5  add_url is limited per account, not only per source IP.
"""

import hashlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)
# A configured Stripe price turns the paywall on. Nothing here talks to Stripe.
os.environ["STRIPE_PRICE_ID"] = "price_test_round6"
os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"

import stripe  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app.main as main  # noqa: E402
import app.security as security  # noqa: E402
from app.models import (  # noqa: E402
    Base, ChangeEvent, FAILURE_PAUSE_THRESHOLD, MonitoredUrl, User,
    get_session, utcnow,
)
from app.monitor import (  # noqa: E402
    MAX_STORED_CONTENT_CHARS, extract_meaningful_content,
)
from app.security import UnsafeUrlError, validate_and_pin  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ------------------------------------------------------------------ fixtures

_tmpfiles = []


def fresh_db(paid: bool = True, users: int = 1):
    """A throwaway database with `users` accounts, each owning one monitor."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = get_session(engine)
    made = []
    for n in range(users):
        user = User(email=f"r6-{len(_tmpfiles)}-{n}@test.local", password_hash="x", is_active=paid)
        db.add(user)
        db.flush()
        monitored = MonitoredUrl(
            user_id=user.id, label=f"Target {n}", url=f"https://example.com/p{n}",
        )
        db.add(monitored)
        db.flush()
        made.append((user.id, monitored.id))
    db.commit()
    db.close()
    return engine, made


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


def csrf_for(client, binding_cookie=None):
    secret = client.cookies.get(security.CSRF_COOKIE)
    auth = client.cookies.get("token") if binding_cookie is None else binding_cookie
    return security.mint_csrf_token(secret, security.csrf_binding_for_auth(auth or ""))


def client_for(engine, user_id=None):
    main.engine = engine
    client = TestClient(main.app)
    client.__enter__()
    client.get("/login")  # seeds the CSRF cookie via the middleware
    if user_id is not None:
        client.cookies.set("token", main.make_token(user_id))
    return client, csrf_for(client)


def roomy_limiters():
    saved = (main.check_now_limiter, main.check_now_user_limiter,
             main.add_url_limiter, main.add_url_user_limiter, main.login_limiter)
    main.check_now_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.check_now_user_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.add_url_limiter = security.TokenBucket(capacity=10_000, refill_seconds=3600)
    main.add_url_user_limiter = security.TokenBucket(capacity=10_000, refill_seconds=3600)
    main.login_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    return saved


def restore_limiters(saved):
    (main.check_now_limiter, main.check_now_user_limiter,
     main.add_url_limiter, main.add_url_user_limiter, main.login_limiter) = saved


def big_page(marker: str, filler_blocks: int = 4000) -> str:
    """An HTML page whose extracted text is far larger than the storage cap."""
    body = "\n".join(f"<p>Line {i} of the catalogue, priced at $19.99</p>"
                     for i in range(filler_blocks))
    return f"<html><body><h1>{marker}</h1>{body}<p>tail {marker}</p></body></html>"


# ------------------------------------------------- (F1) stored content bounded

def test_stored_content_is_bounded():
    print("\n[F1] Extracted content is byte-bounded before it is stored")

    text, content_hash = extract_meaningful_content(big_page("alpha"))
    check("a huge page extracts to a capped string",
          len(text) <= MAX_STORED_CONTENT_CHARS + 200, f"{len(text)} chars")
    check("the truncated copy says it is truncated", "truncated" in text)
    check("the kept part is the head of the page", text.startswith("alpha"))
    check("the cap is a sane size", 1000 <= MAX_STORED_CONTENT_CHARS <= 64_000,
          str(MAX_STORED_CONTENT_CHARS))

    # A small page is untouched, and its hash is still the hash of its text.
    small, small_hash = extract_meaningful_content("<html><body><p>$9 plan</p></body></html>")
    check("a small page is not truncated", "truncated" not in small, small)
    check("small-page hash covers the stored text",
          small_hash == hashlib.sha256(small.encode("utf-8")).hexdigest())

    # Truncation must not blind change detection: two pages identical for the
    # first cap-worth of characters but differing after it still hash apart.
    head = "<html><body>" + "<p>identical filler line with $19.99 on it</p>" * 4000
    a_text, a_hash = extract_meaningful_content(head + "<p>ONLY IN A</p></body></html>")
    b_text, b_hash = extract_meaningful_content(head + "<p>ONLY IN B</p></body></html>")
    check("stored copies of both are truncated to the same prefix", a_text == b_text)
    check("a change past the storage cap is still detected", a_hash != b_hash,
          f"{a_hash[:8]} vs {b_hash[:8]}")


def test_change_events_store_bounded_content():
    print("\n[F1] ChangeEvent rows cannot grow without bound")
    engine, made = fresh_db(paid=True)
    user_id, url_id = made[0]

    old_text, old_hash = extract_meaningful_content(big_page("before"))
    new_text, new_hash = extract_meaningful_content(big_page("after"))

    db = get_session(engine)
    row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
    row.last_hash, row.last_content = old_hash, old_text
    db.commit()
    db.close()

    fake = FakeCheck({
        "changed": True, "new_hash": new_hash, "new_content": new_text,
        "diff_summary": "changed", "error": None,
    })
    real = (main.engine, main.check_url, main.validate_url_async, main._deliver_change_alert)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate

    async def no_alert(*a, **k):
        return None

    main._deliver_change_alert = no_alert
    try:
        client, token = client_for(engine, user_id)
        r = client.post(f"/urls/{url_id}/check", data={"csrf_token": token},
                        follow_redirects=False)
        check("check with a change redirects", r.status_code == 303, str(r.status_code))

        db = get_session(engine)
        event = db.query(ChangeEvent).filter(ChangeEvent.url_id == url_id).one()
        ceiling = MAX_STORED_CONTENT_CHARS + 200
        check("stored old_content is bounded", len(event.old_content or "") <= ceiling,
              f"{len(event.old_content or '')} chars")
        check("stored new_content is bounded", len(event.new_content or "") <= ceiling,
              f"{len(event.new_content or '')} chars")
        stored = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
        check("the monitor's last_content is bounded too",
              len(stored.last_content or "") <= ceiling, f"{len(stored.last_content or '')} chars")
        check("the full-page hash is what gets stored", stored.last_hash == new_hash)
        db.close()
        client.__exit__(None, None, None)
    finally:
        (main.engine, main.check_url, main.validate_url_async,
         main._deliver_change_alert) = real
        restore_limiters(saved)


# ------------------------------------------- (F2) auto-pause survives a resume

def test_autopause_survives_toggle_resume():
    print("\n[F2] Resuming a monitor does not reset the failure backoff")
    engine, made = fresh_db(paid=True)
    user_id, url_id = made[0]
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = (
        FakeCheck({"changed": False, "error": "Failed to fetch page"}), _fake_validate)
    try:
        # Fail it into the auto-pause.
        db = get_session(engine)
        row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
        for _ in range(FAILURE_PAUSE_THRESHOLD):
            row.record_failure("Failed to fetch page")
        db.commit()
        check("threshold failures auto-pause the monitor", row.is_active is False)
        check("the auto-pause records a reason", bool(row.paused_reason))
        failed_at = row.last_failure_at
        db.close()

        client, token = client_for(engine, user_id)
        r = client.post(f"/urls/{url_id}/toggle", data={"csrf_token": token},
                        follow_redirects=False)
        check("resume redirects", r.status_code == 303, str(r.status_code))

        db = get_session(engine)
        row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
        check("resume does flip the monitor back on", row.is_active is True)
        check("resume does NOT zero consecutive_failures",
              row.consecutive_failures == FAILURE_PAUSE_THRESHOLD,
              str(row.consecutive_failures))
        check("resume does NOT clear last_failure_at", row.last_failure_at == failed_at)
        check("resume does NOT clear last_error", row.last_error is not None)
        check("the monitor is still inside its failure cooldown",
              row.is_in_failure_cooldown() is True)
        check("the scheduler still refuses to fetch it", row.is_due() is False)
        db.close()

        # And "check now" is refused for the same reason, without fetching.
        before = main.check_url.calls
        r = client.post(f"/urls/{url_id}/check", data={"csrf_token": token},
                        follow_redirects=False)
        check("check-now after a resume is refused with 429", r.status_code == 429,
              str(r.status_code))
        check("no fetch was attempted for the refused check",
              main.check_url.calls == before, str(main.check_url.calls))

        # Toggling repeatedly gains nothing.
        for _ in range(3):
            client.post(f"/urls/{url_id}/toggle", data={"csrf_token": token},
                        follow_redirects=False)
        db = get_session(engine)
        row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
        check("toggle-flapping still does not clear the failure count",
              row.consecutive_failures == FAILURE_PAUSE_THRESHOLD,
              str(row.consecutive_failures))
        # Only a successful check clears it.
        row.record_success()
        check("a successful check clears consecutive_failures", row.consecutive_failures == 0)
        check("a successful check clears the paused reason", row.paused_reason is None)
        check("a successful check ends the cooldown", row.is_in_failure_cooldown() is False)
        db.close()

        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


# ------------------------------------- (F3) subscription status revokes access

def _webhook_event(event):
    """Make construct_event return `event` regardless of the signature."""
    def constructed(payload, sig_header, secret, *a, **k):
        return event
    return staticmethod(constructed)


def test_subscription_update_revokes_access():
    print("\n[F3] A lapsed Stripe subscription revokes paid access")
    engine, made = fresh_db(paid=True)
    user_id, _ = made[0]

    db = get_session(engine)
    user = db.query(User).filter(User.id == user_id).one()
    user.stripe_customer_id = "cus_r6"
    user.stripe_subscription_id = "sub_r6"
    db.commit()
    db.close()

    real = (main.engine, main.STRIPE_WEBHOOK_SECRET, stripe.Webhook.construct_event)
    main.engine = engine
    main.STRIPE_WEBHOOK_SECRET = "whsec_test_round6"
    try:
        client = TestClient(main.app)
        client.__enter__()

        def post_status(status, event_type="customer.subscription.updated"):
            stripe.Webhook.construct_event = _webhook_event({
                "type": event_type,
                "data": {"object": {
                    "id": "sub_r6", "customer": "cus_r6", "status": status,
                }},
            })
            return client.post("/stripe-webhook", content=b"{}",
                               headers={"stripe-signature": "t=1,v1=valid"})

        def is_active():
            db = get_session(engine)
            try:
                return db.query(User).filter(User.id == user_id).one().is_active
            finally:
                db.close()

        def reactivate():
            db = get_session(engine)
            u = db.query(User).filter(User.id == user_id).one()
            u.is_active = True
            db.commit()
            db.close()

        for status in ("past_due", "unpaid", "canceled", "incomplete_expired", "paused"):
            reactivate()
            r = post_status(status)
            check(f"subscription.updated status={status} -> 200", r.status_code == 200,
                  str(r.status_code))
            check(f"status={status} revokes is_active", is_active() is False)

        # A healthy status leaves (or restores) access.
        for status in ("active", "trialing"):
            r = post_status(status)
            check(f"status={status} -> 200", r.status_code == 200, str(r.status_code))
            check(f"status={status} keeps the account active", is_active() is True)

        # Deletion still revokes and drops the subscription id.
        r = post_status("active", event_type="customer.subscription.deleted")
        check("subscription.deleted -> 200", r.status_code == 200, str(r.status_code))
        db = get_session(engine)
        user = db.query(User).filter(User.id == user_id).one()
        check("subscription.deleted revokes is_active", user.is_active is False)
        check("subscription.deleted clears the subscription id",
              user.stripe_subscription_id is None)
        db.close()

        # An event for an unknown customer touches nobody.
        stripe.Webhook.construct_event = _webhook_event({
            "type": "customer.subscription.updated",
            "data": {"object": {"id": "sub_x", "customer": "cus_someone_else",
                                "status": "past_due"}},
        })
        reactivate()
        r = client.post("/stripe-webhook", content=b"{}",
                        headers={"stripe-signature": "t=1,v1=valid"})
        check("an event for an unknown customer -> 200", r.status_code == 200,
              str(r.status_code))
        check("an event for an unknown customer leaves our user alone",
              is_active() is True)

        # checkout.session.completed still grants access.
        async def no_email(*a, **k):
            return True

        real_email = main.send_welcome_email
        main.send_welcome_email = no_email
        try:
            db = get_session(engine)
            u = db.query(User).filter(User.id == user_id).one()
            u.is_active = False
            db.commit()
            db.close()
            stripe.Webhook.construct_event = _webhook_event({
                "type": "checkout.session.completed",
                "data": {"object": {"metadata": {"user_id": str(user_id)},
                                    "customer": "cus_r6", "subscription": "sub_new",
                                    "payment_status": "paid"}},
            })
            r = client.post("/stripe-webhook", content=b"{}",
                            headers={"stripe-signature": "t=1,v1=valid"})
            check("checkout.session.completed still -> 200", r.status_code == 200,
                  str(r.status_code))
            check("checkout.session.completed still activates the account",
                  is_active() is True)
        finally:
            main.send_welcome_email = real_email

        client.__exit__(None, None, None)
    finally:
        (main.engine, main.STRIPE_WEBHOOK_SECRET, stripe.Webhook.construct_event) = real


# ----------------------------------------------------- (F4) port allow-listing

def test_only_web_ports_are_fetchable():
    print("\n[F4] Only ports 80 and 443 may be fetched")

    # DNS must never be reached for a bad port — the lookup itself is a signal,
    # and the whole point is to refuse before we touch the network.
    real_resolve = security._resolve
    resolved = {"n": 0}

    def counting_resolve(host):
        resolved["n"] += 1
        return real_resolve(host)

    security._resolve = counting_resolve
    try:
        for bad in ("http://example.com:22/", "http://example.com:6379/",
                    "http://example.com:11211/", "https://example.com:8443/x",
                    "http://example.com:8080/", "https://example.com:3306/",
                    "http://example.com:0/", "http://example.com:65535/"):
            try:
                validate_and_pin(bad)
                check(f"{bad} rejected", False, "no error raised")
            except UnsafeUrlError as e:
                check(f"{bad} rejected", True, str(e)[:60])
        check("no DNS lookup happened for any rejected port", resolved["n"] == 0,
              str(resolved["n"]))

        # A malformed port is rejected too, not crashed on.
        try:
            validate_and_pin("http://example.com:notaport/")
            check("a non-numeric port is rejected", False, "no error raised")
        except UnsafeUrlError as e:
            check("a non-numeric port is rejected", True, str(e)[:60])
        except ValueError as e:
            check("a non-numeric port is rejected", False,
                  f"leaked {type(e).__name__}")
    finally:
        security._resolve = real_resolve

    # Explicit and implicit 80/443 still work. Literal public IPs, so no DNS.
    for good in ("http://93.184.216.34/", "http://93.184.216.34:80/",
                 "https://93.184.216.34/", "https://93.184.216.34:443/p?q=1"):
        try:
            validate_and_pin(good)
            check(f"{good} allowed", True)
        except UnsafeUrlError as e:
            check(f"{good} allowed", False, str(e))

    # Private addresses stay blocked regardless of the port being allowed.
    for bad in ("http://127.0.0.1/", "http://127.0.0.1:80/", "https://10.0.0.5:443/"):
        try:
            validate_and_pin(bad)
            check(f"{bad} still rejected as private", False, "no error raised")
        except UnsafeUrlError:
            check(f"{bad} still rejected as private", True)


def test_add_url_rejects_odd_ports():
    print("\n[F4] The add-URL form refuses a non-web port end to end")
    engine, made = fresh_db(paid=True)
    user_id, _ = made[0]
    fake = FakeCheck({"changed": False, "new_hash": "h", "new_content": "c", "error": None})
    real = (main.engine, main.check_url)
    saved = roomy_limiters()
    main.check_url = fake  # real validate_url_async — that is what we're testing
    try:
        client, token = client_for(engine, user_id)
        r = client.post("/urls/new", data={
            "label": "Redis", "url": "http://example.com:6379/",
            "check_interval_hours": "24", "csrf_token": token,
        }, follow_redirects=False)
        check("adding a :6379 URL is refused with 400", r.status_code == 400,
              str(r.status_code))
        check("no fetch was attempted for the refused URL", fake.calls == 0,
              str(fake.calls))
        db = get_session(engine)
        stored = db.query(MonitoredUrl).filter(
            MonitoredUrl.user_id == user_id,
            MonitoredUrl.url.like("%6379%"),
        ).count()
        check("the rejected URL was not stored", stored == 0, str(stored))
        db.close()
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url = real
        restore_limiters(saved)


# --------------------------------------------- (F5) per-user add_url limiting

def test_add_url_is_limited_per_user():
    print("\n[F5] add_url is rate-limited per account, not only per IP")
    engine, made = fresh_db(paid=True, users=2)
    (user_a, _), (user_b, _) = made
    fake = FakeCheck({"changed": False, "new_hash": "h", "new_content": "c", "error": None})
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    # Generous per-IP budget, tight per-account budget: anything refused below
    # was refused by the account limiter.
    main.add_url_user_limiter = security.TokenBucket(capacity=2, refill_seconds=3600)
    try:
        client, token = client_for(engine, user_a)
        codes = []
        for n in range(4):
            r = client.post("/urls/new", data={
                "label": f"T{n}", "url": f"https://example.com/a{n}",
                "check_interval_hours": "24", "csrf_token": token,
            }, follow_redirects=False)
            codes.append(r.status_code)
        check("the first adds within the per-account budget succeed",
              codes[:2] == [303, 303], str(codes))
        check("adds past the per-account budget are refused with 429",
              codes[2:] == [429, 429], str(codes))
        check("no fetch happened for the refused adds", fake.calls == 2, str(fake.calls))

        db = get_session(engine)
        owned = db.query(MonitoredUrl).filter(MonitoredUrl.user_id == user_a).count()
        check("only the allowed adds were stored", owned == 3, str(owned))  # 1 from fixture
        db.close()

        # The limit is per account: a different user on the same IP is unaffected.
        client.cookies.set("token", main.make_token(user_b))
        token_b = csrf_for(client)
        r = client.post("/urls/new", data={
            "label": "B", "url": "https://example.com/b0",
            "check_interval_hours": "24", "csrf_token": token_b,
        }, follow_redirects=False)
        check("a different account on the same IP is not blocked",
              r.status_code == 303, str(r.status_code))

        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


def test_add_url_limiter_defaults():
    print("\n[F5] The per-account add_url bucket is configured")
    check("add_url_user_limiter exists", hasattr(security, "add_url_user_limiter"))
    bucket = security.add_url_user_limiter
    check("its capacity is 20", bucket.capacity == 20, str(bucket.capacity))
    check("it refills over an hour", abs(bucket.refill_rate - 20 / 3600) < 1e-9,
          str(bucket.refill_rate))
    check("it is keyed per user, not per IP",
          bucket is not security.add_url_limiter)


if __name__ == "__main__":
    try:
        test_stored_content_is_bounded()
        test_change_events_store_bounded_content()
        test_autopause_survives_toggle_resume()
        test_subscription_update_revokes_access()
        test_only_web_ports_are_fetchable()
        test_add_url_rejects_odd_ports()
        test_add_url_is_limited_per_user()
        test_add_url_limiter_defaults()
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
