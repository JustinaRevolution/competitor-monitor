"""
Verification for the fifth-round review fixes.

Run from the repo root:  python3 tests/test_round5.py

Covers:
  H1  "Check now" honours the same failure backoff the scheduler does, and
      counts its own failures toward it.
  H2  Stored ChangeEvent history is capped per URL.
  H3  CSRF tokens are bound to the browser's CSRF cookie *and* to the login
      session; missing, junk, legacy-format, cross-browser and cross-session
      tokens are all rejected.
  T   Coverage holes the reviewer flagged: negative CSRF on mutating routes,
      Stripe webhook signature verification, cooldown on check_now, IDOR.
"""

import asyncio
import os
import sys
import tempfile
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)
# A configured Stripe price turns the paywall on. Nothing here talks to Stripe.
os.environ["STRIPE_PRICE_ID"] = "price_test_round5"
os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"

import stripe  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app.main as main  # noqa: E402
import app.security as security  # noqa: E402
from app.models import (  # noqa: E402
    Base, ChangeEvent, MAX_CHANGE_EVENTS_PER_URL, MonitoredUrl, User,
    get_session, prune_change_events, utcnow,
)

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
        user = User(email=f"r5-{len(_tmpfiles)}-{n}@test.local", password_hash="x", is_active=paid)
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
    """A CSRF token valid for `client` as it is currently authenticated."""
    secret = client.cookies.get(security.CSRF_COOKIE)
    auth = client.cookies.get("token") if binding_cookie is None else binding_cookie
    return security.mint_csrf_token(secret, security.csrf_binding_for_auth(auth or ""))


def client_for(engine, user_id=None):
    """A TestClient wired to `engine`, optionally logged in as `user_id`."""
    main.engine = engine
    client = TestClient(main.app)
    client.__enter__()
    client.get("/login")  # seeds the CSRF cookie via the middleware
    if user_id is not None:
        client.cookies.set("token", main.make_token(user_id))
    return client, csrf_for(client)


def roomy_limiters():
    """Swap in generous rate limiters so these tests exercise other gates."""
    saved = (main.check_now_limiter, main.check_now_user_limiter,
             main.add_url_limiter, main.login_limiter)
    main.check_now_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.check_now_user_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.add_url_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.login_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    return saved


def restore_limiters(saved):
    (main.check_now_limiter, main.check_now_user_limiter,
     main.add_url_limiter, main.login_limiter) = saved


# ------------------------------------------------- (H1) check_now and backoff

def test_check_now_honours_cooldown():
    print("\n[H1] 'Check now' cannot outrun the failure backoff")
    engine, made = fresh_db(paid=True)
    user_id, url_id = made[0]
    fake = FakeCheck({"changed": False, "error": "Failed to fetch page"})
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)

        # First manual check fails and is recorded.
        r = client.post(f"/urls/{url_id}/check", data={"csrf_token": token},
                        follow_redirects=False)
        check("failing manual check returns 502", r.status_code == 502, str(r.status_code))
        db = get_session(engine)
        row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
        check("manual failure counted toward consecutive_failures",
              row.consecutive_failures == 1, str(row.consecutive_failures))
        check("manual failure recorded last_failure_at", row.last_failure_at is not None)
        check("one failure opens a cooldown", row.is_in_failure_cooldown() is True)
        db.close()

        # Every subsequent manual check is refused until the cooldown expires,
        # and no fetch is attempted.
        calls_before = fake.calls
        codes = []
        for _ in range(5):
            r = client.post(f"/urls/{url_id}/check", data={"csrf_token": token},
                            follow_redirects=False)
            codes.append(r.status_code)
        check("manual check during cooldown is refused with 429",
              codes == [429] * 5, str(codes))
        check("no fetch was attempted while in cooldown",
              fake.calls == calls_before, f"{fake.calls - calls_before} extra fetches")
        check("the refusal says when it can be checked again",
              "checked again at" in r.text, r.text[:0])

        db = get_session(engine)
        row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
        check("a refused check does not inflate the failure count",
              row.consecutive_failures == 1, str(row.consecutive_failures))

        # Once the cooldown has passed, the manual check runs again.
        row.last_failure_at = utcnow() - timedelta(hours=2)
        db.commit()
        db.close()
        main.check_url = FakeCheck({"changed": False, "new_hash": "H",
                                    "new_content": "C", "error": None})
        r = client.post(f"/urls/{url_id}/check", data={"csrf_token": token},
                        follow_redirects=False)
        check("manual check is allowed once the cooldown expires",
              r.status_code == 303, str(r.status_code))
        db = get_session(engine)
        row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
        check("a good manual check clears the backoff", row.consecutive_failures == 0)

        # An auto-paused monitor is refused on the manual path too.
        row.is_active = False
        row.paused_reason = "Auto-paused after 5 consecutive failed checks."
        db.commit()
        db.close()
        fake2 = FakeCheck({"changed": False, "new_hash": "H", "new_content": "C", "error": None})
        main.check_url = fake2
        r = client.post(f"/urls/{url_id}/check", data={"csrf_token": token},
                        follow_redirects=False)
        check("manual check on a paused monitor is refused with 409",
              r.status_code == 409, str(r.status_code))
        check("a paused monitor is never fetched manually", fake2.calls == 0, str(fake2.calls))

        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


# ------------------------------------------------- (H2) stored history is capped

def test_change_event_history_capped():
    print("\n[H2] stored change history is capped per URL")
    engine, made = fresh_db(paid=True)
    user_id, url_id = made[0]

    db = get_session(engine)
    base = utcnow() - timedelta(days=10)
    for n in range(MAX_CHANGE_EVENTS_PER_URL + 25):
        db.add(ChangeEvent(
            url_id=url_id, detected_at=base + timedelta(minutes=n),
            old_hash=f"h{n}", new_hash=f"h{n + 1}", new_content="x" * 100,
        ))
    db.commit()
    check("history seeded above the cap",
          db.query(ChangeEvent).count() == MAX_CHANGE_EVENTS_PER_URL + 25)

    deleted = prune_change_events(db, url_id)
    db.commit()
    check("prune deleted the overflow", deleted == 25, str(deleted))
    remaining = db.query(ChangeEvent).filter(ChangeEvent.url_id == url_id).all()
    check("exactly the cap is kept", len(remaining) == MAX_CHANGE_EVENTS_PER_URL,
          str(len(remaining)))
    check("the newest events are the ones kept",
          min(e.detected_at for e in remaining) == base + timedelta(minutes=25))
    check("prune is a no-op once at the cap", prune_change_events(db, url_id) == 0)
    db.close()

    # And the route that writes history prunes as it goes.
    fake = FakeCheck({"changed": True, "new_hash": "NEW", "new_content": "NEW",
                      "diff_summary": "changed", "error": None})
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        r = client.post(f"/urls/{url_id}/check", data={"csrf_token": token},
                        follow_redirects=False)
        check("check_now with a change succeeded", r.status_code == 303, str(r.status_code))
        db = get_session(engine)
        total = db.query(ChangeEvent).filter(ChangeEvent.url_id == url_id).count()
        check("check_now kept the history at the cap",
              total == MAX_CHANGE_EVENTS_PER_URL, str(total))
        newest = db.query(ChangeEvent).filter(ChangeEvent.url_id == url_id).order_by(
            ChangeEvent.detected_at.desc(), ChangeEvent.id.desc()).first()
        check("the event just written survived the prune", newest.new_hash == "NEW",
              newest.new_hash)
        db.close()
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


def test_scheduler_prunes_history():
    print("\n[H2] the scheduled sweep prunes history too")
    engine, made = fresh_db(paid=True)
    user_id, url_id = made[0]
    db = get_session(engine)
    base = utcnow() - timedelta(days=10)
    for n in range(MAX_CHANGE_EVENTS_PER_URL + 10):
        db.add(ChangeEvent(url_id=url_id, detected_at=base + timedelta(minutes=n),
                           new_hash=f"h{n}", new_content="x"))
    row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
    row.last_hash, row.last_content = "OLD", "OLD"
    db.commit()
    db.close()

    async def no_alert(*a, **k):
        return True

    real = (main.engine, main.check_url, main._deliver_change_alert)
    main.engine = engine
    main.check_url = FakeCheck({"changed": True, "new_hash": "NEW", "new_content": "NEW",
                                "diff_summary": "d", "error": None})
    main._deliver_change_alert = no_alert
    try:
        asyncio.run(main.run_scheduled_checks())
        db = get_session(engine)
        total = db.query(ChangeEvent).filter(ChangeEvent.url_id == url_id).count()
        check("scheduled sweep kept the history at the cap",
              total == MAX_CHANGE_EVENTS_PER_URL, str(total))
        db.close()
    finally:
        main.engine, main.check_url, main._deliver_change_alert = real


# ------------------------------------------------------------- (H3) CSRF

def test_csrf_negatives():
    print("\n[H3] CSRF: only a token bound to this browser and this session works")
    engine, made = fresh_db(paid=True)
    user_id, url_id = made[0]
    fake = FakeCheck({"changed": False, "new_hash": "H", "new_content": "C", "error": None})
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        cookie_secret = client.cookies.get(security.CSRF_COOKIE)

        # --- missing ---
        r = client.post("/urls/new", follow_redirects=False, data={
            "label": "X", "url": "https://example.com/x", "check_interval_hours": "24"})
        check("add_url with no CSRF token -> 403", r.status_code == 403, str(r.status_code))
        r = client.post(f"/urls/{url_id}/delete", follow_redirects=False, data={})
        check("delete with no CSRF token -> 403", r.status_code == 403, str(r.status_code))
        r = client.post(f"/urls/{url_id}/toggle", follow_redirects=False,
                        data={"csrf_token": ""})
        check("toggle with an empty CSRF token -> 403", r.status_code == 403, str(r.status_code))

        # --- forged / junk ---
        for junk in ("junk", "a.b.c", token[:-4] + "AAAA", token + "x"):
            r = client.post(f"/urls/{url_id}/delete", follow_redirects=False,
                            data={"csrf_token": junk})
            check(f"delete with a forged token ({junk[:12]}…) -> 403",
                  r.status_code == 403, str(r.status_code))

        # --- legacy bare-string token (signed, but with no session half) ---
        legacy = security._csrf_serializer.dumps(cookie_secret)
        r = client.post(f"/urls/{url_id}/delete", follow_redirects=False,
                        data={"csrf_token": legacy})
        check("a correctly-signed legacy token with no session binding -> 403",
              r.status_code == 403, str(r.status_code))

        # --- token minted for a different browser's cookie ---
        other_secret = security.new_csrf_secret()
        foreign = security.mint_csrf_token(
            other_secret, security.csrf_binding_for_auth(client.cookies.get("token")))
        r = client.post(f"/urls/{url_id}/delete", follow_redirects=False,
                        data={"csrf_token": foreign})
        check("a token signed over another browser's CSRF cookie -> 403",
              r.status_code == 403, str(r.status_code))

        # --- right cookie, wrong session (this is the round-5 binding fix) ---
        anon_token = security.mint_csrf_token(cookie_secret,
                                              security.csrf_binding_for_auth(""))
        r = client.post(f"/urls/{url_id}/delete", follow_redirects=False,
                        data={"csrf_token": anon_token})
        check("a token minted before login is not valid after login -> 403",
              r.status_code == 403, str(r.status_code))

        other_session = security.mint_csrf_token(
            cookie_secret, security.csrf_binding_for_auth(main.make_token(999_999)))
        r = client.post(f"/urls/{url_id}/delete", follow_redirects=False,
                        data={"csrf_token": other_session})
        check("a token bound to a different session -> 403",
              r.status_code == 403, str(r.status_code))

        # --- the request cookie itself must be a secret we issued ---
        client.cookies.set(security.CSRF_COOKIE, "short")
        r = client.post(f"/urls/{url_id}/delete", follow_redirects=False,
                        data={"csrf_token": token})
        check("a garbage CSRF cookie is not accepted as half the pair -> 403",
              r.status_code == 403, str(r.status_code))
        # That request made the middleware issue a replacement cookie; drop both
        # and restore the original so the rest of the test has one known secret.
        client.cookies.delete(security.CSRF_COOKIE)
        client.cookies.set(security.CSRF_COOKIE, cookie_secret)

        # Nothing above got as far as the database or the fetcher.
        db = get_session(engine)
        check("no monitor was created or deleted by any rejected request",
              db.query(MonitoredUrl).count() == 1)
        db.close()
        check("no rejected request reached the fetcher", fake.calls == 0, str(fake.calls))

        # --- the real thing still works ---
        r = client.post(f"/urls/{url_id}/toggle", follow_redirects=False,
                        data={"csrf_token": csrf_for(client)})
        check("a properly bound token is accepted", r.status_code == 303, str(r.status_code))

        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


def test_csrf_negatives_on_login():
    print("\n[H3] CSRF: the unauthenticated login form is protected too")
    engine, made = fresh_db(paid=True)
    saved = roomy_limiters()
    real_engine = main.engine
    try:
        client, _ = client_for(engine)  # not logged in
        creds = {"email": "nobody@test.local", "password": "hunter2"}

        r = client.post("/login", data=creds, follow_redirects=False)
        check("login with no CSRF token -> 403", r.status_code == 403, str(r.status_code))
        r = client.post("/login", data={**creds, "csrf_token": "forged"},
                        follow_redirects=False)
        check("login with a forged CSRF token -> 403", r.status_code == 403, str(r.status_code))
        r = client.post("/login", data={**creds, "csrf_token": security.mint_csrf_token(
            security.new_csrf_secret(), "anon")}, follow_redirects=False)
        check("login with a token for another browser's cookie -> 403",
              r.status_code == 403, str(r.status_code))

        r = client.post("/login", data={**creds, "csrf_token": csrf_for(client)},
                        follow_redirects=False)
        check("login with a valid anonymous token passes CSRF",
              r.status_code == 200 and "Invalid email or password" in r.text,
              str(r.status_code))
        client.__exit__(None, None, None)
    finally:
        main.engine = real_engine
        restore_limiters(saved)


# ------------------------------------------- webhook signature verification

def test_webhook_signature_verification():
    print("\n[T] Stripe webhook signature verification")
    engine, made = fresh_db(paid=False)
    user_id, _ = made[0]

    async def no_email(*a, **k):
        return True

    real = (main.engine, main.STRIPE_WEBHOOK_SECRET, main.send_welcome_email,
            stripe.Webhook.construct_event)
    main.engine = engine
    main.send_welcome_email = no_email
    try:
        client = TestClient(main.app)
        client.__enter__()

        # (a) No configured secret: fail closed, never trust the payload.
        main.STRIPE_WEBHOOK_SECRET = ""
        calls = {"n": 0}

        def should_not_run(*a, **k):
            calls["n"] += 1
            raise AssertionError("construct_event must not be reached")

        stripe.Webhook.construct_event = staticmethod(should_not_run)
        r = client.post("/stripe-webhook", content=b"{}",
                        headers={"stripe-signature": "t=1,v1=deadbeef"})
        check("webhook with no configured secret -> 503", r.status_code == 503,
              str(r.status_code))
        check("signature verification is never skipped when unconfigured",
              calls["n"] == 0)

        # (b) Bad signature: rejected.
        main.STRIPE_WEBHOOK_SECRET = "whsec_test_round5"

        def bad_sig(payload, sig_header, secret, *a, **k):
            raise stripe.error.SignatureVerificationError("bad sig", sig_header)

        stripe.Webhook.construct_event = staticmethod(bad_sig)
        r = client.post("/stripe-webhook", content=b'{"type":"checkout.session.completed"}',
                        headers={"stripe-signature": "t=1,v1=forged"})
        check("webhook with a forged signature -> 400", r.status_code == 400,
              str(r.status_code))

        # A malformed payload raises ValueError inside construct_event.
        def bad_payload(*a, **k):
            raise ValueError("not json")

        stripe.Webhook.construct_event = staticmethod(bad_payload)
        r = client.post("/stripe-webhook", content=b"not-json",
                        headers={"stripe-signature": "t=1,v1=x"})
        check("webhook with an unparseable payload -> 400", r.status_code == 400,
              str(r.status_code))

        db = get_session(engine)
        check("no rejected webhook activated the account",
              db.query(User).filter(User.id == user_id).one().is_active is False)
        db.close()

        # Missing signature header entirely.
        stripe.Webhook.construct_event = staticmethod(bad_sig)
        r = client.post("/stripe-webhook", content=b"{}")
        check("webhook with no signature header -> 400", r.status_code == 400,
              str(r.status_code))

        # (c) Valid signature: accepted, and it activates the account.
        def good_sig(payload, sig_header, secret, *a, **k):
            check("the configured secret is the one passed to Stripe",
                  secret == "whsec_test_round5", str(secret))
            return {
                "type": "checkout.session.completed",
                "data": {"object": {
                    "metadata": {"user_id": str(user_id)},
                    "customer": "cus_123", "subscription": "sub_123",
                    "payment_status": "paid",
                }},
            }

        stripe.Webhook.construct_event = staticmethod(good_sig)
        r = client.post("/stripe-webhook", content=b"{}",
                        headers={"stripe-signature": "t=1,v1=valid"})
        check("webhook with a valid signature -> 200", r.status_code == 200,
              str(r.status_code))
        db = get_session(engine)
        user = db.query(User).filter(User.id == user_id).one()
        check("a verified checkout.session.completed activates the account",
              user.is_active is True)
        check("the Stripe customer id was stored", user.stripe_customer_id == "cus_123")
        db.close()

        client.__exit__(None, None, None)
    finally:
        (main.engine, main.STRIPE_WEBHOOK_SECRET, main.send_welcome_email,
         stripe.Webhook.construct_event) = real


# ------------------------------------------------------------------- IDOR

def test_idor_across_accounts():
    print("\n[T] one account cannot touch another account's monitors")
    engine, made = fresh_db(paid=True, users=2)
    (a_id, a_url), (b_id, b_url) = made
    fake = FakeCheck({"changed": False, "new_hash": "H", "new_content": "C", "error": None})
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, a_id)

        r = client.post(f"/urls/{b_url}/toggle", data={"csrf_token": token},
                        follow_redirects=False)
        check("A toggling B's monitor -> 404", r.status_code == 404, str(r.status_code))
        r = client.post(f"/urls/{b_url}/check", data={"csrf_token": token},
                        follow_redirects=False)
        check("A running 'check now' on B's monitor -> 404", r.status_code == 404,
              str(r.status_code))
        r = client.get(f"/urls/{b_url}", follow_redirects=False)
        check("A viewing B's monitor -> 404", r.status_code == 404, str(r.status_code))
        r = client.post(f"/urls/{b_url}/delete", data={"csrf_token": token},
                        follow_redirects=False)
        check("A deleting B's monitor -> 404", r.status_code == 404, str(r.status_code))

        db = get_session(engine)
        b_row = db.query(MonitoredUrl).filter(MonitoredUrl.id == b_url).first()
        check("B's monitor still exists", b_row is not None)
        check("B's monitor was not toggled", b_row is not None and b_row.is_active is True)
        db.close()
        check("no cross-account request reached the fetcher", fake.calls == 0, str(fake.calls))

        # A's own monitor is still operable — the 404s are ownership, not breakage.
        r = client.post(f"/urls/{a_url}/toggle", data={"csrf_token": token},
                        follow_redirects=False)
        check("A can still toggle A's own monitor", r.status_code == 303, str(r.status_code))

        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


if __name__ == "__main__":
    try:
        test_check_now_honours_cooldown()
        test_change_event_history_capped()
        test_scheduler_prunes_history()
        test_csrf_negatives()
        test_csrf_negatives_on_login()
        test_webhook_signature_verification()
        test_idor_across_accounts()
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
