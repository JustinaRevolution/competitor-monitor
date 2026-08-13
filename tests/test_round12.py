"""
Verification for the round-12 fix.

Run from the repo root:  python3 tests/test_round12.py

Covers Finding 1: the blocking Stripe call on the single-worker event loop,
reachable unauthenticated.

`stripe.checkout.Session.create` is a synchronous HTTPS round trip whose client
waits 80 seconds by default. It was awaited straight from `_create_stripe_checkout`,
so it ran *on* the event loop of the one uvicorn worker this app deploys with —
one unauthenticated POST /signup against a slow api.stripe.com stalled every
other request in the process. The tests here pin down:

  (1) the SDK call runs on a worker thread, not the loop thread, and the loop
      keeps servicing other tasks for the whole duration of the call;
  (2) the number of worker threads that path can hold at once is capped, so a
      burst of signups can't drain the pool bcrypt and DNS also draw from;
  (3) the SDK client carries a short explicit timeout and no retries, so those
      threads actually end;
  (4) a Stripe failure degrades to the billing page with the account intact,
      instead of a 500 (the fix introduces the failure mode, so it is tested).
"""

import asyncio
import contextlib
import os
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)
# A configured price turns the real checkout path on. Nothing here reaches the
# network: every test replaces stripe.checkout.Session.create.
os.environ["STRIPE_PRICE_ID"] = "price_test_round12"
os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"

import stripe  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app.main as main  # noqa: E402
import app.security as security  # noqa: E402
from app.models import Base, User, get_session  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ------------------------------------------------------------------ fixtures

_tmpfiles = []


def fresh_db(paid: bool = False):
    """A throwaway database holding one account."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = get_session(engine)
    user = User(email=f"r12-{len(_tmpfiles)}@test.local", password_hash="x", is_active=paid)
    db.add(user)
    db.commit()
    user_id = user.id
    db.close()
    return engine, user_id


class StubUser:
    """Enough of a User for _create_stripe_checkout, with no Session behind it."""

    def __init__(self, n=0):
        self.id = n + 1
        self.email = f"r12-stub-{n}@test.local"


CHECKOUT_URL = "https://checkout.stripe.com/c/pay/test_round12"


class FakeCheckout:
    """
    Stand-in for stripe.checkout.Session.create that blocks the way the real one
    does, and records which thread it blocked and how many ran at once.
    """

    def __init__(self, delay=0.0, error=None):
        self.delay, self.error = delay, error
        self.calls, self.thread_ids = 0, set()
        self.max_concurrent, self._live = 0, 0
        self._lock = threading.Lock()

    def __call__(self, **kwargs):
        with self._lock:
            self.calls += 1
            self.thread_ids.add(threading.get_ident())
            self._live += 1
            self.max_concurrent = max(self.max_concurrent, self._live)
        try:
            time.sleep(self.delay)  # a real network round trip, minus the network
            if self.error:
                raise self.error
            return SimpleNamespace(url=CHECKOUT_URL)
        finally:
            with self._lock:
                self._live -= 1


@contextlib.contextmanager
def patched_checkout(fake):
    real = stripe.checkout.Session.create
    stripe.checkout.Session.create = fake
    try:
        yield fake
    finally:
        stripe.checkout.Session.create = real


@contextlib.contextmanager
def roomy_signup_limiter():
    """Signup is 3/hour/IP in production; these tests need more than that."""
    saved = main.signup_limiter
    main.signup_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    try:
        yield
    finally:
        main.signup_limiter = saved


def csrf_for(client):
    secret = client.cookies.get(security.CSRF_COOKIE)
    auth = client.cookies.get("token")
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


# --------------------------------------------- (1) the loop stays free

def test_checkout_runs_off_the_event_loop():
    print("\n[1] the blocking Stripe call does not run on the event loop")
    fake = FakeCheckout(delay=0.5)

    async def scenario():
        ticks = {"n": 0}

        async def ticker():
            while True:
                ticks["n"] += 1
                await asyncio.sleep(0.01)

        loop_thread = threading.get_ident()
        task = asyncio.create_task(ticker())
        await asyncio.sleep(0.05)  # let the ticker settle
        before = ticks["n"]
        url = await main._create_stripe_checkout(StubUser())
        during = ticks["n"] - before
        task.cancel()
        return url, during, loop_thread

    with patched_checkout(fake):
        url, during, loop_thread = asyncio.run(scenario())

    check("checkout still returns the Stripe URL", url == CHECKOUT_URL, url)
    check("the SDK call ran on a worker thread, not the loop thread",
          bool(fake.thread_ids) and loop_thread not in fake.thread_ids,
          f"loop={loop_thread} sdk={fake.thread_ids}")
    # 0.5s blocked against a 10ms ticker: ~50 ticks if the loop is free. Awaited
    # inline it is 0 — this is the assertion the old code failed.
    check("the event loop kept serving other tasks for the whole 0.5s call",
          during >= 20, f"ticks during the call = {during}")


# --------------------------------------------- (2) worker threads are capped

def test_concurrent_checkouts_are_capped():
    print("\n[2] a burst of checkouts cannot drain the thread pool")
    fake = FakeCheckout(delay=0.15)
    attempts = 12

    async def scenario():
        return await asyncio.gather(
            *(main._create_stripe_checkout(StubUser(n)) for n in range(attempts))
        )

    with patched_checkout(fake):
        urls = asyncio.run(scenario())

    check("every queued checkout still completed",
          fake.calls == attempts and all(u == CHECKOUT_URL for u in urls),
          f"calls={fake.calls}")
    check("in-flight SDK calls never exceeded MAX_CONCURRENT_STRIPE_CALLS",
          fake.max_concurrent <= main.MAX_CONCURRENT_STRIPE_CALLS,
          f"peak={fake.max_concurrent} cap={main.MAX_CONCURRENT_STRIPE_CALLS}")
    check("the cap leaves threads for bcrypt and DNS",
          main.MAX_CONCURRENT_STRIPE_CALLS < 8, str(main.MAX_CONCURRENT_STRIPE_CALLS))


# --------------------------------------------- (3) the threads actually end

def test_stripe_client_is_bounded():
    print("\n[3] the SDK client has a short timeout and no retries")
    saved = (main._stripe_configured, stripe.default_http_client,
             stripe.max_network_retries)
    try:
        main._stripe_configured = False
        stripe.default_http_client = None
        mod = main._configure_stripe()

        check("_configure_stripe returns the stripe module", mod is stripe)
        client = stripe.default_http_client
        check("an explicit HTTP client is installed", client is not None,
              repr(client))
        check("its timeout is bounded, not the SDK's 80s default",
              getattr(client, "_timeout", 80) <= main.STRIPE_TIMEOUT_SECONDS,
              f"timeout={getattr(client, '_timeout', None)}")
        check("that bound is short enough to matter",
              main.STRIPE_TIMEOUT_SECONDS <= 30, str(main.STRIPE_TIMEOUT_SECONDS))
        check("network retries are off, so one request holds one thread once",
              stripe.max_network_retries == 0, str(stripe.max_network_retries))
        check("the api key is applied", stripe.api_key == "sk_test_dummy")
    finally:
        (main._stripe_configured, stripe.default_http_client,
         stripe.max_network_retries) = saved


# --------------------------------------------- (4) failure degrades gracefully

def test_signup_survives_a_stripe_failure():
    print("\n[4a] an unreachable Stripe does not 500 an otherwise-good signup")
    engine, _ = fresh_db()
    real_engine = main.engine
    fake = FakeCheckout(error=stripe.error.APIConnectionError("connection timed out"))
    try:
        with roomy_signup_limiter(), patched_checkout(fake):
            client, token = client_for(engine)
            r = client.post("/signup", follow_redirects=False, data={
                "email": "stripe-down@test.local",
                "password": "correct horse battery",
                "csrf_token": token,
            })
            check("signup does not 500 when Stripe fails",
                  r.status_code == 303, str(r.status_code))
            check("it lands on the billing page with the failure flagged",
                  r.headers.get("location") == "/billing?error=checkout",
                  r.headers.get("location", ""))
            check("the visitor is still logged in to the account they created",
                  bool(client.cookies.get("token")))
            client.__exit__(None, None, None)

        db = get_session(engine)
        try:
            user = db.query(User).filter(User.email == "stripe-down@test.local").first()
            check("the account exists", user is not None)
            check("and is not activated by a checkout that never happened",
                  user is not None and user.is_active is False)
        finally:
            db.close()
    finally:
        main.engine = real_engine


def test_billing_checkout_retry_survives_a_stripe_failure():
    print("\n[4b] the retry button on /billing degrades the same way")
    engine, user_id = fresh_db()
    real_engine = main.engine
    fake = FakeCheckout(error=stripe.error.APIConnectionError("connection timed out"))
    try:
        with roomy_signup_limiter(), patched_checkout(fake):
            client, token = client_for(engine, user_id)
            r = client.post("/billing/checkout", follow_redirects=False,
                            data={"csrf_token": token})
            check("POST /billing/checkout does not 500", r.status_code == 303,
                  str(r.status_code))
            check("it redirects back to billing with the error flag",
                  r.headers.get("location") == "/billing?error=checkout",
                  r.headers.get("location", ""))

            page = client.get("/billing?error=checkout")
            check("the billing page explains what happened",
                  page.status_code == 200 and "couldn't reach Stripe" in page.text,
                  str(page.status_code))
            client.__exit__(None, None, None)
    finally:
        main.engine = real_engine


def test_working_stripe_still_redirects_to_checkout():
    print("\n[4c] the happy path is unchanged")
    engine, _ = fresh_db()
    real_engine = main.engine
    fake = FakeCheckout()
    try:
        with roomy_signup_limiter(), patched_checkout(fake):
            client, token = client_for(engine)
            r = client.post("/signup", follow_redirects=False, data={
                "email": "stripe-up@test.local",
                "password": "correct horse battery",
                "csrf_token": token,
            })
            check("signup redirects to the Stripe checkout URL",
                  r.status_code == 303 and r.headers.get("location") == CHECKOUT_URL,
                  f"{r.status_code} {r.headers.get('location', '')}")
            check("the user id is carried in the session metadata",
                  fake.calls == 1)
            client.__exit__(None, None, None)
    finally:
        main.engine = real_engine


if __name__ == "__main__":
    for fn in (test_checkout_runs_off_the_event_loop,
               test_concurrent_checkouts_are_capped,
               test_stripe_client_is_bounded,
               test_signup_survives_a_stripe_failure,
               test_billing_checkout_retry_survives_a_stripe_failure,
               test_working_stripe_still_redirects_to_checkout):
        fn()
    for path in _tmpfiles:
        try:
            os.unlink(path)
        except OSError:
            pass
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)
