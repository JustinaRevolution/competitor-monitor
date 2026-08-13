"""
Verification for the referral program.

Run from the repo root:  python3 tests/test_round16.py

"Give a friend a month free, get a month free."

R1 — POST /signup?ref=CODE links the new account to the referrer, starts its
free month (`trial_ends_at`), and writes a referral_redemptions row. The account
lands on the dashboard rather than Stripe, because we said it wouldn't pay today.

R2 — a code that is unknown, malformed, self-owned, or held by an account that
is not itself subscribed grants nothing. The trial is the thing being handed
out, so an unpaid or trial referrer would let referral chains mint free months.

R3 — the free month is a real entitlement: `user_is_paid` accepts it, the
scheduler's SQL predicate accepts it, and it stops mattering once it expires.

R4 — a paid dashboard shows the referral link and the counts.

R5 — checkout.session.completed for a referred account banks one month for the
referrer, once, no matter how often Stripe retries the event.

R6 — migrate_schema backfills a referral_code onto accounts that predate the
program, and makes the column unique.
"""

import os
import sys
import tempfile
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)

from contextlib import contextmanager  # noqa: E402

import stripe  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

import app.main as main  # noqa: E402
import app.models as models  # noqa: E402
from app.models import (  # noqa: E402
    Base, MonitoredUrl, ReferralRedemption, User,
    REFERRAL_CODE_LEN, REFERRAL_TRIAL_DAYS,
    credit_referrer_for_payment, ensure_referral_code, entitled_user_clause,
    generate_referral_code, get_session, migrate_schema, normalize_referral_code,
    referral_trial_active, resolve_referrer, user_is_paid, utcnow,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ------------------------------------------------------------------ fixtures

_tmpfiles = []


def fresh_db():
    """A throwaway database with the current schema and no rows."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return engine


def make_user(engine, email, is_active=True, code=None):
    """An account, subscribed by default, with a known referral code."""
    db = get_session(engine)
    try:
        user = User(email=email, password_hash="x", is_active=is_active)
        db.add(user)
        db.commit()
        if code is None:
            code = ensure_referral_code(db, user)
        else:
            user.referral_code = code
        db.commit()
        return user.id, user.referral_code
    finally:
        db.close()


@contextmanager
def paywall_enforced():
    """
    Turn the paywall on for the duration.

    `REQUIRE_PAID_ACCOUNT` is False here because no Stripe price is configured —
    which also keeps signup from making a real network call. `user_is_paid`
    short-circuits to True in that mode, so anything asserting what the paywall
    actually *decides* has to flip the flag the predicate reads.
    """
    real = models.REQUIRE_PAID_ACCOUNT
    models.REQUIRE_PAID_ACCOUNT = True
    try:
        yield
    finally:
        models.REQUIRE_PAID_ACCOUNT = real


def load(engine, user_id):
    db = get_session(engine)
    try:
        return db.query(User).filter(User.id == user_id).one()
    finally:
        db.close()


class _Client:
    """TestClient against a given engine, with the paywall and rate limits real."""

    def __init__(self, engine):
        self.engine = engine

    def __enter__(self):
        self._real = main.engine
        main.engine = self.engine
        # The limiters are process-wide; a full bucket per test keeps signup
        # tests from starving each other.
        self._buckets = {}
        for name in ("signup_limiter", "login_limiter"):
            limiter = getattr(main, name)
            self._buckets[name] = dict(limiter._buckets)
            limiter._buckets.clear()
        self.client = TestClient(main.app)
        self.client.__enter__()
        return self.client

    def __exit__(self, *exc):
        self.client.__exit__(*exc)
        main.engine = self._real
        for name, buckets in self._buckets.items():
            getattr(main, name)._buckets.clear()
            getattr(main, name)._buckets.update(buckets)
        return False


def do_signup(client, email, password="correct-horse-battery", ref=None):
    """
    POST /signup the way a browser does. Returns the response.

    The CSRF token is read back out of the rendered form rather than minted
    here, so the test exercises the real token the page hands a visitor.
    """
    page = client.get("/signup" + (f"?ref={ref}" if ref else "")).text
    marker = 'name="csrf_token" value="'
    start = page.index(marker) + len(marker)
    form = {"email": email, "password": password,
            "csrf_token": page[start:page.index('"', start)]}
    if ref:
        form["ref"] = ref
    return client.post("/signup", data=form, follow_redirects=False)


# --------------------------------------------------- (R1) signup with a code

def test_signup_with_valid_ref_credits_new_user():
    print("\n[R1] A valid ref grants the new account its free month and records the referral")
    engine = fresh_db()
    referrer_id, code = make_user(engine, "r16-referrer@test.local")

    with _Client(engine) as client:
        r = do_signup(client, "r16-friend@test.local", ref=code)

    check("R1 signup redirects to the dashboard, not Stripe",
          r.status_code == 303 and r.headers["location"].startswith("/dashboard"),
          f"{r.status_code} → {r.headers.get('location')}")

    db = get_session(engine)
    try:
        friend = db.query(User).filter(User.email == "r16-friend@test.local").one()
        check("R1 referred_by_id points at the referrer",
              friend.referred_by_id == referrer_id, str(friend.referred_by_id))
        check("R1 the new account is on a free month",
              referral_trial_active(friend), str(friend.trial_ends_at))
        check("R1 the free month is REFERRAL_TRIAL_DAYS long",
              friend.trial_ends_at is not None
              and abs((friend.trial_ends_at - utcnow()).days - REFERRAL_TRIAL_DAYS) <= 1)
        with paywall_enforced():
            check("R1 the paywall lets the referred account in",
                  user_is_paid(friend))
        check("R1 the referred account is not marked as having paid",
              friend.is_active is False)

        redemption = db.query(ReferralRedemption).filter(
            ReferralRedemption.referred_user_id == friend.id).one_or_none()
        check("R1 a redemption row records who redeemed whose code",
              redemption is not None
              and redemption.referrer_id == referrer_id
              and redemption.code == code)
        check("R1 the redemption is not yet credited",
              redemption is not None and redemption.credited_at is None)
        check("R1 the referrer banks nothing until the friend pays",
              db.query(User).filter(User.id == referrer_id).one()
              .referral_credit_months == 0)
    finally:
        db.close()


# ------------------------------------------------- (R2) codes that grant nothing

def test_invalid_and_self_refs_are_rejected():
    print("\n[R2] Unknown, malformed, self and non-subscriber codes grant nothing")
    engine = fresh_db()
    paid_id, paid_code = make_user(engine, "r16-paid@test.local")
    _, unpaid_code = make_user(engine, "r16-unpaid@test.local", is_active=False)

    db = get_session(engine)
    try:
        check("R2 an unknown code resolves to nobody",
              resolve_referrer(db, generate_referral_code()) is None)
        check("R2 a malformed code resolves to nobody",
              resolve_referrer(db, "not-a-code") is None)
        check("R2 an empty code resolves to nobody",
              resolve_referrer(db, "") is None and resolve_referrer(db, None) is None)
        check("R2 a code held by an unsubscribed account resolves to nobody",
              resolve_referrer(db, unpaid_code) is None)
        check("R2 your own code resolves to nobody",
              resolve_referrer(db, paid_code, email="r16-paid@test.local") is None)
        check("R2 a valid code still resolves",
              getattr(resolve_referrer(db, paid_code), "id", None) == paid_id)
        check("R2 codes are matched case-insensitively",
              getattr(resolve_referrer(db, paid_code.lower()), "id", None) == paid_id)

        # A trial account must not be able to refer: its own month was free, so
        # letting it hand out months would be a self-sustaining loop.
        trial = User(email="r16-trial@test.local", password_hash="x", is_active=False,
                     trial_ends_at=utcnow() + timedelta(days=10))
        db.add(trial)
        db.commit()
        trial_code = ensure_referral_code(db, trial)
        db.commit()
        check("R2 an account on a free month cannot refer",
              resolve_referrer(db, trial_code) is None)
        with paywall_enforced():
            check("R2 …even though the paywall lets it in", user_is_paid(trial))
    finally:
        db.close()

    with _Client(engine) as client:
        r = do_signup(client, "r16-nobonus@test.local", ref=generate_referral_code())
    db = get_session(engine)
    try:
        friend = db.query(User).filter(User.email == "r16-nobonus@test.local").one()
        check("R2 a bad code still creates the account",
              friend is not None and r.status_code == 303)
        check("R2 …with no free month and no referrer",
              friend.trial_ends_at is None and friend.referred_by_id is None)
        check("R2 …and no redemption row",
              db.query(ReferralRedemption).count() == 0)
    finally:
        db.close()


# ------------------------------------------- (R3) the free month is a real grant

def test_trial_entitles_and_expires():
    print("\n[R3] The free month entitles the account, in Python and in SQL, then expires")
    engine = fresh_db()
    db = get_session(engine)
    try:
        live = User(email="r16-live@test.local", password_hash="x", is_active=False,
                    trial_ends_at=utcnow() + timedelta(days=5))
        lapsed = User(email="r16-lapsed@test.local", password_hash="x", is_active=False,
                      trial_ends_at=utcnow() - timedelta(minutes=1))
        never = User(email="r16-never@test.local", password_hash="x", is_active=False)
        db.add_all([live, lapsed, never])
        db.commit()

        with paywall_enforced():
            check("R3 a live free month passes the paywall", user_is_paid(live))
            check("R3 an expired free month does not", not user_is_paid(lapsed))
            check("R3 no free month and no subscription does not",
                  not user_is_paid(never))

        for user in (live, lapsed, never):
            db.add(MonitoredUrl(user_id=user.id, label="x",
                                url="https://example.com/" + str(user.id)))
        db.commit()

        # The sweep's SQL has to agree with user_is_paid, or the free month buys
        # an entitlement the scheduler then ignores.
        swept = {
            row.user_id for row in
            db.query(MonitoredUrl).join(User).filter(entitled_user_clause()).all()
        }
        check("R3 the sweep predicate includes the live free month",
              live.id in swept)
        check("R3 the sweep predicate excludes the expired one",
              lapsed.id not in swept and never.id not in swept)
    finally:
        db.close()


# --------------------------------------------- (R4) the dashboard shows the link

def test_dashboard_shows_referral_link():
    print("\n[R4] A subscribed dashboard shows the referral link and counts")
    engine = fresh_db()
    referrer_id, code = make_user(engine, "r16-dash@test.local")

    def dashboard_body(user_id):
        # One client per fetch: nesting TestClient contexts tears the app's
        # lifespan (and its scheduler) down out of order.
        with _Client(engine) as client:
            client.cookies.set("token", main.make_token(user_id))
            return client.get("/dashboard").text

    body = dashboard_body(referrer_id)
    check("R4 the dashboard shows the referral link", f"/signup?ref={code}" in body)
    check("R4 the link is absolute", main.referral_link(code) in body,
          main.referral_link(code))
    check("R4 a referrer with no referrals yet shows zero",
          ">0</strong> signed up" in body)

    with _Client(engine) as client:
        do_signup(client, "r16-dashfriend@test.local", ref=code)

    body = dashboard_body(referrer_id)
    check("R4 a pending referral counts as a signup", ">1</strong> signed up" in body)
    check("R4 …but not yet as a conversion", ">0</strong> subscribed" in body)

    db = get_session(engine)
    try:
        friend = db.query(User).filter(
            User.email == "r16-dashfriend@test.local").one()
        credit_referrer_for_payment(db, friend)
        db.commit()
    finally:
        db.close()

    body = dashboard_body(referrer_id)
    check("R4 a converted referral is counted", ">1</strong> subscribed" in body)
    check("R4 the banked months are shown",
          ">1</strong> free month(s) banked" in body)

    # A never-subscribed account has no link to share.
    unpaid_id, _ = make_user(engine, "r16-notpaid@test.local", is_active=False)
    check("R4 an unsubscribed dashboard shows no referral link",
          "/signup?ref=" not in dashboard_body(unpaid_id))


# ------------------------------------- (R5) the webhook credits the referrer once

def _webhook_event(event):
    """Make construct_event return `event` regardless of the signature."""
    def constructed(payload, sig_header, secret, *a, **k):
        return event
    return staticmethod(constructed)


def test_webhook_credits_referrer_once():
    print("\n[R5] checkout.session.completed for a referred account banks one month")
    engine = fresh_db()
    referrer_id, code = make_user(engine, "r16-wh-referrer@test.local")

    with _Client(engine) as client:
        do_signup(client, "r16-wh-friend@test.local", ref=code)
    db = get_session(engine)
    try:
        friend_id = db.query(User).filter(
            User.email == "r16-wh-friend@test.local").one().id
    finally:
        db.close()

    real = (main.engine, main.STRIPE_WEBHOOK_SECRET, stripe.Webhook.construct_event)
    main.engine = engine
    main.STRIPE_WEBHOOK_SECRET = "whsec_test_round16"
    try:
        client = TestClient(main.app)
        client.__enter__()

        def post(payment_status, user_id):
            stripe.Webhook.construct_event = _webhook_event({
                "type": "checkout.session.completed",
                "data": {"object": {
                    "payment_status": payment_status,
                    "customer": f"cus_r16_{user_id}",
                    "subscription": f"sub_r16_{user_id}",
                    "metadata": {"user_id": str(user_id)},
                }},
            })
            return client.post("/stripe-webhook", content=b"{}",
                               headers={"stripe-signature": "t=1,v1=valid"})

        def credits():
            return load(engine, referrer_id).referral_credit_months

        post("unpaid", friend_id)
        check("R5 an abandoned checkout banks nothing", credits() == 0, str(credits()))

        post("paid", friend_id)
        check("R5 a settled checkout banks one month for the referrer",
              credits() == 1, str(credits()))
        check("R5 the friend is now subscribed", load(engine, friend_id).is_active)

        post("paid", friend_id)
        post("paid", friend_id)
        check("R5 a replayed webhook does not bank a second month",
              credits() == 1, str(credits()))

        db = get_session(engine)
        try:
            redemption = db.query(ReferralRedemption).filter(
                ReferralRedemption.referred_user_id == friend_id).one()
            check("R5 the redemption records when it was credited",
                  redemption.credited_at is not None)
        finally:
            db.close()

        # An account nobody referred must not blow up the webhook.
        solo_id, _ = make_user(engine, "r16-solo@test.local", is_active=False)
        r = post("paid", solo_id)
        check("R5 an unreferred account pays normally",
              r.status_code == 200 and load(engine, solo_id).is_active)

        client.__exit__(None, None, None)
    finally:
        (main.engine, main.STRIPE_WEBHOOK_SECRET,
         stripe.Webhook.construct_event) = real


# ------------------------------------------------ (R6) migration backfills codes

def test_migration_backfills_referral_codes():
    print("\n[R6] Accounts predating the program get a code, and the column is unique")
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}",
                           connect_args={"check_same_thread": False})

    # A pre-referral `users` table: no referral columns at all.
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email VARCHAR(255) UNIQUE,
                password_hash VARCHAR(255),
                stripe_customer_id VARCHAR(255),
                stripe_subscription_id VARCHAR(255),
                is_active BOOLEAN NOT NULL DEFAULT 0,
                max_urls INTEGER DEFAULT 10,
                created_at DATETIME
            )
        """))
        for i in range(3):
            conn.execute(
                text("INSERT INTO users (email, password_hash, is_active) "
                     "VALUES (:e, 'x', 1)"), {"e": f"r16-old{i}@test.local"})

    applied = migrate_schema(engine)
    check("R6 the migration reports the referral columns it added",
          any("referral_code" in a for a in applied), str(applied))

    with engine.begin() as conn:
        codes = [r[0] for r in conn.execute(
            text("SELECT referral_code FROM users ORDER BY id"))]
    check("R6 every existing account has a code",
          len(codes) == 3 and all(c for c in codes), str(codes))
    check("R6 the codes are the right shape",
          all(c == normalize_referral_code(c) and len(c) == REFERRAL_CODE_LEN
              for c in codes), str(codes))
    check("R6 the codes are distinct", len(set(codes)) == 3)

    # The unique index is what stops two accounts sharing a code.
    duplicated = False
    try:
        with engine.begin() as conn:
            conn.execute(text("UPDATE users SET referral_code = :c WHERE id = 2"),
                         {"c": codes[0]})
        duplicated = True
    except Exception:
        pass
    check("R6 the referral_code column is unique", not duplicated)

    check("R6 re-running the migration is a no-op",
          not any("referral_code" in a for a in migrate_schema(engine)))

    # And the rest of the schema still comes up on top of the migrated table.
    Base.metadata.create_all(engine)
    db = get_session(engine)
    try:
        user = db.query(User).filter(User.id == 1).one()
        check("R6 the ORM reads the backfilled code", user.referral_code == codes[0])
        check("R6 backfilled accounts start with no banked months",
              user.referral_credit_months == 0)
        check("R6 backfilled accounts are not on a free month",
              user.trial_ends_at is None and not referral_trial_active(user))
    finally:
        db.close()


# ------------------------------------------------------------------ entry point

def main_runner():
    tests = [
        test_signup_with_valid_ref_credits_new_user,
        test_invalid_and_self_refs_are_rejected,
        test_trial_entitles_and_expires,
        test_dashboard_shows_referral_link,
        test_webhook_credits_referrer_once,
        test_migration_backfills_referral_codes,
    ]
    for t in tests:
        t()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    for name in _tmpfiles:
        try:
            os.unlink(name)
        except OSError:
            pass
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main_runner())
