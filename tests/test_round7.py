"""
Verification for the seventh-round review fixes.

Run from the repo root:  python3 tests/test_round7.py

Covers:
  F1  Signup bounds and checks the email address, so an unauthenticated request
      cannot write a multi-megabyte row into `users`. Passwords have a floor.
  F2  add_url bounds the label, so `max_urls` caps bytes as well as rows, and a
      label can no longer carry CR/LF into the alert email's Subject header.
"""

import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)
# No Stripe price configured: a successful signup takes the local-dev path and
# activates directly instead of calling out to Stripe.
os.environ.pop("STRIPE_PRICE_ID", None)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app.alerts as alerts  # noqa: E402
import app.main as main  # noqa: E402
import app.security as security  # noqa: E402
from app.models import Base, MonitoredUrl, User, get_session  # noqa: E402
from app.security import (  # noqa: E402
    MAX_EMAIL_LEN, MAX_LABEL_LEN, MIN_PASSWORD_LEN, InvalidInputError,
    header_safe, normalize_email, normalize_label, validate_password,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


def raises(fn, *args):
    """True when `fn(*args)` refuses the input with InvalidInputError."""
    try:
        fn(*args)
    except InvalidInputError:
        return True
    return False


# ------------------------------------------------------------------ fixtures

_tmpfiles = []


def fresh_db(paid: bool = True, users: int = 0):
    """A throwaway database, optionally pre-seeded with `users` accounts."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = get_session(engine)
    made = []
    for n in range(users):
        user = User(email=f"r7-{len(_tmpfiles)}-{n}@test.local", password_hash="x", is_active=paid)
        db.add(user)
        db.flush()
        made.append(user.id)
    db.commit()
    db.close()
    return engine, made


def csrf_for(client):
    secret = client.cookies.get(security.CSRF_COOKIE)
    return security.mint_csrf_token(
        secret, security.csrf_binding_for_auth(client.cookies.get("token") or "")
    )


def client_for(engine, user_id=None):
    main.engine = engine
    client = TestClient(main.app)
    client.__enter__()
    client.get("/login")  # seeds the CSRF cookie via the middleware
    if user_id is not None:
        client.cookies.set("token", main.make_token(user_id))
    return client, csrf_for(client)


def roomy_limiters():
    saved = (main.signup_limiter, main.login_limiter,
             main.add_url_limiter, main.add_url_user_limiter)
    main.signup_limiter = security.TokenBucket(capacity=10_000, refill_seconds=3600)
    main.login_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.add_url_limiter = security.TokenBucket(capacity=10_000, refill_seconds=3600)
    main.add_url_user_limiter = security.TokenBucket(capacity=10_000, refill_seconds=3600)
    return saved


def restore_limiters(saved):
    (main.signup_limiter, main.login_limiter,
     main.add_url_limiter, main.add_url_user_limiter) = saved


def rows_and_bytes(engine, model, column):
    """(row count, total characters stored in `column`) for a table."""
    db = get_session(engine)
    try:
        values = [getattr(r, column) or "" for r in db.query(model).all()]
        return len(values), sum(len(v) for v in values)
    finally:
        db.close()


# --------------------------------------------------- (F1) email is bounded

def test_normalize_email_bounds_and_shape():
    print("\n[F1] normalize_email bounds length and rejects non-addresses")

    check("a 200,013-char address is refused",
          raises(normalize_email, "a" * 200_000 + "@example.com"))
    check(f"one character over {MAX_EMAIL_LEN} is refused",
          raises(normalize_email, "a" * (MAX_EMAIL_LEN - 11) + "x@example.com"))
    check("an address exactly at the limit is accepted",
          len(normalize_email("a" * (MAX_EMAIL_LEN - 12) + "@example.com")) == MAX_EMAIL_LEN)
    check("no @ is refused", raises(normalize_email, "not-an-address"))
    check("no domain dot is refused", raises(normalize_email, "user@localhost"))
    check("an embedded space is refused", raises(normalize_email, "user name@example.com"))
    check("an empty address is refused", raises(normalize_email, "   "))
    check("surrounding whitespace is trimmed",
          normalize_email("  user@example.com \n") == "user@example.com")


def test_password_floor():
    print("\n[F1] validate_password enforces a floor and a ceiling")

    check("a 1-character password is refused", raises(validate_password, "x"))
    check(f"{MIN_PASSWORD_LEN - 1} characters is refused",
          raises(validate_password, "x" * (MIN_PASSWORD_LEN - 1)))
    check(f"{MIN_PASSWORD_LEN} characters is accepted",
          validate_password("x" * MIN_PASSWORD_LEN) == "x" * MIN_PASSWORD_LEN)
    check("a 10 MB password is refused", raises(validate_password, "x" * 10_000_000))


def test_signup_refuses_oversized_email():
    print("\n[F1] POST /signup writes no row for an oversized or malformed email")

    engine, _ = fresh_db()
    saved = roomy_limiters()
    # Popping STRIPE_PRICE_ID from the environment at import time only works
    # when this module is the first to import app.config. Under `pytest tests/`
    # an earlier module already imported it, so main.STRIPE_PRICE_ID still holds
    # that module's price and the "valid signup" below would call the real
    # Stripe API over the network. Force the local-dev path on the module itself,
    # and put it back so the modules after this one keep their billing config.
    saved_price = main.STRIPE_PRICE_ID
    main.STRIPE_PRICE_ID = ""
    try:
        client, token = client_for(engine)
        huge = "a" * 200_000 + "@example.com"
        resp = client.post("/signup", data={
            "email": huge, "password": "a-good-password", "csrf_token": token,
        }, follow_redirects=False)
        check("the oversized signup is rejected, not redirected",
              resp.status_code == 400, f"got {resp.status_code}")

        rows, chars = rows_and_bytes(engine, User, "email")
        check("nothing was written to users", rows == 0, f"{rows} rows, {chars} chars")

        resp = client.post("/signup", data={
            "email": "shorty@example.com", "password": "x", "csrf_token": token,
        }, follow_redirects=False)
        check("a 1-character password is rejected at signup",
              resp.status_code == 400, f"got {resp.status_code}")
        check("still nothing in users", rows_and_bytes(engine, User, "email")[0] == 0)

        resp = client.post("/signup", data={
            "email": "  real@example.com  ", "password": "a-good-password",
            "csrf_token": token,
        }, follow_redirects=False)
        check("a valid signup still succeeds", resp.status_code == 303,
              f"got {resp.status_code}")
        rows, chars = rows_and_bytes(engine, User, "email")
        check("exactly one, trimmed, bounded row", rows == 1 and chars <= MAX_EMAIL_LEN,
              f"{rows} rows, {chars} chars")
    finally:
        main.STRIPE_PRICE_ID = saved_price
        restore_limiters(saved)
        client.__exit__(None, None, None)


def test_login_refuses_oversized_email():
    print("\n[F1] POST /login refuses an oversized address before the DB query")

    engine, _ = fresh_db(users=1)
    saved = roomy_limiters()
    try:
        client, token = client_for(engine)
        resp = client.post("/login", data={
            "email": "a" * 200_000 + "@example.com", "password": "whatever",
            "csrf_token": token,
        }, follow_redirects=False)
        check("rejected with the generic error", resp.status_code == 400,
              f"got {resp.status_code}")
        check("the error does not distinguish it from a bad password",
              "Invalid email or password" in resp.text)
    finally:
        restore_limiters(saved)
        client.__exit__(None, None, None)


# --------------------------------------------------- (F2) label is bounded

def test_normalize_label_bounds_and_strips():
    print("\n[F2] normalize_label bounds length and strips control characters")

    check("a 500,000-char label is refused", raises(normalize_label, "L" * 500_000))
    check(f"one character over {MAX_LABEL_LEN} is refused",
          raises(normalize_label, "L" * (MAX_LABEL_LEN + 1)))
    check("a label exactly at the limit is accepted",
          normalize_label("L" * MAX_LABEL_LEN) == "L" * MAX_LABEL_LEN)
    check("an empty label is refused", raises(normalize_label, "   "))
    check("surrounding whitespace is trimmed", normalize_label("  Acme  ") == "Acme")

    injected = normalize_label("Acme\r\nBcc: victim@example.com")
    check("CR and LF do not survive", "\r" not in injected and "\n" not in injected,
          repr(injected))
    check("a NUL does not survive", "\x00" not in normalize_label("Acme\x00Corp"))


def test_add_url_refuses_oversized_label():
    print("\n[F2] POST /urls/new writes no row for an oversized label")

    engine, users = fresh_db(users=1)
    saved = roomy_limiters()
    try:
        client, token = client_for(engine, user_id=users[0])
        resp = client.post("/urls/new", data={
            "label": "L" * 500_000, "url": "https://example.com/p",
            "check_interval_hours": "24", "csrf_token": token,
        }, follow_redirects=False)
        check("the oversized label is a form error",
              resp.status_code == 400, f"got {resp.status_code}")

        rows, chars = rows_and_bytes(engine, MonitoredUrl, "label")
        check("no monitor row was written", rows == 0, f"{rows} rows, {chars} chars")

        resp = client.post("/urls/new", data={
            "label": "   ", "url": "https://example.com/p",
            "check_interval_hours": "24", "csrf_token": token,
        }, follow_redirects=False)
        check("a whitespace-only label is a form error",
              resp.status_code == 400, f"got {resp.status_code}")
        check("still no monitor row",
              rows_and_bytes(engine, MonitoredUrl, "label")[0] == 0)
    finally:
        restore_limiters(saved)
        client.__exit__(None, None, None)


def test_alert_subject_cannot_carry_headers():
    print("\n[F2] send_change_alert cannot put CR/LF into the Subject")

    sent = {}

    async def fake_send(to, subject, body):
        sent["to"], sent["subject"], sent["body"] = to, subject, body
        return True

    real_send = alerts._send_email
    alerts._send_email = fake_send
    try:
        asyncio.run(alerts.send_change_alert(
            "user@example.com",
            "Acme\r\nBcc: victim@example.com\nSubject: Free money",
            "https://example.com/p",
            "prices moved",
        ))
    finally:
        alerts._send_email = real_send

    subject = sent.get("subject", "")
    check("no CR in the subject", "\r" not in subject, repr(subject))
    check("no LF in the subject", "\n" not in subject, repr(subject))
    check("the label's text is still there", "Acme" in subject)
    check("the subject is bounded",
          len(alerts.header_safe("L" * 500_000)) <= MAX_LABEL_LEN)
    check("header_safe leaves an ordinary label alone",
          header_safe("Acme Corp Pricing") == "Acme Corp Pricing")


if __name__ == "__main__":
    try:
        test_normalize_email_bounds_and_shape()
        test_password_floor()
        test_signup_refuses_oversized_email()
        test_login_refuses_oversized_email()
        test_normalize_label_bounds_and_strips()
        test_add_url_refuses_oversized_label()
        test_alert_subject_cannot_carry_headers()
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
