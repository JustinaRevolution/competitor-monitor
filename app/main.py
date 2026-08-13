"""
PriceGazer — FastAPI Web Application
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import hashlib, hmac
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from passlib.hash import bcrypt

from app.config import (
    SECRET_KEY, APP_URL, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET,
    COOKIE_SECURE, COOKIE_SAMESITE, IS_PRODUCTION,
    BILLING_ENABLED, REQUIRE_PAID_ACCOUNT,
)
from app.models import (
    Base, User, MonitoredUrl, ChangeEvent,
    DEFAULT_CHECK_INTERVAL_HOURS, FAILURE_PAUSE_THRESHOLD, InvalidIntervalError,
    MAX_ALERT_ATTEMPTS, MIN_CHECK_INTERVAL_HOURS, MAX_CHECK_INTERVAL_HOURS,
    REFERRAL_TRIAL_DAYS, credit_referrer_for_payment, ensure_referral_code,
    entitled_user_clause, get_engine, get_session, init_db,
    normalize_referral_code, pending_alert_events,
    prune_change_events, recall_failure_state, record_referral,
    referral_stats, referral_trial_active, remember_failure_state, resolve_referrer,
    user_is_paid, utcnow, validate_check_interval_hours,
)
from app.monitor import check_url
from app.alerts import send_change_alert, send_welcome_email
from app.security import (
    CSRF_COOKIE, MAX_EMAIL_LEN, MAX_PASSWORD_LEN, InvalidInputError,
    UnsafeUrlError, add_url_limiter,
    add_url_user_limiter, check_now_limiter, check_now_user_limiter,
    csrf_secret_is_valid, csrf_token, enforce_rate_limit, enforce_user_rate_limit,
    login_limiter, new_csrf_secret, normalize_email, normalize_label,
    set_csrf_cookie, signup_limiter, validate_password, validate_url_async,
    verify_csrf,
)

# ----- Passwords -----

BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")

# passlib 1.7.4 logs a noisy traceback probing bcrypt's removed __about__ module.
# It is harmless and already trapped; keep it out of the startup log.
logging.getLogger("passlib.handlers.bcrypt").setLevel(logging.ERROR)

# Cost of one bcrypt verify, used to keep "no such user" as slow as a real login.
_DUMMY_BCRYPT_HASH = bcrypt.hash("dummy-password-for-timing-equalization")


def _hash_password(password: str) -> str:
    return bcrypt.hash(password)


async def _hash_password_async(password: str) -> str:
    """
    bcrypt is ~240ms of pure CPU. On a single uvicorn worker, running it inline
    stalls the whole event loop, so a handful of concurrent logins is a DoS.
    Every request path hashes in a worker thread instead.
    """
    return await asyncio.to_thread(_hash_password, password)


def _is_legacy_hash(stored: str) -> bool:
    """True for the old salt:sha256 format that predates bcrypt."""
    return bool(stored) and not stored.startswith(BCRYPT_PREFIXES)


def _verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    if _is_legacy_hash(stored):
        # Legacy salted single-round SHA-256. Verified in constant time, then
        # rehashed with bcrypt by the caller on success.
        try:
            salt, h = stored.split(":", 1)
        except ValueError:
            return False
        candidate = hashlib.sha256((salt + password).encode()).hexdigest()
        return hmac.compare_digest(candidate, h)
    try:
        return bcrypt.verify(password, stored)
    except ValueError:
        return False


async def _verify_password_async(password: str, stored: str) -> bool:
    return await asyncio.to_thread(_verify_password, password, stored)


def _dummy_verify() -> None:
    """Burn a bcrypt verify so a missing user costs the same as a wrong password."""
    try:
        bcrypt.verify("wrong-password", _DUMMY_BCRYPT_HASH)
    except ValueError:
        pass


async def _dummy_verify_async() -> None:
    await asyncio.to_thread(_dummy_verify)


def _set_auth_cookie(response, token: str) -> None:
    response.set_cookie(
        "token", token,
        max_age=86400 * 30,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )

# ----- App Setup -----

engine = get_engine()

templates = Jinja2Templates(directory="app/templates")
# Templates call {{ csrf_token(request) }} inside every mutating form.
templates.env.globals["csrf_token"] = csrf_token

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="auth")

def make_token(user_id: int) -> str:
    return serializer.dumps(str(user_id))

def parse_token(token: str, max_age: int = 86400 * 30) -> int | None:
    """Returns user_id or None."""
    try:
        data = serializer.loads(token, max_age=max_age)
        return int(data)
    except (BadSignature, SignatureExpired, ValueError):
        return None

def get_user_from_request(request: Request, db: Session) -> User | None:
    token = request.cookies.get("token")
    if not token:
        return None
    user_id = parse_token(token)
    if user_id is None:
        return None
    return db.query(User).filter(User.id == user_id).first()


def _smoke_check_scheduled_cycle() -> None:
    """
    Prove at startup that a scheduled-style check can actually complete.

    The scheduler used to fail silently every 15 minutes: aware timestamps went
    into naive DateTime columns, came back naive, and the elapsed-time
    subtraction raised TypeError before anything committed. This runs the same
    write → read → subtract → record-a-change → commit sequence against a
    throwaway in-memory database, so a regression in the datetime convention is
    loud at boot instead of invisible for a week.
    """
    from sqlalchemy import create_engine as _create_engine
    from sqlalchemy.orm import Session as _Session

    probe = _create_engine("sqlite://")
    Base.metadata.create_all(probe)
    with _Session(probe) as db:
        user = User(email="smoke@localhost", password_hash="x", is_active=True)
        db.add(user)
        db.flush()
        monitored = MonitoredUrl(
            user_id=user.id, label="smoke", url="https://example.com",
            last_checked_at=utcnow(), last_hash="old", last_content="old content",
        )
        db.add(monitored)
        db.commit()
        db.expire_all()  # force a real read-back through the SQLite type layer

        row = db.query(MonitoredUrl).one()
        # The subtraction that used to blow up.
        (utcnow() - row.last_checked_at).total_seconds()

        old_hash, old_content = row.last_hash, row.last_content
        row.last_hash, row.last_content = "new", "new content"
        row.last_checked_at = utcnow()
        db.add(ChangeEvent(
            url_id=row.id, old_hash=old_hash, new_hash=row.last_hash,
            old_content=old_content, new_content=row.last_content,
        ))
        db.commit()

        change = db.query(ChangeEvent).one()
        assert change.old_hash != change.new_hash, "ChangeEvent recorded new==old"
    probe.dispose()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: init DB and start scheduler
    init_db(engine)
    try:
        _smoke_check_scheduled_cycle()
        print("[STARTUP] Smoke check passed — scheduled check cycle completes and commits")
    except Exception as e:
        print(f"[STARTUP] FATAL: scheduled check cycle is broken: {e!r}")
        raise
    _start_scheduler()
    yield
    # Shutdown
    _stop_scheduler()


app = FastAPI(title="PriceGazer", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

if IS_PRODUCTION and not STRIPE_WEBHOOK_SECRET:
    print("[STARTUP] WARNING: STRIPE_WEBHOOK_SECRET is empty — /stripe-webhook will reject all events.")


@app.middleware("http")
async def csrf_cookie_middleware(request: Request, call_next):
    """
    Make sure every browser carries a CSRF secret cookie. Form tokens are
    signatures over this value, so a cross-site page cannot forge one: it can
    neither read the cookie nor sign a token.
    """
    secret = request.cookies.get(CSRF_COOKIE, "")
    is_new = not csrf_secret_is_valid(secret)
    if is_new:
        secret = new_csrf_secret()
    request.state.csrf_secret = secret

    response = await call_next(request)
    if is_new:
        set_csrf_cookie(response, secret)
    return response


# ----- Background Scheduler -----

_scheduler = None

# Outbound fetches are the scarce resource: they hold sockets open against
# third-party sites. Cap how many can be in flight at once across the whole
# process, so a slow sweep and a burst of "Check now" clicks can't pile up.
MAX_CONCURRENT_CHECKS = 5
_check_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)


async def _bounded_check_url(url: str, previous_hash, previous_content) -> dict:
    """Run one check under the global concurrency cap."""
    async with _check_semaphore:
        return await check_url(url, previous_hash, previous_content)


def _start_scheduler():
    global _scheduler
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        _scheduler = AsyncIOScheduler()
        _scheduler.add_job(
            run_scheduled_checks,
            "interval",
            minutes=15,
            id="check_all_urls",
            replace_existing=True,
            # One sweep at a time. A sweep that outruns the 15-minute tick used
            # to start a second copy on top of the first, doubling outbound
            # load on every target.
            max_instances=1,
            coalesce=True,
            misfire_grace_time=300,
        )
        _scheduler.start()
        print("[SCHEDULER] Started — checking eligible URLs every 15 minutes")
    except Exception as e:
        # Without a scheduler the product does nothing: no page is ever checked
        # and no alert is ever sent. That has to be a loud boot failure, not a
        # line in the log.
        print(f"[SCHEDULER] FATAL: failed to start: {e!r}")
        raise

def _stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        print("[SCHEDULER] Stopped")


async def _deliver_change_alert(change: ChangeEvent, monitored: MonitoredUrl,
                               user: User, result: dict | None = None) -> bool:
    """
    Send the alert for `change` and mark it alerted **only** if the send worked.

    A failed send leaves `alerted` False and counts an attempt, so
    `retry_pending_alerts` picks the event up on a later sweep; a change marked
    alerted after a failed send is silently lost forever, which is the one
    failure mode this product cannot have.

    `result` is the fresh check result when one is at hand. On a retry there is
    no live result, so the email is rebuilt from what the row stored.
    """
    result = result or {}
    diff_summary = (
        result.get("diff_summary")
        or change.diff_summary
        or "Content changed"
    )
    now = utcnow()
    try:
        sent = await send_change_alert(
            to_email=user.email,
            url_label=monitored.label,
            url=monitored.url,
            diff_summary=diff_summary,
            # Only a live check carries the pricing breakdown; it is not stored.
            pricing_changes=result.get("pricing_changes", ""),
        )
    except Exception as e:
        change.record_alert_attempt(now)
        print(f"[ALERT] {monitored.label}: send failed, queued for retry "
              f"(attempt {change.alert_attempts}/{MAX_ALERT_ATTEMPTS}): {e!r}")
        return False
    if sent:
        change.mark_alerted(now)
        print(f"[ALERT] {monitored.label}: change detected, alert sent to {user.email}")
    else:
        change.record_alert_attempt(now)
        print(f"[ALERT] {monitored.label}: send returned failure, queued for retry "
              f"(attempt {change.alert_attempts}/{MAX_ALERT_ATTEMPTS})")
    return bool(sent)


async def retry_pending_alerts(db, now=None) -> int:
    """
    Re-send alerts for changes whose email never went out. Returns the number
    delivered.

    Nothing else revisits these rows: by the time a send fails the monitor's
    cursor has already advanced, so the next check hashes the same page, reports
    no change, and the un-alerted event would sit there forever. This sweep is
    the only thing standing between a 30-second Resend outage and a customer who
    is never told their competitor moved.
    """
    now = now or utcnow()
    pending = pending_alert_events(db, now)
    if not pending:
        return 0
    delivered = 0
    for change in pending:
        # One undeliverable event must not abort the rest of the backlog.
        try:
            monitored = change.url
            user = monitored.user if monitored else None
            if monitored is None or user is None:
                continue
            if await _deliver_change_alert(change, monitored, user):
                delivered += 1
            elif change.alert_gave_up(now):
                print(f"[ALERT] {monitored.label}: giving up on the "
                      f"{change.detected_at:%Y-%m-%d %H:%M} UTC change after "
                      f"{change.alert_attempts} failed attempt(s)")
        except Exception as e:
            print(f"[ALERT] retry failed for change {change.id}: {e!r}")
            continue
    print(f"[ALERT] Retry sweep: {delivered}/{len(pending)} pending alert(s) delivered")
    return delivered


async def run_scheduled_checks():
    """Check every due URL belonging to a paid account."""
    db = get_session(engine)
    try:
        now = utcnow()

        # Drain the un-alerted backlog first, and commit it on its own, so a
        # later failure in the check loop cannot roll back a delivered alert
        # and cause it to be sent twice.
        try:
            await retry_pending_alerts(db, now)
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"[ALERT] Retry sweep failed: {e!r}")

        # Monitoring is a paid feature, and this is the one path that fetches
        # URLs without a request behind it — an unpaid (or cancelled) account
        # must not keep the server making outbound requests on its behalf.
        query = db.query(MonitoredUrl).filter(MonitoredUrl.is_active == True)
        if REQUIRE_PAID_ACCOUNT:
            query = query.join(User).filter(entitled_user_clause(now))
        urls = query.all()
        checked = 0
        for monitored in urls:
            # One bad URL must not abort the whole sweep — that is how every
            # scheduled check used to die silently before reaching the commit.
            try:
                # Interval elapsed *and* not serving a failure cooldown.
                if not monitored.is_due(now):
                    continue

                result = await _bounded_check_url(
                    monitored.url,
                    monitored.last_hash,
                    monitored.last_content,
                )

                if result.get("error"):
                    monitored.record_failure(result["error"], now)
                    if monitored.paused_reason:
                        print(f"[CHECK] {monitored.label}: {monitored.paused_reason}")
                    else:
                        print(
                            f"[CHECK] {monitored.label}: {result['error']} "
                            f"(failure #{monitored.consecutive_failures}, "
                            f"next retry in {monitored.cooldown_until()})"
                        )
                    continue

                # Snapshot the previous state before it is overwritten, so the
                # ChangeEvent records a real before/after pair.
                old_hash = monitored.last_hash
                old_content = monitored.last_content

                monitored.last_hash = result["new_hash"]
                monitored.last_content = result["new_content"]
                monitored.last_checked_at = now
                monitored.record_success()

                if result.get("changed"):
                    change = ChangeEvent(
                        url_id=monitored.id,
                        old_hash=old_hash,
                        new_hash=result["new_hash"],
                        old_content=old_content,
                        new_content=result["new_content"],
                        diff_summary=result.get("diff_summary"),
                    )
                    db.add(change)
                    db.flush()
                    # Bound the stored history so a target that changes every
                    # sweep cannot grow this monitor's rows without limit.
                    prune_change_events(db, monitored.id)

                    user = monitored.user
                    if user:
                        await _deliver_change_alert(change, monitored, user, result)

                checked += 1
            except Exception as e:
                print(f"[CHECK] {monitored.label}: skipped after error: {e!r}")
                continue

        db.commit()
        if checked > 0:
            print(f"[CHECK] Checked {checked} URL(s)")
    except Exception as e:
        db.rollback()
        print(f"[CHECK] Error during scheduled check: {e!r}")
    finally:
        db.close()


# ----- Helper: require auth -----

async def require_user(request: Request, db: Session = Depends(lambda: get_session(engine))):
    user = get_user_from_request(request, db)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


# ----- Helper: require payment -----
#
# Free tier: sign up, log in, see the dashboard. Everything that makes the
# server fetch a URL — adding a monitor, "Check now", and the scheduled sweep —
# needs an active subscription. Unauthenticated callers never get that far,
# which also closes the anonymous path to the URL fetcher.

PAYWALL_MESSAGE = (
    "Monitoring is a paid feature. Start your subscription to add pages and run checks."
)


def _paid_or_redirect(user: User | None):
    """
    None when `user` may use the paid features; otherwise the response to return.

    Unauthenticated → /login. Authenticated but unpaid → /billing.
    """
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not user_is_paid(user):
        return RedirectResponse("/billing", status_code=303)
    return None


# ----- Routes -----

@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if user:
            # Logged in → redirect to dashboard
            return RedirectResponse("/dashboard", status_code=303)
        return templates.TemplateResponse("index.html", {"request": request, "user": None})
    finally:
        db.close()


# ----- Referrals -----

def referral_link(code: str) -> str:
    """The URL a referrer hands out. `ref` is read by both /signup handlers."""
    return f"{APP_URL.rstrip('/')}/signup?ref={code}"


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    # Carried through to the form's hidden field so the code survives the POST.
    # Not validated here: whether it is real is decided at signup, and telling an
    # anonymous visitor which codes exist would make them enumerable.
    return templates.TemplateResponse("signup.html", {
        "request": request, "user": None,
        "ref": normalize_referral_code(request.query_params.get("ref", "")),
        "referral_trial_days": REFERRAL_TRIAL_DAYS,
    })


@app.post("/signup")
async def signup(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    ref: str = Form(""),
):
    verify_csrf(request, csrf_token)
    enforce_rate_limit(request, signup_limiter, "signup")

    # Bound and check the credentials before anything is queried or stored. The
    # email column is `String(255)`, which SQLite ignores entirely, so without
    # this an unauthenticated request writes a row as large as the body nginx
    # accepts — 10 MB a time, three times an hour per IP, forever, with no
    # account and no payment behind it and nothing that ever prunes `users`.
    # A code may arrive on the form (the hidden field) or on the query string, so
    # that /signup?ref=CODE still works if the form is posted without it.
    ref_code = normalize_referral_code(ref) or normalize_referral_code(
        request.query_params.get("ref", ""))

    try:
        email = normalize_email(email)
        validate_password(password)
    except InvalidInputError as e:
        return templates.TemplateResponse("signup.html", {
            "request": request, "user": None, "error": str(e), "ref": ref_code,
            "referral_trial_days": REFERRAL_TRIAL_DAYS,
        }, status_code=400)

    db = get_session(engine)
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            return templates.TemplateResponse("signup.html", {
                "request": request, "user": None,
                "error": "Email already registered", "ref": ref_code,
                "referral_trial_days": REFERRAL_TRIAL_DAYS,
            })

        user = User(
            email=email,
            password_hash=await _hash_password_async(password),
            is_active=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # An unknown, unpaid or self-referring code is simply ignored — the
        # account is already created, and a bad code is not worth failing on.
        referrer = resolve_referrer(db, ref_code, email=email) if ref_code else None
        if referrer is not None:
            record_referral(db, user, referrer)
            db.commit()
            # The first month is already free, so sending them to Stripe now
            # would be asking for money we said we wouldn't take. They can
            # subscribe from /billing whenever they like — which is also what
            # credits the referrer.
            token = make_token(user.id)
            response = RedirectResponse("/dashboard?welcome=referral", status_code=303)
            _set_auth_cookie(response, token)
            return response

        # Create Stripe Checkout Session
        try:
            checkout_url = await _create_stripe_checkout(user)
        except StripeUnavailableError:
            # The account is already committed; only the payment session failed.
            # Log them in and land them on /billing, which has the retry button,
            # rather than returning a 500 over an account they can't reach.
            checkout_url = "/billing?error=checkout"

        # Log user in
        token = make_token(user.id)
        response = RedirectResponse(checkout_url, status_code=303)
        _set_auth_cookie(response, token)
        return response
    finally:
        db.close()


# ----- Stripe -----

# Every call in the `stripe` SDK is a blocking HTTPS round trip, and its default
# client waits 80 seconds before giving up. This app runs a single uvicorn
# worker, so making that call from inside a coroutine stops *everything* in the
# process — other requests, health checks, the scheduler sweep — for as long as
# Stripe takes to answer. POST /signup reaches it with no authentication at all,
# which made one request against a slow or unreachable api.stripe.com an outage
# of the whole app rather than a slow signup.
#
# Three things bound it, and all three are needed:
#   * the call runs in a worker thread, so the event loop stays free — the same
#     shape as _hash_password_async and security.validate_and_pin_async;
#   * the SDK gets a short explicit timeout and no retries, so the thread itself
#     ends instead of leaking out of the pool bcrypt and DNS also draw from;
#   * a semaphore caps how many of those threads this path can ever hold.
STRIPE_TIMEOUT_SECONDS = 10
MAX_CONCURRENT_STRIPE_CALLS = 4
_stripe_semaphore = asyncio.Semaphore(MAX_CONCURRENT_STRIPE_CALLS)
_stripe_configured = False


class StripeUnavailableError(RuntimeError):
    """Stripe refused or never answered — there is no checkout URL to send anyone to."""


def _configure_stripe():
    """Return the `stripe` module, keyed and pinned to a bounded HTTP client."""
    global _stripe_configured
    import stripe

    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
    if not _stripe_configured:
        # `requests` is a hard dependency of the stripe SDK, so RequestsClient is
        # what it picks by itself anyway; naming it means the timeout can't
        # silently stop applying if that default ever moves to a client whose
        # constructor ignores it.
        stripe.default_http_client = stripe.RequestsClient(timeout=STRIPE_TIMEOUT_SECONDS)
        # A retry multiplies how long the worker thread is held for one request.
        # 0 is already the SDK default — pinning it keeps it that way.
        stripe.max_network_retries = 0
        _stripe_configured = True
    return stripe


async def _create_stripe_checkout(user: User) -> str:
    """Create a Stripe Checkout Session. Returns the checkout URL."""
    if not STRIPE_PRICE_ID:
        # No price configured means there is no way to pay, so this is local dev
        # (production refuses to boot in this state unless ALLOW_FREE_ACCESS is
        # set). Activate directly so the app is usable without Stripe.
        db = get_session(engine)
        try:
            u = db.query(User).filter(User.id == user.id).first()
            u.is_active = True
            db.commit()
        finally:
            db.close()
        return f"{APP_URL}/dashboard"

    stripe = _configure_stripe()

    # Read the ORM attributes here, on the event loop. The Session that loaded
    # `user` belongs to this thread, and touching an expired attribute inside the
    # worker would emit a refresh query from the wrong one.
    email, user_id = user.email, user.id

    def _create():
        return stripe.checkout.Session.create(
            customer_email=email,
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=f"{APP_URL}/dashboard?welcome=1",
            cancel_url=f"{APP_URL}/signup",
            metadata={"user_id": str(user_id)},
        )

    try:
        async with _stripe_semaphore:
            session = await asyncio.to_thread(_create)
    except stripe.error.StripeError as e:
        # Timeouts and connection failures arrive here as APIConnectionError, a
        # declined key as AuthenticationError. The account already exists either
        # way; the caller decides where to land the visitor.
        print(f"[STRIPE] checkout session failed: {type(e).__name__}: {e}")
        raise StripeUnavailableError(str(e)) from e
    return session.url


@app.get("/billing", response_class=HTMLResponse)
async def billing(request: Request):
    """Where an unpaid account lands: what it gets, and a button to subscribe."""
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)
        # `is_active`, not `user_is_paid`: an account inside its free referral
        # month is entitled but has nothing to manage here yet, and bouncing it
        # to the dashboard would leave it no way to subscribe before the month
        # runs out.
        if user.is_active:
            return RedirectResponse("/dashboard", status_code=303)
        return templates.TemplateResponse("billing.html", {
            "request": request, "user": user, "is_paid": False,
            "billing_enabled": BILLING_ENABLED,
            "on_trial": referral_trial_active(user),
            "trial_ends_at": user.trial_ends_at,
            "referral_credit_months": user.referral_credit_months or 0,
            # Set when a checkout session could not be created, so the visitor
            # is told why they landed here instead of on Stripe.
            "checkout_error": request.query_params.get("error") == "checkout",
        })
    finally:
        db.close()


@app.post("/billing/checkout")
async def billing_checkout(request: Request, csrf_token: str = Form("")):
    """Start (or restart) Stripe Checkout for the logged-in account."""
    verify_csrf(request, csrf_token)
    enforce_rate_limit(request, signup_limiter, "checkout")
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)
        # Same reason as GET /billing: a trial account must still be able to buy.
        if user.is_active:
            return RedirectResponse("/dashboard", status_code=303)
        try:
            checkout_url = await _create_stripe_checkout(user)
        except StripeUnavailableError:
            return RedirectResponse("/billing?error=checkout", status_code=303)
        return RedirectResponse(checkout_url, status_code=303)
    finally:
        db.close()


# The only Stripe subscription statuses that entitle an account to paid access.
# Everything else — past_due, unpaid, canceled, incomplete, incomplete_expired,
# paused — means we stop monitoring for them.
PAID_SUBSCRIPTION_STATUSES = ("active", "trialing")


@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events (subscription created, updated, cancelled)."""
    # Signature verification below is a local HMAC, not a call out to Stripe, so
    # nothing on this path blocks the loop. Configuring through the same helper
    # keeps one place where the key and the client timeout are set.
    stripe = _configure_stripe()

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    endpoint_secret = STRIPE_WEBHOOK_SECRET
    if not endpoint_secret:
        # Never accept unverifiable webhook events — they can activate accounts.
        raise HTTPException(status_code=503, detail="Webhook secret not configured")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400)

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        # Stripe fires this event for mode="subscription" even when the first
        # invoice fails or SCA is abandoned: the subscription is created
        # `incomplete` and the session arrives with payment_status "unpaid".
        # Activating on the event alone hands an abandoned checkout full paid
        # access, so only a settled session entitles the account. A trial takes
        # no money up front and arrives as "no_payment_required" — that counts.
        settled = session.get("payment_status") in ("paid", "no_payment_required")
        user_id = session.get("metadata", {}).get("user_id")
        if user_id:
            db = get_session(engine)
            try:
                user = db.query(User).filter(User.id == int(user_id)).first()
                if user:
                    # An unsettled session still links the Stripe ids if we have
                    # none, so that a subscription which pays later is matched
                    # back to this account by customer.subscription.updated. It
                    # never overwrites ids we already trust, and never entitles.
                    if settled or not user.stripe_customer_id:
                        user.stripe_customer_id = session.get("customer")
                    if settled or not user.stripe_subscription_id:
                        user.stripe_subscription_id = session.get("subscription")
                    if settled:
                        user.is_active = True
                        # "Get a month free": the friend has actually paid, so
                        # whoever referred them banks a month. A no-op unless
                        # this account signed up with a code, and idempotent, so
                        # a retried webhook cannot bank a second one.
                        credit_referrer_for_payment(db, user)
                    db.commit()
                    if settled:
                        # Send welcome email
                        await send_welcome_email(user.email)
            finally:
                db.close()

    elif event["type"] in ("customer.subscription.updated", "customer.subscription.deleted"):
        # A subscription that goes past_due/unpaid/canceled has to revoke paid
        # access. Handling only `deleted` left an unpaid account fully active
        # until Stripe eventually deleted the subscription — often never, if
        # dunning is configured to leave it hanging.
        subscription = event["data"]["object"]
        customer_id = subscription.get("customer")
        deleted = event["type"] == "customer.subscription.deleted"
        status = subscription.get("status")
        entitled = (not deleted) and status in PAID_SUBSCRIPTION_STATUSES
        if customer_id:
            db = get_session(engine)
            try:
                user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
                if user:
                    user.is_active = entitled
                    if deleted:
                        user.stripe_subscription_id = None
                    elif subscription.get("id"):
                        user.stripe_subscription_id = subscription["id"]
                    db.commit()
            finally:
                db.close()

    return {"ok": True}


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "user": None})


@app.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
):
    verify_csrf(request, csrf_token)
    enforce_rate_limit(request, login_limiter, "login")

    # Length only, and no minimum: accounts created before signup validated any
    # of this must still be able to log in. Nothing over the limit can match a
    # stored credential, so it is refused before the query and the bcrypt verify
    # rather than carried through them.
    email = (email or "").strip()
    if len(email) > MAX_EMAIL_LEN or len(password or "") > MAX_PASSWORD_LEN:
        return templates.TemplateResponse("login.html", {
            "request": request, "user": None,
            "error": "Invalid email or password",
        }, status_code=400)

    db = get_session(engine)
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            # Equalize timing so a missing account is not distinguishable.
            await _dummy_verify_async()
            return templates.TemplateResponse("login.html", {
                "request": request, "user": None,
                "error": "Invalid email or password",
            })

        if not await _verify_password_async(password, user.password_hash):
            return templates.TemplateResponse("login.html", {
                "request": request, "user": None,
                "error": "Invalid email or password",
            })

        # Migrate legacy salt:sha256 hashes to bcrypt on first successful login.
        if _is_legacy_hash(user.password_hash):
            user.password_hash = await _hash_password_async(password)
            db.commit()

        # Unpaid accounts may log in and see their dashboard; the paywall lives
        # on the paid features themselves, so there is somewhere to land and pay
        # from instead of a dead end at the login form.
        token = make_token(user.id)
        destination = "/dashboard" if user_is_paid(user) else "/billing"
        response = RedirectResponse(destination, status_code=303)
        _set_auth_cookie(response, token)
        return response
    finally:
        db.close()


@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("token")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)

        urls = db.query(MonitoredUrl).filter(MonitoredUrl.user_id == user.id).all()

        # Only a subscribed account gets a link to share: `resolve_referrer`
        # refuses codes from trial accounts, so showing one there would promise
        # a friend a month that signup would then decline to give.
        referral = None
        if user.is_active:
            code = ensure_referral_code(db, user)
            db.commit()
            referral = dict(referral_stats(db, user), code=code,
                            link=referral_link(code))

        return templates.TemplateResponse("dashboard.html", {
            "request": request, "user": user, "urls": urls,
            "is_paid": user_is_paid(user), "paywall_message": PAYWALL_MESSAGE,
            "referral": referral,
            "on_trial": referral_trial_active(user),
            "trial_ends_at": user.trial_ends_at,
            "welcome_referral": request.query_params.get("welcome") == "referral",
            "referral_trial_days": REFERRAL_TRIAL_DAYS,
        })
    finally:
        db.close()


@app.get("/urls/new", response_class=HTMLResponse)
async def add_url_page(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        blocked = _paid_or_redirect(user)
        if blocked is not None:
            return blocked
        return templates.TemplateResponse("add_url.html", {
            "request": request, "user": user, "is_paid": True,
            "min_interval": MIN_CHECK_INTERVAL_HOURS,
            "max_interval": MAX_CHECK_INTERVAL_HOURS,
        })
    finally:
        db.close()


@app.post("/urls/new")
async def add_url(
    request: Request,
    label: str = Form(...),
    url: str = Form(...),
    check_interval_hours: str = Form(str(DEFAULT_CHECK_INTERVAL_HOURS)),
    csrf_token: str = Form(""),
):
    verify_csrf(request, csrf_token)
    enforce_rate_limit(request, add_url_limiter, "add_url")

    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        # This route fetches the submitted URL from the server, so it is gated
        # on auth *and* payment before anything is resolved or fetched.
        blocked = _paid_or_redirect(user)
        if blocked is not None:
            return blocked

        # Per-account ceiling on top of the per-IP one: adding a URL triggers an
        # immediate server-side fetch, so one paid account rotating IPs would
        # otherwise have an unbounded outbound budget.
        enforce_user_rate_limit(user.id, add_url_user_limiter, "add_url")

        def form_error(message: str):
            return templates.TemplateResponse("add_url.html", {
                "request": request, "user": user, "is_paid": True,
                "min_interval": MIN_CHECK_INTERVAL_HOURS,
                "max_interval": MAX_CHECK_INTERVAL_HOURS,
                "error": message,
            }, status_code=400)

        url_count = db.query(MonitoredUrl).filter(MonitoredUrl.user_id == user.id).count()
        if url_count >= user.max_urls:
            return form_error(f"Max {user.max_urls} URLs reached. Upgrade to monitor more.")

        # The interval drives the scheduler's due-check arithmetic; an
        # out-of-range value is a re-fetch loop against someone else's server.
        try:
            interval = validate_check_interval_hours(check_interval_hours)
        except InvalidIntervalError as e:
            return form_error(str(e))

        # `max_urls` caps rows, not bytes: 20 adds an hour against a 10 MB body
        # limit, and deleting then re-adding makes even that unlimited over
        # time. Bound the label here, where the column does not.
        try:
            label = normalize_label(label)
        except InvalidInputError as e:
            return form_error(str(e))

        # Reject non-http(s) schemes and anything resolving into the private
        # network before the URL is ever stored. Re-checked again at fetch time.
        url = url.strip()
        try:
            await validate_url_async(url)
        except UnsafeUrlError as e:
            return form_error(str(e))

        # `validate_url_async` above resolves DNS on a worker thread, so the
        # event loop was free the whole time: concurrent adds from one account
        # could each pass the count check at the top and then all insert past
        # `max_urls`. Re-count here, after the last await, where nothing can
        # interleave before the insert.
        url_count = db.query(MonitoredUrl).filter(MonitoredUrl.user_id == user.id).count()
        if url_count >= user.max_urls:
            return form_error(f"Max {user.max_urls} URLs reached. Upgrade to monitor more.")

        monitored = MonitoredUrl(
            user_id=user.id,
            label=label,
            url=url,
            check_interval_hours=interval,
        )

        # Delete + re-add used to launder the backoff: a monitor auto-paused
        # after 5 failures came back with a clean counter and an immediate
        # fetch, on repeat. Failure state parked by `delete_url` is inherited
        # here, so the cooldown survives the round trip.
        remembered = recall_failure_state(db, user.id, url)
        if remembered is not None:
            failures, last_failure_at, last_error = remembered
            monitored.consecutive_failures = failures
            monitored.last_failure_at = last_failure_at
            monitored.last_error = last_error
            if failures >= FAILURE_PAUSE_THRESHOLD:
                monitored.is_active = False
                monitored.paused_reason = (
                    f"Auto-paused after {failures} consecutive failed checks "
                    f"({last_error}). Resume to try again."
                )[:255]

        db.add(monitored)
        db.commit()

        # Do an immediate first check — unless the inherited state says this
        # target is still inside its cooldown, which is exactly the fetch the
        # delete/re-add cycle was buying.
        if remembered is None:
            result = await _bounded_check_url(url, None, None)
            if result.get("error"):
                monitored.record_failure(result["error"])
            elif result.get("new_hash"):
                monitored.last_hash = result["new_hash"]
                monitored.last_content = result["new_content"]
                monitored.last_checked_at = utcnow()
                monitored.record_success()
            db.commit()

        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()


@app.get("/urls/{url_id}")
async def url_detail(request: Request, url_id: int):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)

        monitored = db.query(MonitoredUrl).filter(
            MonitoredUrl.id == url_id,
            MonitoredUrl.user_id == user.id,
        ).first()
        if not monitored:
            raise HTTPException(status_code=404)

        changes = db.query(ChangeEvent).filter(
            ChangeEvent.url_id == monitored.id
        ).order_by(ChangeEvent.detected_at.desc()).all()

        return templates.TemplateResponse("url_detail.html", {
            "request": request, "user": user, "is_paid": user_is_paid(user),
            "url": monitored, "changes": changes,
        })
    finally:
        db.close()


@app.post("/urls/{url_id}/check")
async def check_now(request: Request, url_id: int, csrf_token: str = Form("")):
    verify_csrf(request, csrf_token)
    # This route makes the server fetch a page on demand, so cap it per source
    # IP *and* per account — an IP limit alone is free to rotate around.
    enforce_rate_limit(request, check_now_limiter, "check_now")
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        blocked = _paid_or_redirect(user)
        if blocked is not None:
            return blocked
        enforce_user_rate_limit(user.id, check_now_user_limiter, "check_now")

        monitored = db.query(MonitoredUrl).filter(
            MonitoredUrl.id == url_id,
            MonitoredUrl.user_id == user.id,
        ).first()
        if not monitored:
            raise HTTPException(status_code=404)

        def detail_error(message: str, status_code: int):
            """Re-render the detail page with an error, without fetching."""
            changes = db.query(ChangeEvent).filter(
                ChangeEvent.url_id == monitored.id
            ).order_by(ChangeEvent.detected_at.desc()).all()
            return templates.TemplateResponse("url_detail.html", {
                "request": request, "user": user, "is_paid": True,
                "url": monitored, "changes": changes, "error": message,
            }, status_code=status_code)

        now = utcnow()

        # The failure backoff has to gate *this* path too. Guarding only the
        # scheduler left "Check now" as a way to keep hammering a dead or
        # hostile target at will, and to keep fetching one the auto-pause had
        # already given up on.
        if not monitored.is_active:
            return detail_error(
                monitored.paused_reason
                or "This monitor is paused. Resume it before running a check.",
                409,
            )
        if monitored.is_in_failure_cooldown(now):
            until = monitored.cooldown_until()
            return detail_error(
                f"This monitor is in a failure cooldown after "
                f"{monitored.consecutive_failures} failed check(s)"
                f"{f' ({monitored.last_error})' if monitored.last_error else ''}. "
                f"It can be checked again at {until:%Y-%m-%d %H:%M} UTC.",
                429,
            )

        # Re-validate before fetching. The URL passed at add time, but DNS can
        # have been re-pointed into the private network since.
        try:
            await validate_url_async(monitored.url)
        except UnsafeUrlError as e:
            monitored.record_failure(f"Unsafe URL: {e}", now)
            db.commit()
            return detail_error(f"Refusing to fetch this URL: {e}", 400)

        result = await _bounded_check_url(
            monitored.url,
            monitored.last_hash,
            monitored.last_content,
        )

        # Snapshot the previous state before overwriting it, so the ChangeEvent
        # records a real before/after pair rather than new==old.
        old_hash = monitored.last_hash
        old_content = monitored.last_content

        if result.get("error"):
            # A manual check counts toward the same backoff the scheduler uses,
            # and the gate above then refuses the next one until the cooldown
            # expires — so clicking the button cannot outrun the backoff.
            monitored.record_failure(result["error"], now)
            db.commit()
            return detail_error(f"Check failed: {result['error']}", 502)

        monitored.last_hash = result.get("new_hash", monitored.last_hash)
        monitored.last_content = result.get("new_content", monitored.last_content)
        monitored.last_checked_at = now
        monitored.record_success()

        if result.get("changed"):
            change = ChangeEvent(
                url_id=monitored.id,
                old_hash=old_hash,
                new_hash=result["new_hash"],
                old_content=old_content,
                new_content=result["new_content"],
                diff_summary=result.get("diff_summary"),
            )
            db.add(change)
            db.flush()
            prune_change_events(db, monitored.id)
            # alerted is set only if the send actually succeeded.
            await _deliver_change_alert(change, monitored, user, result)

        db.commit()

        # Redirect back to detail page
        return RedirectResponse(f"/urls/{url_id}", status_code=303)
    finally:
        db.close()


@app.post("/urls/{url_id}/toggle")
async def toggle_url(request: Request, url_id: int, csrf_token: str = Form("")):
    verify_csrf(request, csrf_token)
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)

        monitored = db.query(MonitoredUrl).filter(
            MonitoredUrl.id == url_id,
            MonitoredUrl.user_id == user.id,
        ).first()
        if not monitored:
            raise HTTPException(status_code=404)

        # Resuming flips the switch and nothing else. Clearing the failure
        # counter here made the auto-pause decorative: a monitor pointed at a
        # dead (or hostile) target could be toggled back on for a fresh budget
        # of retries, forever. Only a successful check clears failure state.
        monitored.is_active = not monitored.is_active
        db.commit()
        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()


@app.post("/urls/{url_id}/delete")
async def delete_url(request: Request, url_id: int, csrf_token: str = Form("")):
    verify_csrf(request, csrf_token)
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)

        monitored = db.query(MonitoredUrl).filter(
            MonitoredUrl.id == url_id,
            MonitoredUrl.user_id == user.id,
        ).first()
        if not monitored:
            raise HTTPException(status_code=404)

        # The row goes, but its failure state does not: park it so re-adding
        # the same URL inherits the remaining cooldown instead of buying a
        # fresh retry budget. No-op for a monitor that is healthy or whose
        # cooldown has already expired.
        remember_failure_state(db, monitored)

        db.delete(monitored)
        db.commit()
        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()


# ----- Legal Pages -----

@app.get("/privacy", response_class=HTMLResponse)
async def privacy(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        return templates.TemplateResponse("privacy.html", {"request": request, "user": user})
    finally:
        db.close()


@app.get("/terms", response_class=HTMLResponse)
async def tos(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        return templates.TemplateResponse("tos.html", {"request": request, "user": user})
    finally:
        db.close()


# ----- SEO / Content Pages -----

@app.get("/vs-visualping", response_class=HTMLResponse)
async def vs_visualping(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        return templates.TemplateResponse("seo_vs_visualping.html", {"request": request, "user": user})
    finally:
        db.close()


@app.get("/how-to-track-competitor-prices", response_class=HTMLResponse)
async def how_to_track_competitor_prices(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        return templates.TemplateResponse("seo_how_to_track.html", {"request": request, "user": user})
    finally:
        db.close()


@app.get("/competitor-price-tracking", response_class=HTMLResponse)
async def competitor_price_tracking(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        return templates.TemplateResponse("seo_category.html", {"request": request, "user": user})
    finally:
        db.close()



@app.get("/googledb33d1f4b0067f46.html", response_class=HTMLResponse)
async def google_verification(request: Request):
    return HTMLResponse(
        "google-site-verification: googledb33d1f4b0067f46.html",
        status_code=200,
    )


@app.get("/sitemap.xml", response_class=Response)
async def sitemap(request: Request):
    return Response(
        content='''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://pricegazer.com/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://pricegazer.com/competitor-price-tracking</loc><changefreq>monthly</changefreq><priority>0.9</priority></url>
  <url><loc>https://pricegazer.com/how-to-track-competitor-prices</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://pricegazer.com/vs-visualping</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://pricegazer.com/signup</loc><changefreq>yearly</changefreq><priority>0.7</priority></url>
  <url><loc>https://pricegazer.com/login</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>https://pricegazer.com/privacy</loc><changefreq>yearly</changefreq><priority>0.2</priority></url>
  <url><loc>https://pricegazer.com/terms</loc><changefreq>yearly</changefreq><priority>0.2</priority></url>
</urlset>''',
        media_type="application/xml",
        status_code=200,
    )


@app.get("/robots.txt", response_class=Response)
async def robots(request: Request):
    return Response(
        content="User-agent: *\nAllow: /\nSitemap: https://pricegazer.com/sitemap.xml\n",
        media_type="text/plain",
        status_code=200,
    )


# ----- Health Check -----

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
