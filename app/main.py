"""
Competitor Monitor — FastAPI Web Application
"""

import os
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import hashlib, secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"

def _verify_password(password: str, stored: str) -> bool:
    salt, h = stored.split(":", 1)
    return hashlib.sha256((salt + password).encode()).hexdigest() == h

from app.config import SECRET_KEY, APP_URL, STRIPE_PRICE_ID
from app.models import (
    Base, User, MonitoredUrl, ChangeEvent,
    get_engine, get_session, init_db,
)
from app.monitor import check_url
from app.alerts import send_change_alert, send_welcome_email

# ----- App Setup -----

engine = get_engine()

templates = Jinja2Templates(directory="app/templates")

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: init DB and start scheduler
    init_db(engine)
    _start_scheduler()
    yield
    # Shutdown
    _stop_scheduler()


app = FastAPI(title="Competitor Monitor", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ----- Background Scheduler -----

_scheduler = None

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
        )
        _scheduler.start()
        print("[SCHEDULER] Started — checking eligible URLs every 15 minutes")
    except Exception as e:
        print(f"[SCHEDULER] Failed to start: {e}")

def _stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        print("[SCHEDULER] Stopped")


async def run_scheduled_checks():
    """Check all active URLs whose interval has elapsed."""
    db = get_session(engine)
    try:
        now = datetime.now(timezone.utc)
        urls = db.query(MonitoredUrl).filter(MonitoredUrl.is_active == True).all()
        checked = 0
        for monitored in urls:
            # Skip if not enough time has passed
            if monitored.last_checked_at:
                elapsed = (now - monitored.last_checked_at).total_seconds()
                if elapsed < monitored.check_interval_hours * 3600 * 0.9:  # 90% threshold
                    continue

            result = await check_url(
                monitored.url,
                monitored.last_hash,
                monitored.last_content,
            )

            if result.get("error"):
                print(f"[CHECK] {monitored.label}: {result['error']}")
                continue

            monitored.last_hash = result["new_hash"]
            monitored.last_content = result["new_content"]
            monitored.last_checked_at = now

            if result.get("changed"):
                change = ChangeEvent(
                    url_id=monitored.id,
                    old_hash=monitored.last_hash,
                    new_hash=result["new_hash"],
                    old_content=monitored.last_content,
                    new_content=result["new_content"],
                    diff_summary=result.get("diff_summary"),
                )
                db.add(change)
                db.flush()

                # Send alert
                user = monitored.user
                if user:
                    await send_change_alert(
                        to_email=user.email,
                        url_label=monitored.label,
                        url=monitored.url,
                        diff_summary=result.get("diff_summary", "Content changed"),
                        pricing_changes=result.get("pricing_changes", ""),
                    )
                change.alerted = True
                print(f"[ALERT] {monitored.label}: Change detected, alert sent to {user.email if user else 'unknown'}")

            checked += 1

        db.commit()
        if checked > 0:
            print(f"[CHECK] Checked {checked} URL(s)")
    except Exception as e:
        print(f"[CHECK] Error during scheduled check: {e}")
    finally:
        db.close()


# ----- Helper: require auth -----

async def require_user(request: Request, db: Session = Depends(lambda: get_session(engine))):
    user = get_user_from_request(request, db)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


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


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request, "user": None})


@app.post("/signup")
async def signup(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    db = get_session(engine)
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            return templates.TemplateResponse("signup.html", {
                "request": request, "user": None,
                "error": "Email already registered",
            })

        user = User(
            email=email,
            password_hash=_hash_password(password),
            is_active=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Create Stripe Checkout Session
        checkout_url = await _create_stripe_checkout(user)

        # Log user in
        token = make_token(user.id)
        response = RedirectResponse(checkout_url, status_code=303)
        response.set_cookie("token", token, max_age=86400 * 30, httponly=True, secure=False)
        return response
    finally:
        db.close()


async def _create_stripe_checkout(user: User) -> str:
    """Create a Stripe Checkout Session. Returns the checkout URL."""
    if not STRIPE_PRICE_ID:
        # Dev mode — skip Stripe, activate user directly
        db = get_session(engine)
        try:
            u = db.query(User).filter(User.id == user.id).first()
            u.is_active = True
            db.commit()
        finally:
            db.close()
        return f"{APP_URL}/dashboard"

    import stripe
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

    session = stripe.checkout.Session.create(
        customer_email=user.email,
        payment_method_types=["card"],
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        mode="subscription",
        success_url=f"{APP_URL}/dashboard?welcome=1",
        cancel_url=f"{APP_URL}/signup",
        metadata={"user_id": str(user.id)},
    )
    return session.url


@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events (subscription created, updated, cancelled)."""
    import stripe
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400)

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_id = session.get("metadata", {}).get("user_id")
        if user_id:
            db = get_session(engine)
            try:
                user = db.query(User).filter(User.id == int(user_id)).first()
                if user:
                    user.stripe_customer_id = session.get("customer")
                    user.stripe_subscription_id = session.get("subscription")
                    user.is_active = True
                    db.commit()
                    # Send welcome email
                    await send_welcome_email(user.email)
            finally:
                db.close()

    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        customer_id = subscription.get("customer")
        if customer_id:
            db = get_session(engine)
            try:
                user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
                if user:
                    user.is_active = False
                    user.stripe_subscription_id = None
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
):
    db = get_session(engine)
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not _verify_password(password, user.password_hash):
            return templates.TemplateResponse("login.html", {
                "request": request, "user": None,
                "error": "Invalid email or password",
            })

        if not user.is_active:
            return templates.TemplateResponse("login.html", {
                "request": request, "user": None,
                "error": "Account not activated. Please complete payment.",
            })

        token = make_token(user.id)
        response = RedirectResponse("/dashboard", status_code=303)
        response.set_cookie("token", token, max_age=86400 * 30, httponly=True, secure=False)
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
        return templates.TemplateResponse("dashboard.html", {
            "request": request, "user": user, "urls": urls,
        })
    finally:
        db.close()


@app.get("/urls/new", response_class=HTMLResponse)
async def add_url_page(request: Request):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)
        return templates.TemplateResponse("add_url.html", {"request": request, "user": user})
    finally:
        db.close()


@app.post("/urls/new")
async def add_url(
    request: Request,
    label: str = Form(...),
    url: str = Form(...),
    check_interval_hours: int = Form(24),
):
    db = get_session(engine)
    try:
        user = get_user_from_request(request, db)
        if not user:
            return RedirectResponse("/login", status_code=303)

        url_count = db.query(MonitoredUrl).filter(MonitoredUrl.user_id == user.id).count()
        if url_count >= user.max_urls:
            return templates.TemplateResponse("add_url.html", {
                "request": request, "user": user,
                "error": f"Max {user.max_urls} URLs reached. Upgrade to monitor more.",
            })

        monitored = MonitoredUrl(
            user_id=user.id,
            label=label,
            url=url,
            check_interval_hours=check_interval_hours,
        )
        db.add(monitored)
        db.commit()

        # Do an immediate first check
        result = await check_url(url, None, None)
        if result.get("new_hash") and not result.get("error"):
            monitored.last_hash = result["new_hash"]
            monitored.last_content = result["new_content"]
            monitored.last_checked_at = datetime.now(timezone.utc)
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
            "request": request, "user": user,
            "url": monitored, "changes": changes,
        })
    finally:
        db.close()


@app.get("/urls/{url_id}/check")
async def check_now(request: Request, url_id: int):
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

        result = await check_url(
            monitored.url,
            monitored.last_hash,
            monitored.last_content,
        )

        now = datetime.now(timezone.utc)
        monitored.last_hash = result.get("new_hash", monitored.last_hash)
        monitored.last_content = result.get("new_content", monitored.last_content)
        monitored.last_checked_at = now

        if result.get("changed"):
            change = ChangeEvent(
                url_id=monitored.id,
                old_hash=monitored.last_hash,
                new_hash=result["new_hash"],
                old_content=monitored.last_content,
                new_content=result["new_content"],
                diff_summary=result.get("diff_summary"),
            )
            db.add(change)
            db.flush()
            await send_change_alert(
                to_email=user.email,
                url_label=monitored.label,
                url=monitored.url,
                diff_summary=result.get("diff_summary", "Content changed"),
                pricing_changes=result.get("pricing_changes", ""),
            )
            change.alerted = True

        db.commit()

        # Redirect back to detail page
        return RedirectResponse(f"/urls/{url_id}", status_code=303)
    finally:
        db.close()


@app.get("/urls/{url_id}/toggle")
async def toggle_url(request: Request, url_id: int):
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

        monitored.is_active = not monitored.is_active
        db.commit()
        return RedirectResponse("/dashboard", status_code=303)
    finally:
        db.close()


@app.get("/urls/{url_id}/delete")
async def delete_url(request: Request, url_id: int):
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


# ----- Health Check -----

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
