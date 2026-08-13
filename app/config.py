import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# production | development. Controls cookie hardening and startup strictness.
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"

_INSECURE_SECRET_KEYS = {
    "",
    "dev-secret-change-in-production",
    "generate-a-random-secret-key-here",
    "changeme",
}

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
if SECRET_KEY in _INSECURE_SECRET_KEYS:
    raise RuntimeError(
        "SECRET_KEY is unset or still the placeholder value. Generate one with:\n"
        "  python3 -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "and set it in your .env before starting the app."
    )
if len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be at least 32 characters.")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///data/monitor.db")
APP_URL = os.getenv("APP_URL", "http://localhost:8000")

# Stripe
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()

if IS_PRODUCTION and STRIPE_SECRET_KEY and not STRIPE_PRICE_ID:
    raise RuntimeError(
        "STRIPE_PRICE_ID is empty but STRIPE_SECRET_KEY is set, so billing is "
        "expected in production. With no price ID the signup flow silently skips "
        "Stripe and activates every account for free. Set it in your .env."
    )

if IS_PRODUCTION and STRIPE_PRICE_ID and not STRIPE_WEBHOOK_SECRET:
    raise RuntimeError(
        "STRIPE_WEBHOOK_SECRET is empty but Stripe billing is enabled in production. "
        "Without it, webhook signatures cannot be verified and anyone could activate "
        "accounts by POSTing to /stripe-webhook. Set it in your .env."
    )

# ----- Paywall -----
# Monitoring is a paid feature: an account may only add URLs or trigger fetches
# once it has an active subscription. Billing counts as configured when a Stripe
# price ID is set — with no price ID (local dev) there is no way to pay, so every
# account is treated as paid and the app stays usable without Stripe.
BILLING_ENABLED = bool(STRIPE_PRICE_ID)

# Explicit escape hatch for a production deploy that genuinely wants to run
# without billing. It has to be opt-in: silently giving away paid features is
# exactly the bug this flag exists to make impossible by accident.
ALLOW_FREE_ACCESS = os.getenv("ALLOW_FREE_ACCESS", "").strip().lower() in ("1", "true", "yes")

# The gate the app actually checks. False = everyone is treated as paid.
REQUIRE_PAID_ACCOUNT = BILLING_ENABLED and not ALLOW_FREE_ACCESS

if IS_PRODUCTION and not BILLING_ENABLED and not ALLOW_FREE_ACCESS:
    raise RuntimeError(
        "Running in production with no STRIPE_PRICE_ID means nobody can pay and "
        "every signup would get the paid features for free. Set STRIPE_PRICE_ID, "
        "or set ALLOW_FREE_ACCESS=true if you really mean to run this free."
    )

# Email (Resend)
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
FROM_EMAIL = os.getenv("FROM_EMAIL", "alerts@pricegazer.com")

# Alerting is the product. With no key, `_send_email` falls back to printing the
# message and reporting success, which makes `_deliver_change_alert` mark the
# change alerted and commit it — and nothing revisits an alerted row. A deploy
# that skipped this prompt would look completely healthy while never sending a
# single alert, with no queue left to replay once anyone noticed.
if IS_PRODUCTION and not RESEND_API_KEY:
    raise RuntimeError(
        "RESEND_API_KEY is empty in production. Alert delivery would silently "
        "report success and mark every change as alerted, losing it forever. "
        "Get a key at resend.com and set it in your .env."
    )

# Cookies — HTTPS-only in production, always httponly + explicit SameSite.
COOKIE_SECURE = IS_PRODUCTION
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").strip().lower()
if COOKIE_SAMESITE not in ("lax", "strict", "none"):
    raise RuntimeError("COOKIE_SAMESITE must be one of: lax, strict, none")

# The deploy script puts nginx in front and sets X-Forwarded-For, so trust it in
# production. Override explicitly if the app is exposed directly.
TRUST_PROXY_HEADERS = os.getenv(
    "TRUST_PROXY_HEADERS", "true" if IS_PRODUCTION else "false"
).strip().lower() in ("1", "true", "yes")

# ----- Outbound fetches -----
# httpx's `timeout` is per-I/O-operation, not per-fetch: a server that trickles
# one byte at a time resets the read clock on every chunk, and a redirect chain
# pays it once per hop. Either one holds a fetch open far past the number below.
# This is the *total* wall-clock budget for one fetch — DNS validation, every
# redirect hop and the body read included — enforced with an outer deadline.
# It matters beyond the one monitor: the scheduled sweep checks URLs one after
# another, so an unbounded fetch on a single account stalls alerting for every
# other customer in the same sweep.
try:
    FETCH_TIMEOUT_SECONDS = float(os.getenv("FETCH_TIMEOUT_SECONDS", "30").strip() or 30)
except ValueError:
    raise RuntimeError("FETCH_TIMEOUT_SECONDS must be a number of seconds.")
if not 1 <= FETCH_TIMEOUT_SECONDS <= 300:
    raise RuntimeError("FETCH_TIMEOUT_SECONDS must be between 1 and 300 seconds.")

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
