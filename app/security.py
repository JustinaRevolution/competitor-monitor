"""
Security primitives: SSRF-safe URL validation, CSRF tokens, per-IP rate limiting.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import re
import secrets
import socket
import time
from collections import OrderedDict
from typing import Optional
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import SECRET_KEY, COOKIE_SECURE, COOKIE_SAMESITE, TRUST_PROXY_HEADERS

# ----- SSRF-safe URL validation -----

ALLOWED_SCHEMES = ("http", "https")
MAX_REDIRECTS = 5

# Only the two ports a public web page is actually served on. Allowing arbitrary
# ports turned this server into a port scanner pointed at third parties: the
# difference between a connection refused, a TLS error and a timeout is an
# observable oracle, and it is our IP doing the knocking. Checked before the DNS
# lookup, and — since every redirect hop is re-validated — on each hop too.
ALLOWED_PORTS = {80, 443}
_DEFAULT_PORTS = {"http": 80, "https": 443}


class UnsafeUrlError(ValueError):
    """Raised when a URL is not safe to fetch (bad scheme or internal address)."""


def _ip_is_disallowed(ip: ipaddress._BaseAddress) -> bool:
    """Reject anything that is not a routable public address."""
    # Unwrap IPv4-mapped/compatible IPv6 (::ffff:127.0.0.1 etc.) before judging.
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or getattr(ip, "sixtofour", None)
        if mapped is not None:
            ip = mapped
    return (
        not ip.is_global       # the real test: anything not publicly routable
        or ip.is_private       # RFC1918, 127.0.0.0/8, ::1, fc00::/7
        or ip.is_loopback
        or ip.is_link_local    # 169.254.0.0/16, fe80::/10
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve(host: str) -> list:
    """Resolve a hostname to every address it maps to. Raises UnsafeUrlError on failure."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeUrlError(f"Could not resolve host '{host}'") from e
    addrs = []
    for info in infos:
        try:
            addrs.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not addrs:
        raise UnsafeUrlError(f"Could not resolve host '{host}'")
    return addrs


def validate_and_pin(url: str) -> ipaddress._BaseAddress:
    """
    Validate that `url` is an http(s) URL pointing at a public address, and
    return the single IP address a fetch of it must connect to.

    The caller must connect to *this* address rather than letting the HTTP
    client resolve the hostname again: a second lookup reopens the DNS-rebinding
    window, where a name resolves public here and private at connect time.
    """
    if not url or len(url) > 2048:
        raise UnsafeUrlError("URL is missing or too long")

    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeUrlError("Only http:// and https:// URLs are allowed")

    host = parsed.hostname
    if not host:
        raise UnsafeUrlError("URL has no hostname")

    # Before any DNS work: a non-web port is never something we fetch.
    try:
        port = parsed.port
    except ValueError as e:  # non-numeric or out-of-range port in the URL
        raise UnsafeUrlError("URL has an invalid port") from e
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    if port not in ALLOWED_PORTS:
        raise UnsafeUrlError(f"Port {port} is not allowed — only 80 and 443 may be fetched")

    # A literal IP still has to be public.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _ip_is_disallowed(literal):
            raise UnsafeUrlError("URL points at a private or reserved address")
        return literal

    # Every address the name maps to has to be public — a round-robin record
    # with one private entry is still an attack.
    addrs = _resolve(host)
    for addr in addrs:
        if _ip_is_disallowed(addr):
            raise UnsafeUrlError(f"'{host}' resolves to a private or reserved address")
    return addrs[0]


def validate_url(url: str) -> str:
    """Validate `url`, returning it unchanged. Raises UnsafeUrlError otherwise."""
    validate_and_pin(url)
    return url


async def validate_url_async(url: str) -> str:
    """Async wrapper — DNS resolution is blocking, so keep it off the event loop."""
    return await asyncio.to_thread(validate_url, url)


async def validate_and_pin_async(url: str) -> ipaddress._BaseAddress:
    """Async wrapper — DNS resolution is blocking, so keep it off the event loop."""
    return await asyncio.to_thread(validate_and_pin, url)


# ----- User-supplied text -----

# `String(255)` is documentation, not a constraint: SQLite stores whatever it is
# given, so every one of these columns is unbounded at the database. The limit
# has to live here, at the edge, or an unauthenticated signup writes rows the
# size of the request body nginx will accept (10 MB) and nothing ever prunes
# them. Lengths are the real-world ones: RFC 5321 caps an address at 254.
MAX_EMAIL_LEN = 254
MIN_PASSWORD_LEN = 8
# bcrypt only reads the first 72 bytes; the rest is just something to hash and
# store. Refuse the novel rather than silently truncating it.
MAX_PASSWORD_LEN = 1024
MAX_LABEL_LEN = 200

# Deliberately loose — this rejects the shapes that are never an address, and
# leaves deciding whether mail is deliverable to the mail server.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")

# CR/LF are the header-injection characters; the rest are control characters
# with no business in a label or a subject line.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class InvalidInputError(ValueError):
    """Raised when submitted text is missing, malformed, or over its limit."""


def normalize_email(email: str) -> str:
    """Trimmed address, or `InvalidInputError` if it is too long or malformed."""
    email = (email or "").strip()
    if not email:
        raise InvalidInputError("Email address is required")
    if len(email) > MAX_EMAIL_LEN:
        raise InvalidInputError(
            f"Email address must be at most {MAX_EMAIL_LEN} characters"
        )
    if not _EMAIL_RE.match(email):
        raise InvalidInputError("Enter a valid email address")
    return email


def validate_password(password: str) -> str:
    """The password unchanged, or `InvalidInputError` if it is not usable."""
    if password is None:
        raise InvalidInputError("Password is required")
    if len(password) < MIN_PASSWORD_LEN:
        raise InvalidInputError(
            f"Password must be at least {MIN_PASSWORD_LEN} characters"
        )
    if len(password) > MAX_PASSWORD_LEN:
        raise InvalidInputError(
            f"Password must be at most {MAX_PASSWORD_LEN} characters"
        )
    return password


def normalize_label(label: str) -> str:
    """
    Trimmed, control-character-free label, or `InvalidInputError` past the limit.

    Truncating instead of rejecting would silently rename the user's monitor, so
    an over-long label is a form error. Control characters are stripped rather
    than rejected because the reason they matter is downstream: the label is
    interpolated into the alert email's Subject, where a newline is a header
    injection attempt.
    """
    label = _CONTROL_RE.sub(" ", (label or "")).strip()
    if not label:
        raise InvalidInputError("Label is required")
    if len(label) > MAX_LABEL_LEN:
        raise InvalidInputError(f"Label must be at most {MAX_LABEL_LEN} characters")
    return label


def header_safe(value: str, limit: int = MAX_LABEL_LEN) -> str:
    """
    A string that cannot break out of a mail header: no CR/LF, bounded length.

    Applied at send time as well as at input time, because rows written before
    `normalize_label` existed are still in the database.
    """
    return _CONTROL_RE.sub(" ", (value or ""))[:limit]


# ----- CSRF -----

CSRF_COOKIE = "csrf"
CSRF_FIELD = "csrf_token"
CSRF_MAX_AGE = 86400 * 7
# A server-issued secret is `token_urlsafe(32)` — 43 characters. Anything
# shorter did not come from us, so it is not accepted as one half of the pair.
CSRF_SECRET_MIN_LEN = 32
AUTH_COOKIE = "token"

_csrf_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="csrf")


def new_csrf_secret() -> str:
    """A fresh per-browser CSRF secret."""
    return secrets.token_urlsafe(32)


def csrf_secret_is_valid(secret) -> bool:
    """True only for a value shaped like a secret this server issued."""
    return isinstance(secret, str) and len(secret) >= CSRF_SECRET_MIN_LEN


def csrf_binding_for_auth(auth_cookie: str) -> str:
    """
    Fingerprint of the login session a CSRF token belongs to.

    A hash of the auth cookie, never the cookie itself: an itsdangerous token is
    *signed, not encrypted*, so its payload is readable by anyone who can see the
    rendered form. Embedding the session token there would hand it out in HTML.
    """
    if not auth_cookie:
        return "anon"
    return hashlib.sha256(auth_cookie.encode("utf-8")).hexdigest()[:32]


def csrf_session_binding(request: Request) -> str:
    return csrf_binding_for_auth(request.cookies.get(AUTH_COOKIE, ""))


def mint_csrf_token(secret: str, binding: str) -> str:
    """Sign the (cookie secret, session) pair a form token has to reproduce."""
    return _csrf_serializer.dumps({"s": secret, "b": binding})


def csrf_token(request: Request) -> str:
    """
    Signed token bound to *both* the per-browser CSRF cookie and the login
    session it was rendered for. Used as a Jinja global.

    Binding to the cookie alone left the token session-independent: one minted
    before login (or for the previous account on a shared browser) stayed valid
    for seven days afterwards, so a token captured from an anonymous page could
    be replayed against the authenticated one. The auth cookie is re-issued on
    every login, which retires every token minted for the old session.
    """
    secret = getattr(request.state, "csrf_secret", None) or request.cookies.get(CSRF_COOKIE, "")
    if not csrf_secret_is_valid(secret):
        # Never mint over a secret we did not issue — a token signed over ""
        # would otherwise pair with an empty/garbage cookie.
        secret = ""
    return mint_csrf_token(secret, csrf_session_binding(request))


def verify_csrf(request: Request, token: Optional[str]) -> None:
    """
    Raise 403 unless `token` is our signature over this browser's CSRF cookie
    *and* over the session making the request.
    """
    cookie_secret = request.cookies.get(CSRF_COOKIE, "")
    if not token or not csrf_secret_is_valid(cookie_secret):
        raise HTTPException(status_code=403, detail="CSRF token missing")
    try:
        payload = _csrf_serializer.loads(token, max_age=CSRF_MAX_AGE)
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=403, detail="CSRF token invalid or expired")

    # Old-format tokens were a bare signed string with no session half. Reject
    # them outright rather than falling back to the weaker check.
    if not isinstance(payload, dict):
        raise HTTPException(status_code=403, detail="CSRF token invalid or expired")
    signed_secret = payload.get("s")
    signed_binding = payload.get("b")
    if not isinstance(signed_secret, str) or not isinstance(signed_binding, str):
        raise HTTPException(status_code=403, detail="CSRF token invalid or expired")

    if not hmac.compare_digest(signed_secret, cookie_secret):
        raise HTTPException(status_code=403, detail="CSRF token mismatch")
    if not hmac.compare_digest(signed_binding, csrf_session_binding(request)):
        raise HTTPException(status_code=403, detail="CSRF token is not valid for this session")


def set_csrf_cookie(response, secret: str) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        secret,
        max_age=CSRF_MAX_AGE,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )


# ----- Rate limiting -----

def client_ip(request: Request) -> str:
    """
    Best-effort client IP. Behind nginx (`proxy_add_x_forwarded_for`) the
    rightmost X-Forwarded-For entry is the one the proxy appended, so it is the
    only one a client cannot spoof.
    """
    if TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[-1].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else "unknown"


class TokenBucket:
    """
    Tiny in-memory per-key token bucket. Single-process only, which matches how
    this app is deployed (one uvicorn worker); it degrades to "no limit across
    workers" rather than failing if that ever changes.
    """

    def __init__(self, capacity: int, refill_seconds: float, max_keys: int = 10_000):
        self.capacity = capacity
        self.refill_rate = capacity / refill_seconds
        self.max_keys = max_keys
        self._buckets: "OrderedDict[str, tuple]" = OrderedDict()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (float(self.capacity), now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill_rate)
        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            self._buckets.move_to_end(key)
            return False
        self._buckets[key] = (tokens - 1.0, now)
        self._buckets.move_to_end(key)
        while len(self._buckets) > self.max_keys:
            self._buckets.popitem(last=False)
        return True


# 5 attempts, refilling over 5 minutes — enough for humans, painful for guessers.
login_limiter = TokenBucket(capacity=5, refill_seconds=300)
signup_limiter = TokenBucket(capacity=3, refill_seconds=3600)
# Adding a URL also makes the server fetch it immediately, so it needs the same
# per-account ceiling "check now" has — an IP-only limit is a limit on nothing
# for one authenticated user rotating addresses.
add_url_limiter = TokenBucket(capacity=20, refill_seconds=3600)
add_url_user_limiter = TokenBucket(capacity=20, refill_seconds=3600)

# "Check now" makes the server fetch an arbitrary page, so it is the cheapest
# request to turn into an outbound flood. Limit it by IP *and* by account —
# one authenticated user rotating IPs otherwise gets an unbounded budget.
check_now_limiter = TokenBucket(capacity=10, refill_seconds=300)
check_now_user_limiter = TokenBucket(capacity=10, refill_seconds=300)


def enforce_rate_limit(request: Request, limiter: TokenBucket, what: str) -> None:
    if not limiter.allow(f"{what}:{client_ip(request)}"):
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait a few minutes and try again.",
            headers={"Retry-After": "300"},
        )


def enforce_user_rate_limit(user_id: int, limiter: TokenBucket, what: str) -> None:
    """Same as `enforce_rate_limit` but keyed on the account, not the source IP."""
    if not limiter.allow(f"{what}:user:{user_id}"):
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait a few minutes and try again.",
            headers={"Retry-After": "300"},
        )
