import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urlunparse

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Text, Boolean, Float, DateTime, ForeignKey, Integer

from app.config import DATABASE_URL, REQUIRE_PAID_ACCOUNT
# The one table of default ports lives with the URL validator; duplicating it
# here would let the two drift apart.
from app.security import _DEFAULT_PORTS as DEFAULT_PORTS


# ----- Check interval bounds -----
#
# The scheduler multiplies this value by 3600 and compares it against elapsed
# time, so an unvalidated 0 means "re-fetch the target every single tick" and a
# negative one means the same. Clamp on the way in *and* on the way out.
MIN_CHECK_INTERVAL_HOURS = 1
MAX_CHECK_INTERVAL_HOURS = 168  # one week
DEFAULT_CHECK_INTERVAL_HOURS = 24


class InvalidIntervalError(ValueError):
    """Raised when a submitted check interval is outside the allowed range."""


def validate_check_interval_hours(value) -> int:
    """
    Parse and range-check a user-submitted interval. Raises InvalidIntervalError
    with a message meant to be shown in the form.
    """
    try:
        hours = int(value)
    except (TypeError, ValueError):
        raise InvalidIntervalError("Check interval must be a whole number of hours.")
    if hours < MIN_CHECK_INTERVAL_HOURS or hours > MAX_CHECK_INTERVAL_HOURS:
        raise InvalidIntervalError(
            f"Check interval must be between {MIN_CHECK_INTERVAL_HOURS} and "
            f"{MAX_CHECK_INTERVAL_HOURS} hours (got {hours})."
        )
    return hours


def clamp_check_interval_hours(value) -> int:
    """
    Read-time defence. Rows predating validation (or written by anything but the
    form) still have to produce a sane schedule rather than a hot loop.
    """
    try:
        hours = int(value)
    except (TypeError, ValueError):
        return DEFAULT_CHECK_INTERVAL_HOURS
    return max(MIN_CHECK_INTERVAL_HOURS, min(MAX_CHECK_INTERVAL_HOURS, hours))


# ----- Failure backoff -----
#
# A dead or hostile target used to be re-fetched every 15-minute tick forever.
# Each consecutive failure doubles the cooldown, and after enough of them the
# monitor auto-pauses and says so in the UI.
FAILURE_BACKOFF_BASE_HOURS = 1
FAILURE_BACKOFF_MAX_HOURS = 24
FAILURE_PAUSE_THRESHOLD = 5


def failure_cooldown_hours(consecutive_failures: int) -> float:
    """Hours to wait after `consecutive_failures` failures: 1, 2, 4, 8, 16, 24…"""
    if consecutive_failures <= 0:
        return 0.0
    return float(min(
        FAILURE_BACKOFF_BASE_HOURS * (2 ** (consecutive_failures - 1)),
        FAILURE_BACKOFF_MAX_HOURS,
    ))


# ----- Alert delivery retries -----
#
# A ChangeEvent is only marked `alerted` when the email actually went out, so a
# Resend blip (or a restart mid-send) leaves the row un-alerted. The monitor's
# cursor has already advanced by then, so the next check sees no change and the
# event is never revisited on its own — it has to be swept explicitly. These
# bounds keep that sweep from turning into a retry flood.
ALERT_RETRY_BASE_MINUTES = 5
ALERT_RETRY_MAX_MINUTES = 240
MAX_ALERT_ATTEMPTS = 6
# Past this age the news is stale enough that re-sending it is noise, not value.
ALERT_RETRY_WINDOW_HOURS = 72
# Per sweep, across all accounts. The sweep shares the 15-minute scheduler tick
# with the real checks, so it must not be able to monopolise it.
MAX_ALERT_RETRIES_PER_SWEEP = 50


def alert_retry_cooldown_minutes(attempts: int) -> float:
    """Minutes to wait after `attempts` failed sends: 5, 10, 20, 40, 80, 160…"""
    if attempts <= 0:
        return 0.0
    return float(min(
        ALERT_RETRY_BASE_MINUTES * (2 ** (attempts - 1)),
        ALERT_RETRY_MAX_MINUTES,
    ))


def pending_alert_events(db, now: datetime | None = None,
                         limit: int = MAX_ALERT_RETRIES_PER_SWEEP) -> list:
    """
    Un-alerted ChangeEvents that are due for another delivery attempt.

    Oldest first, so a backlog drains in the order the changes happened. Rows
    that are out of attempts or past the staleness window are excluded in SQL —
    `needs_alert_retry` re-checks each one anyway, but filtering here keeps a
    permanently-failing backlog from crowding out deliverable events.
    """
    from datetime import timedelta
    now = now or utcnow()
    limit = max(0, limit)
    if limit == 0:
        return []
    query = (
        db.query(ChangeEvent)
        .join(MonitoredUrl, ChangeEvent.url_id == MonitoredUrl.id)
        .join(User, MonitoredUrl.user_id == User.id)
        .filter(
            ChangeEvent.alerted == False,  # noqa: E712 — SQL comparison, not identity
            ChangeEvent.alert_attempts < MAX_ALERT_ATTEMPTS,
            ChangeEvent.detected_at > now - timedelta(hours=ALERT_RETRY_WINDOW_HOURS),
            # Cheapest possible backoff gate in SQL. The exact per-attempt
            # cooldown is exponential, so `needs_alert_retry` decides below;
            # this only stops the shortest cooldown from being loaded at all.
            (ChangeEvent.last_alert_attempt_at == None)  # noqa: E711
            | (ChangeEvent.last_alert_attempt_at
               <= now - timedelta(minutes=ALERT_RETRY_BASE_MINUTES)),
        )
    )
    if REQUIRE_PAID_ACCOUNT:
        # Same rule as the check sweep: a cancelled account gets no outbound work.
        query = query.filter(entitled_user_clause(now))
    # Over-fetch a bounded multiple so events still inside a longer exponential
    # cooldown can be dropped without an unbounded load of the whole backlog.
    candidates = (
        query.order_by(ChangeEvent.detected_at.asc(), ChangeEvent.id.asc())
        .limit(limit * 4)
        .all()
    )
    return [c for c in candidates if c.needs_alert_retry(now)][:limit]


def user_is_paid(user) -> bool:
    """
    The single paywall predicate. `is_active` on User is the paid flag, set only
    by the Stripe webhook (or by dev-mode signup when billing is unconfigured).

    A referred account is also entitled while its free first month is running —
    that window is stored as an absolute `trial_ends_at`, so it expires on its
    own rather than leaving a permanently free account behind.
    """
    if not REQUIRE_PAID_ACCOUNT:
        return True
    if user is None:
        return False
    return bool(user.is_active) or referral_trial_active(user)


def referral_trial_active(user, now: datetime | None = None) -> bool:
    """True while a referred account is inside the free month it signed up with."""
    ends_at = getattr(user, "trial_ends_at", None)
    if ends_at is None:
        return False
    return (now or utcnow()) < ends_at


def entitled_user_clause(now: datetime | None = None):
    """
    `user_is_paid` as a SQL predicate, for the sweeps that select across users.

    The two have to agree: a trial account the paywall lets in must also have its
    monitors checked and its alerts retried, or the free month buys nothing.
    """
    now = now or utcnow()
    return (User.is_active == True) | (User.trial_ends_at > now)  # noqa: E712


def utcnow() -> datetime:
    """
    The one datetime convention in this app: **naive UTC**.

    Every DateTime column below is naive (SQLite has no timezone type and drops
    the offset on write), so anything written to one has to be naive too —
    otherwise a value goes in aware, comes back naive, and the next subtraction
    against it raises TypeError. Read and write timestamps through this helper.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


# ----- Users -----

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)  # True after first payment
    max_urls: Mapped[int] = mapped_column(Integer, default=10)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # ----- Referrals -----
    #
    # `referral_code` is what this account hands out; it is nullable because
    # accounts predating the program are backfilled by the migration and new ones
    # get theirs on first use. `trial_ends_at` is the free month a referred
    # account signed up with — the paywall reads it, so it is the one field that
    # can entitle an account without `is_active`.
    referral_code: Mapped[str | None] = mapped_column(
        String(32), unique=True, index=True, nullable=True)
    referred_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), index=True, nullable=True)
    referral_credit_months: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0")
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    urls = relationship("MonitoredUrl", back_populates="user", cascade="all, delete-orphan")
    referred_by = relationship("User", remote_side=[id], foreign_keys=[referred_by_id])


# ----- Referral program -----
#
# "Give a friend a month free, get a month free." The friend's month is granted
# at signup as `trial_ends_at`, whether or not they pay that day. The referrer's
# month is *banked* (`referral_credit_months`) only once the friend actually
# pays, so handing out codes costs nothing until it earns something.
#
# Applying a banked month to the next Stripe invoice is deliberately not built:
# it needs subscription-schedule or coupon handling that this app has no other
# reason to carry. The balance is tracked and shown on /billing; spending it is
# future work.

REFERRAL_CODE_LEN = 8
# Crockford-style base32 — no I, L, O or U, so a code read off a screen and typed
# back in can't be ambiguous or spell anything.
REFERRAL_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
REFERRAL_CODE_ATTEMPTS = 10
REFERRAL_TRIAL_DAYS = 30


def generate_referral_code() -> str:
    """A fresh code. 32**8 ≈ 1.1e12, so collisions are rare and checked anyway."""
    return "".join(secrets.choice(REFERRAL_CODE_ALPHABET) for _ in range(REFERRAL_CODE_LEN))


def normalize_referral_code(code) -> str:
    """
    Fold a user-supplied code to storage form, or "" when it cannot be one.

    Case is folded because the codes are typed by hand, but nothing else is
    repaired: silently dropping stray characters could turn one account's typo
    into another account's valid code.
    """
    if not isinstance(code, str):
        return ""
    cleaned = code.strip().upper()
    if len(cleaned) != REFERRAL_CODE_LEN:
        return ""
    if any(c not in REFERRAL_CODE_ALPHABET for c in cleaned):
        return ""
    return cleaned


class ReferralRedemption(Base):
    """One row per account created with somebody's referral code."""

    __tablename__ = "referral_redemptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    referrer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    # Unique: an account is referred once, by one person, at signup.
    referred_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), unique=True, index=True)
    code: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Set the first time the referred account pays. Also the idempotence guard:
    # Stripe retries webhooks, and a replay must not bank a second month.
    credited_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


def ensure_referral_code(db, user) -> str:
    """
    The account's code, allocated and stored on first use. Callers commit.

    The pre-check makes a collision improbable; the savepoint makes it harmless
    if the unique index catches one anyway.
    """
    if user.referral_code:
        return user.referral_code
    for _ in range(REFERRAL_CODE_ATTEMPTS):
        code = generate_referral_code()
        if db.query(User.id).filter(User.referral_code == code).first() is not None:
            continue
        user.referral_code = code
        try:
            with db.begin_nested():
                db.flush()
            return code
        except IntegrityError:
            user.referral_code = None
    raise RuntimeError("could not allocate a unique referral code")


def resolve_referrer(db, code, email: str | None = None):
    """
    The account that owns `code` and may be credited for it, or None.

    Only a genuinely subscribed account (`is_active`) can refer. A trial account
    must not, or a referral chain would mint free months out of nothing: each
    free month would be enough to hand out the next one.
    """
    normalized = normalize_referral_code(code)
    if not normalized:
        return None
    referrer = db.query(User).filter(User.referral_code == normalized).first()
    if referrer is None or not referrer.is_active:
        return None
    if email and referrer.email == email:
        return None  # no referring yourself
    return referrer


def start_referral_trial(user, now: datetime | None = None) -> datetime:
    """Give `user` their free first month. Callers commit."""
    user.trial_ends_at = (now or utcnow()) + timedelta(days=REFERRAL_TRIAL_DAYS)
    return user.trial_ends_at


def record_referral(db, new_user, referrer, now: datetime | None = None):
    """
    Link a new account to its referrer and start its free month. Callers commit.

    `new_user` must already have an id — the redemption row points at it.
    """
    now = now or utcnow()
    new_user.referred_by_id = referrer.id
    start_referral_trial(new_user, now)
    redemption = ReferralRedemption(
        referrer_id=referrer.id,
        referred_user_id=new_user.id,
        code=referrer.referral_code,
        created_at=now,
    )
    db.add(redemption)
    db.flush()
    return redemption


def credit_referrer_for_payment(db, user, now: datetime | None = None) -> bool:
    """
    A referred account has paid: bank one free month for whoever referred it.

    Returns whether a credit was applied. Safe to call on every payment event —
    an already-credited or never-referred account is a no-op. Callers commit.
    """
    redemption = (
        db.query(ReferralRedemption)
        .filter(ReferralRedemption.referred_user_id == user.id,
                ReferralRedemption.credited_at == None)  # noqa: E711
        .first()
    )
    if redemption is None:
        return False
    referrer = db.query(User).filter(User.id == redemption.referrer_id).first()
    if referrer is None:
        return False
    referrer.referral_credit_months = (referrer.referral_credit_months or 0) + 1
    redemption.credited_at = now or utcnow()
    db.flush()
    return True


def referral_stats(db, user) -> dict:
    """Counts behind the referral panel: who signed up, and who went on to pay."""
    rows = (
        db.query(ReferralRedemption)
        .filter(ReferralRedemption.referrer_id == user.id)
        .all()
    )
    return {
        "signups": len(rows),
        "converted": sum(1 for r in rows if r.credited_at is not None),
        "credit_months": user.referral_credit_months or 0,
    }


# ----- Monitored URLs -----

class MonitoredUrl(Base):
    __tablename__ = "monitored_urls"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    label: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(2048))
    check_interval_hours: Mapped[int] = mapped_column(Integer, default=DEFAULT_CHECK_INTERVAL_HOURS)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_content: Mapped[str | None] = mapped_column(Text, nullable=True)  # stored stripped text for diff
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    paused_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user = relationship("User", back_populates="urls")
    changes = relationship("ChangeEvent", back_populates="url", cascade="all, delete-orphan")

    # ----- Scheduling -----

    @property
    def effective_interval_hours(self) -> int:
        """The interval the scheduler is allowed to act on, clamped at read time."""
        return clamp_check_interval_hours(self.check_interval_hours)

    def cooldown_until(self) -> datetime | None:
        """When this monitor may next be retried after failures, or None."""
        failures = self.consecutive_failures or 0
        if failures <= 0 or self.last_failure_at is None:
            return None
        from datetime import timedelta
        return self.last_failure_at + timedelta(hours=failure_cooldown_hours(failures))

    def is_in_failure_cooldown(self, now: datetime | None = None) -> bool:
        until = self.cooldown_until()
        if until is None:
            return False
        return (now or utcnow()) < until

    def is_due(self, now: datetime | None = None) -> bool:
        """
        True when the scheduler should fetch this URL right now.

        Both gates live here so the due-check logic and the backoff can't drift
        apart: the interval must have elapsed *and* the failure cooldown must
        have expired.
        """
        now = now or utcnow()
        if not self.is_active:
            return False
        if self.is_in_failure_cooldown(now):
            return False
        if self.last_checked_at is None:
            return True
        elapsed = (now - self.last_checked_at).total_seconds()
        return elapsed >= self.effective_interval_hours * 3600 * 0.9  # 90% threshold

    # ----- Failure bookkeeping -----

    def record_failure(self, error: str, now: datetime | None = None) -> None:
        """Count a failed fetch, and auto-pause once the target has had enough."""
        now = now or utcnow()
        self.consecutive_failures = (self.consecutive_failures or 0) + 1
        self.last_failure_at = now
        self.last_error = (error or "Check failed")[:255]
        if self.consecutive_failures >= FAILURE_PAUSE_THRESHOLD and self.is_active:
            self.is_active = False
            self.paused_reason = (
                f"Auto-paused after {self.consecutive_failures} consecutive failed "
                f"checks ({self.last_error}). Resume to try again."
            )[:255]

    def record_success(self) -> None:
        """A good fetch clears the backoff state."""
        self.consecutive_failures = 0
        self.last_failure_at = None
        self.last_error = None
        self.paused_reason = None


# ----- Failure state that outlives the row -----
#
# The backoff and the auto-pause both live on the MonitoredUrl row, so deleting
# the row threw them away: delete + re-add gave a paused-for-24h monitor a clean
# counter *and* another immediate first fetch, on repeat. Failure state is
# therefore parked here on delete, keyed on (user, URL), and handed back to the
# replacement row on re-add.
#
# Each parked row is consumed when it is read back, and one is written only for
# a monitor that actually has failures, so this cannot grow per add/delete
# cycle. The per-user cap bounds what is left: a user cycling many *distinct*
# failing URLs keeps only the most recent entries.
MAX_BACKOFF_MEMORY_PER_USER = 50


def backoff_key(url: str) -> str:
    """
    Identity of a URL for backoff purposes: same target, same cooldown.

    Scheme and host are case-insensitive per RFC 3986 and the default port is
    redundant, so those are normalized away — otherwise `HTTPS://Host/x` and
    `https://host:443/x` would each get a fresh retry budget. Path and query are
    left exactly as given; they are case-sensitive and meaningful.
    """
    parsed = urlparse((url or "").strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    netloc = f"[{host}]" if ":" in host else host
    port = None
    try:
        port = parsed.port
    except ValueError:  # malformed port — keep it in the key rather than guess
        netloc = parsed.netloc.lower()
    if port is not None and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{netloc}:{port}"
    return urlunparse((scheme, netloc, parsed.path, parsed.params,
                       parsed.query, ""))[:2048]


class UrlBackoff(Base):
    """Parked failure state for a deleted monitor, awaiting a re-add."""

    __tablename__ = "url_backoff"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    url_key: Mapped[str] = mapped_column(String(2048), index=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_failure_at: Mapped[datetime] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    def cooldown_until(self) -> datetime:
        """When the parked state stops being worth enforcing."""
        from datetime import timedelta
        return self.last_failure_at + timedelta(
            hours=failure_cooldown_hours(self.consecutive_failures or 0))

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.cooldown_until()


def remember_failure_state(db, monitored, now: datetime | None = None) -> bool:
    """
    Park `monitored`'s failure state so a re-add inherits it. Callers commit.

    A monitor with no failures — or one whose cooldown has already run out — has
    nothing worth remembering, so nothing is written and any older entry for the
    same target is cleared.
    """
    now = now or utcnow()
    key = backoff_key(monitored.url)
    existing = (
        db.query(UrlBackoff)
        .filter(UrlBackoff.user_id == monitored.user_id, UrlBackoff.url_key == key)
        .first()
    )
    failures = monitored.consecutive_failures or 0
    live = (failures > 0 and monitored.last_failure_at is not None
            and monitored.is_in_failure_cooldown(now))
    if not live:
        if existing is not None:
            db.delete(existing)
        return False

    if existing is None:
        existing = UrlBackoff(user_id=monitored.user_id, url_key=key)
        db.add(existing)
    existing.consecutive_failures = failures
    existing.last_failure_at = monitored.last_failure_at
    existing.last_error = monitored.last_error
    existing.updated_at = now
    db.flush()
    _prune_backoff_memory(db, monitored.user_id, now)
    return True


def recall_failure_state(db, user_id: int, url: str, now: datetime | None = None):
    """
    Pop the parked failure state for (`user_id`, `url`), if it is still live.

    Reading consumes the entry: from here on the state lives on the new
    MonitoredUrl row, and a later delete parks it again. That keeps a monitor
    that has since succeeded from being re-seeded with stale failures.
    Expired entries are dropped rather than returned. Callers commit.
    """
    now = now or utcnow()
    key = backoff_key(url)
    entry = (
        db.query(UrlBackoff)
        .filter(UrlBackoff.user_id == user_id, UrlBackoff.url_key == key)
        .first()
    )
    if entry is None:
        return None
    failures, last_failure_at, last_error = (
        entry.consecutive_failures, entry.last_failure_at, entry.last_error)
    expired = entry.is_expired(now)
    db.delete(entry)
    if expired:
        return None
    return (failures, last_failure_at, last_error)


def _prune_backoff_memory(db, user_id: int, now: datetime | None = None) -> int:
    """Drop expired entries for a user, then all but the newest N. Callers commit."""
    now = now or utcnow()
    entries = (
        db.query(UrlBackoff)
        .filter(UrlBackoff.user_id == user_id)
        .order_by(UrlBackoff.updated_at.desc(), UrlBackoff.id.desc())
        .all()
    )
    stale = [e for e in entries if e.is_expired(now)]
    keep = [e for e in entries if not e.is_expired(now)]
    for entry in stale + keep[MAX_BACKOFF_MEMORY_PER_USER:]:
        db.delete(entry)
    return len(stale) + max(0, len(keep) - MAX_BACKOFF_MEMORY_PER_USER)


# ----- Change Events -----

class ChangeEvent(Base):
    __tablename__ = "change_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("monitored_urls.id"))
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    old_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    new_hash: Mapped[str] = mapped_column(String(64))
    old_content: Mapped[str | None] = mapped_column(Text, nullable=True)  # snapshot before change
    new_content: Mapped[str | None] = mapped_column(Text, nullable=True)   # snapshot after change
    diff_summary: Mapped[str | None] = mapped_column(Text, nullable=True)  # human-readable summary
    alerted: Mapped[bool] = mapped_column(Boolean, default=False)
    alert_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_alert_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    url = relationship("MonitoredUrl", back_populates="changes")

    # ----- Alert delivery bookkeeping -----

    def mark_alerted(self, now: datetime | None = None) -> None:
        """The send succeeded: stop retrying this event."""
        self.alerted = True
        self.alert_attempts = (self.alert_attempts or 0) + 1
        self.last_alert_attempt_at = now or utcnow()

    def record_alert_attempt(self, now: datetime | None = None) -> None:
        """The send failed: count it so the retry sweep can back off and give up."""
        self.alert_attempts = (self.alert_attempts or 0) + 1
        self.last_alert_attempt_at = now or utcnow()

    def alert_retry_ready_at(self) -> datetime | None:
        """When this event may next be re-sent, or None if it never has been tried."""
        if self.last_alert_attempt_at is None:
            return None
        from datetime import timedelta
        return self.last_alert_attempt_at + timedelta(
            minutes=alert_retry_cooldown_minutes(self.alert_attempts or 0)
        )

    def alert_gave_up(self, now: datetime | None = None) -> bool:
        """True once this event is out of attempts or too old to be worth sending."""
        if self.alerted:
            return False
        if (self.alert_attempts or 0) >= MAX_ALERT_ATTEMPTS:
            return True
        return self.alert_is_stale(now)

    def alert_is_stale(self, now: datetime | None = None) -> bool:
        """True when the change is older than we are still willing to alert about."""
        from datetime import timedelta
        detected = self.detected_at or utcnow()
        return (now or utcnow()) - detected > timedelta(hours=ALERT_RETRY_WINDOW_HOURS)

    def needs_alert_retry(self, now: datetime | None = None) -> bool:
        """True when the retry sweep should attempt this event right now."""
        now = now or utcnow()
        if self.alerted or self.alert_gave_up(now):
            return False
        ready = self.alert_retry_ready_at()
        return ready is None or now >= ready


# ----- Stored history cap -----
#
# Every detected change stores two full page snapshots. Unbounded, a target that
# changes on every check (or a user hammering "Check now") writes megabytes per
# monitor until the disk fills. Keep a useful window and drop the rest.
MAX_CHANGE_EVENTS_PER_URL = 100


def prune_change_events(db, url_id: int, keep: int = MAX_CHANGE_EVENTS_PER_URL) -> int:
    """
    Delete all but the `keep` most recent ChangeEvents for `url_id`.

    Ordered by (detected_at, id) descending so ties inside the same second still
    have a total order — otherwise a prune could drop the row just inserted.
    Returns how many rows were deleted. Callers commit.
    """
    if keep < 0:
        keep = 0
    stale = (
        db.query(ChangeEvent.id)
        .filter(ChangeEvent.url_id == url_id)
        .order_by(ChangeEvent.detected_at.desc(), ChangeEvent.id.desc())
        .offset(keep)
        .all()
    )
    ids = [row[0] for row in stale]
    if not ids:
        return 0
    db.query(ChangeEvent).filter(ChangeEvent.id.in_(ids)).delete(synchronize_session="fetch")
    return len(ids)


# ----- Database Setup -----

def get_engine():
    return create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


# Columns added after the first release. SQLite has no ALTER TABLE ... IF NOT
# EXISTS, so each one is added only when the live table is missing it.
_ADDED_COLUMNS = {
    "monitored_urls": {
        "consecutive_failures": "INTEGER NOT NULL DEFAULT 0",
        "last_failure_at": "DATETIME",
        "last_error": "VARCHAR(255)",
        "paused_reason": "VARCHAR(255)",
    },
    "users": {
        "is_active": "BOOLEAN NOT NULL DEFAULT 0",
        "referral_code": "VARCHAR(32)",
        "referred_by_id": "INTEGER REFERENCES users(id)",
        "referral_credit_months": "INTEGER NOT NULL DEFAULT 0",
        "trial_ends_at": "DATETIME",
    },
    "change_events": {
        "alert_attempts": "INTEGER NOT NULL DEFAULT 0",
        "last_alert_attempt_at": "DATETIME",
    },
}


def migrate_schema(engine) -> list[str]:
    """
    Bring an existing database up to the current schema. Returns what it did.

    Existing rows keep whatever paid state they already had; when billing is not
    configured (local dev) `user_is_paid` treats everyone as paid anyway, so a
    dev database keeps working untouched.
    """
    applied = []
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table, columns in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue
            present = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name in present:
                    continue
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                applied.append(f"{table}.{name}")
        if "users" in existing_tables:
            applied.extend(_backfill_referral_codes(conn))
    return applied


def _backfill_referral_codes(conn) -> list[str]:
    """
    Give every pre-referral account a code, then make the column unique.

    `ALTER TABLE ADD COLUMN` cannot carry a UNIQUE constraint in SQLite, so the
    index is created here instead — after the backfill, so it can never fail on
    rows this function just wrote. Raw SQL because this runs inside the migration
    transaction, before the ORM is used against the new columns.
    """
    rows = conn.execute(text(
        "SELECT id FROM users WHERE referral_code IS NULL OR referral_code = ''"
    )).fetchall()
    taken = {
        row[0] for row in conn.execute(text(
            "SELECT referral_code FROM users WHERE referral_code IS NOT NULL"
        )).fetchall() if row[0]
    }
    for (user_id,) in rows:
        code = generate_referral_code()
        while code in taken:
            code = generate_referral_code()
        taken.add(code)
        conn.execute(text("UPDATE users SET referral_code = :code WHERE id = :id"),
                     {"code": code, "id": user_id})
    conn.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_referral_code ON users (referral_code)"
    ))
    return [f"users.referral_code (backfilled {len(rows)})"] if rows else []


def init_db(engine=None):
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(engine)
    added = migrate_schema(engine)
    if added:
        print(f"[DB] Added missing columns: {', '.join(added)}")
    return engine


def get_session(engine=None):
    if engine is None:
        engine = get_engine()
    from sqlalchemy.orm import Session
    return Session(engine)
