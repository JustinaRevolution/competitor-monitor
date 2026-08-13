"""
Verification for the ninth-round review fix.

Run from the repo root:  python3 tests/test_round9.py

Covers:
  F1  Un-alerted ChangeEvents are actually retried. A send that fails leaves
      `alerted=False`, but the monitor's cursor has already advanced, so the
      next check sees no change and nothing ever revisits the row. The alert
      retry sweep at the top of run_scheduled_checks is what closes that gap,
      and it has to stay bounded: exponential backoff between attempts, a cap
      on total attempts, a staleness window, a per-sweep ceiling, and no
      outbound work at all for an unpaid account.
"""

import asyncio
import os
import sys
import tempfile
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)
# A configured Stripe price turns the paywall on. Nothing here talks to Stripe.
os.environ["STRIPE_PRICE_ID"] = "price_test_round9"
os.environ["STRIPE_SECRET_KEY"] = "sk_test_dummy"

from sqlalchemy import create_engine, text  # noqa: E402

import app.main as main  # noqa: E402
from app.models import (  # noqa: E402
    ALERT_RETRY_BASE_MINUTES, ALERT_RETRY_WINDOW_HOURS, Base, ChangeEvent,
    MAX_ALERT_ATTEMPTS, MAX_ALERT_RETRIES_PER_SWEEP, MonitoredUrl, User,
    alert_retry_cooldown_minutes, get_session, init_db, pending_alert_events,
    utcnow,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ------------------------------------------------------------------ fixtures

_tmpfiles = []


def fresh_db(paid=True):
    """A throwaway database with one account and one already-checked monitor."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = get_session(engine)
    user = User(email=f"r9-{len(_tmpfiles)}@test.local", password_hash="x", is_active=paid)
    db.add(user)
    db.flush()
    monitored = MonitoredUrl(
        user_id=user.id, label="Acme pricing", url="https://example.com/pricing",
        # Freshly checked, so the sweep's check loop has nothing to do and any
        # outbound fetch during these tests is a bug.
        last_checked_at=utcnow(), last_hash="NEW", last_content="new",
    )
    db.add(monitored)
    db.commit()
    ids = (user.id, monitored.id)
    db.close()
    return engine, ids


def add_pending_change(engine, url_id, *, detected_at=None, attempts=0,
                       last_attempt_at=None, diff_summary="Price: $10 -> $8"):
    """An un-alerted ChangeEvent, exactly as a failed send leaves one."""
    db = get_session(engine)
    change = ChangeEvent(
        url_id=url_id, old_hash="OLD", new_hash="NEW",
        old_content="old", new_content="new", diff_summary=diff_summary,
        detected_at=detected_at or utcnow(), alerted=False,
        alert_attempts=attempts, last_alert_attempt_at=last_attempt_at,
    )
    db.add(change)
    db.commit()
    change_id = change.id
    db.close()
    return change_id


class Recorder:
    """Stands in for send_change_alert, recording every call."""

    def __init__(self, succeed=True):
        self.succeed = succeed
        self.calls = []

    async def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if self.succeed == "raise":
            raise RuntimeError("resend is down")
        return bool(self.succeed)


class FetchSpy:
    """Stands in for check_url; any call means the sweep fetched a page."""

    def __init__(self):
        self.calls = 0

    async def __call__(self, url, previous_hash, previous_content):
        self.calls += 1
        return {"changed": False, "new_hash": previous_hash,
                "new_content": previous_content, "error": None}


def run_sweep(engine, sender, fetcher=None):
    """Run one scheduled sweep with the email and fetch layers stubbed."""
    fetcher = fetcher or FetchSpy()
    real = (main.engine, main.send_change_alert, main.check_url)
    main.engine, main.send_change_alert, main.check_url = engine, sender, fetcher
    try:
        asyncio.run(main.run_scheduled_checks())
    finally:
        main.engine, main.send_change_alert, main.check_url = real
    return fetcher


def load_change(engine, change_id):
    db = get_session(engine)
    try:
        return db.query(ChangeEvent).filter(ChangeEvent.id == change_id).one()
    finally:
        db.close()


# ------------------------------------------- (F1a) the retry actually happens

def test_failed_alert_is_retried_on_the_next_sweep():
    print("\n[F1a] A change whose email failed is re-sent by a later sweep")
    engine, (user_id, url_id) = fresh_db()

    # The send fails, exactly as a Resend blip leaves it.
    failing = Recorder(succeed=False)
    change_id = add_pending_change(engine, url_id)
    run_sweep(engine, failing)

    change = load_change(engine, change_id)
    check("the failed send left the event un-alerted", change.alerted is False)
    check("the failed send counted an attempt", change.alert_attempts == 1,
          str(change.alert_attempts))
    check("the failed send recorded when it was tried",
          change.last_alert_attempt_at is not None)

    # Backoff has expired; the page itself has not changed again, so nothing but
    # the retry sweep can possibly deliver this.
    db = get_session(engine)
    row = db.query(ChangeEvent).filter(ChangeEvent.id == change_id).one()
    row.last_alert_attempt_at = utcnow() - timedelta(minutes=ALERT_RETRY_BASE_MINUTES + 1)
    db.commit()
    db.close()

    working = Recorder(succeed=True)
    spy = run_sweep(engine, working)

    change = load_change(engine, change_id)
    check("the retry sweep re-sent the alert", len(working.calls) == 1,
          f"{len(working.calls)} send(s)")
    check("the event is now marked alerted", change.alerted is True)
    check("the retry did not refetch the page", spy.calls == 0, f"{spy.calls} fetch(es)")
    if working.calls:
        sent = working.calls[0]
        check("the retry used the stored diff summary",
              sent["diff_summary"] == "Price: $10 -> $8", repr(sent["diff_summary"]))
        check("the retry went to the monitor's owner",
              sent["to_email"].startswith("r9-"), sent["to_email"])
        check("the retry carried the label", sent["url_label"] == "Acme pricing")

    # An alerted event is never sent twice.
    again = Recorder(succeed=True)
    run_sweep(engine, again)
    check("a delivered alert is not re-sent", len(again.calls) == 0,
          f"{len(again.calls)} send(s)")


# ---------------------------------------------------- (F1b) a raising send too

def test_a_raising_send_is_retried():
    print("\n[F1b] A send that raises is queued for retry, not lost")
    engine, (user_id, url_id) = fresh_db()
    change_id = add_pending_change(engine, url_id)

    run_sweep(engine, Recorder(succeed="raise"))
    change = load_change(engine, change_id)
    check("an exception left the event un-alerted", change.alerted is False)
    check("an exception counted an attempt", change.alert_attempts == 1,
          str(change.alert_attempts))

    db = get_session(engine)
    row = db.query(ChangeEvent).filter(ChangeEvent.id == change_id).one()
    row.last_alert_attempt_at = utcnow() - timedelta(hours=6)
    db.commit()
    db.close()

    working = Recorder(succeed=True)
    run_sweep(engine, working)
    check("the next sweep delivered it", len(working.calls) == 1, f"{len(working.calls)}")
    check("and marked it alerted", load_change(engine, change_id).alerted is True)


# ------------------------------------------------------ (F1c) bounded backoff

def test_retry_backoff_is_exponential():
    print("\n[F1c] Retries back off instead of hammering every 15 minutes")
    check("cooldown after 0 attempts is 0", alert_retry_cooldown_minutes(0) == 0.0)
    check("cooldown doubles: 5, 10, 20, 40",
          [alert_retry_cooldown_minutes(n) for n in (1, 2, 3, 4)] == [5.0, 10.0, 20.0, 40.0],
          str([alert_retry_cooldown_minutes(n) for n in (1, 2, 3, 4)]))
    check("cooldown is capped", alert_retry_cooldown_minutes(50) == 240.0,
          str(alert_retry_cooldown_minutes(50)))

    engine, (user_id, url_id) = fresh_db()
    # One failed attempt a minute ago: still inside the 5-minute cooldown.
    change_id = add_pending_change(engine, url_id, attempts=1,
                                   last_attempt_at=utcnow() - timedelta(minutes=1))
    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check("a sweep inside the cooldown sends nothing", len(sender.calls) == 0,
          f"{len(sender.calls)} send(s)")
    check("the attempt count did not move",
          load_change(engine, change_id).alert_attempts == 1)

    # Two attempts, last one 11 minutes ago: past the 10-minute cooldown.
    engine, (user_id, url_id) = fresh_db()
    add_pending_change(engine, url_id, attempts=2,
                       last_attempt_at=utcnow() - timedelta(minutes=11))
    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check("a sweep past the cooldown does send", len(sender.calls) == 1,
          f"{len(sender.calls)} send(s)")


# ------------------------------------------------------- (F1d) it gives up

def test_retries_stop_after_the_attempt_cap():
    print("\n[F1d] Retries stop after the attempt cap, so a bad address is not looped forever")
    engine, (user_id, url_id) = fresh_db()
    change_id = add_pending_change(engine, url_id, attempts=MAX_ALERT_ATTEMPTS,
                                   last_attempt_at=utcnow() - timedelta(days=1))
    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check("an event out of attempts is not retried", len(sender.calls) == 0,
          f"{len(sender.calls)} send(s)")
    check("it reports itself as given up",
          load_change(engine, change_id).alert_gave_up() is True)

    # And a real run of failures walks itself up to the cap rather than looping.
    engine, (user_id, url_id) = fresh_db()
    change_id = add_pending_change(engine, url_id)
    failing = Recorder(succeed=False)
    for _ in range(MAX_ALERT_ATTEMPTS + 3):
        db = get_session(engine)
        row = db.query(ChangeEvent).filter(ChangeEvent.id == change_id).one()
        if row.last_alert_attempt_at is not None:
            # Fast-forward past whatever cooldown the last failure earned.
            row.last_alert_attempt_at = utcnow() - timedelta(days=1)
            db.commit()
        db.close()
        run_sweep(engine, failing)
    check(f"failures stop at the cap of {MAX_ALERT_ATTEMPTS}",
          len(failing.calls) == MAX_ALERT_ATTEMPTS, f"{len(failing.calls)} send(s)")
    check("the event is left un-alerted and given up",
          load_change(engine, change_id).alerted is False
          and load_change(engine, change_id).alert_gave_up() is True)


# ---------------------------------------------------- (F1e) staleness window

def test_stale_changes_are_not_resent():
    print("\n[F1e] A change older than the retry window is not re-sent as fresh news")
    engine, (user_id, url_id) = fresh_db()
    change_id = add_pending_change(
        engine, url_id,
        detected_at=utcnow() - timedelta(hours=ALERT_RETRY_WINDOW_HOURS + 1),
    )
    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check("a stale change is not retried", len(sender.calls) == 0,
          f"{len(sender.calls)} send(s)")
    check("it reports itself as given up",
          load_change(engine, change_id).alert_gave_up() is True)

    # Just inside the window it is still delivered.
    engine, (user_id, url_id) = fresh_db()
    add_pending_change(
        engine, url_id,
        detected_at=utcnow() - timedelta(hours=ALERT_RETRY_WINDOW_HOURS - 1),
    )
    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check("a change inside the window is retried", len(sender.calls) == 1,
          f"{len(sender.calls)} send(s)")


# ------------------------------------------------------ (F1f) paywall + bound

def test_unpaid_accounts_get_no_retries():
    print("\n[F1f] The retry sweep does no outbound work for an unpaid account")
    engine, (user_id, url_id) = fresh_db(paid=False)
    add_pending_change(engine, url_id)
    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check("an unpaid account's pending alert is not sent", len(sender.calls) == 0,
          f"{len(sender.calls)} send(s)")

    # Paying re-enables it.
    db = get_session(engine)
    db.query(User).filter(User.id == user_id).one().is_active = True
    db.commit()
    db.close()
    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check("once paid, the pending alert is delivered", len(sender.calls) == 1,
          f"{len(sender.calls)} send(s)")


def test_one_sweep_cannot_flood():
    print("\n[F1g] A large backlog is drained in bounded batches")
    engine, (user_id, url_id) = fresh_db()
    backlog = MAX_ALERT_RETRIES_PER_SWEEP + 20
    db = get_session(engine)
    base = utcnow() - timedelta(hours=1)
    for n in range(backlog):
        db.add(ChangeEvent(url_id=url_id, old_hash="OLD", new_hash=f"H{n}",
                           diff_summary=f"change {n}", alerted=False,
                           detected_at=base + timedelta(seconds=n)))
    db.commit()
    db.close()

    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check(f"one sweep sends at most {MAX_ALERT_RETRIES_PER_SWEEP}",
          len(sender.calls) == MAX_ALERT_RETRIES_PER_SWEEP, f"{len(sender.calls)} send(s)")
    check("the oldest changes go first",
          sender.calls[0]["diff_summary"] == "change 0", sender.calls[0]["diff_summary"])

    # The rest are not dropped — the next sweep picks them up.
    sender = Recorder(succeed=True)
    run_sweep(engine, sender)
    check("the next sweep drains the remainder",
          len(sender.calls) == backlog - MAX_ALERT_RETRIES_PER_SWEEP,
          f"{len(sender.calls)} send(s)")

    db = get_session(engine)
    left = db.query(ChangeEvent).filter(ChangeEvent.alerted == False).count()  # noqa: E712
    db.close()
    check("nothing is left un-alerted", left == 0, f"{left} pending")


# ------------------------------------------------------- (F1h) query helper

def test_pending_alert_events_ignores_delivered_rows():
    print("\n[F1h] pending_alert_events selects only what still needs sending")
    engine, (user_id, url_id) = fresh_db()
    add_pending_change(engine, url_id)
    db = get_session(engine)
    db.add(ChangeEvent(url_id=url_id, new_hash="DONE", alerted=True,
                       detected_at=utcnow()))
    db.commit()
    pending = pending_alert_events(db)
    check("only the un-alerted row is pending", len(pending) == 1, str(len(pending)))
    check("and it is the right one", bool(pending) and pending[0].alerted is False)
    check("a zero limit returns nothing", pending_alert_events(db, limit=0) == [])
    db.close()


# ----------------------------------------------------------- (F1i) migration

def test_legacy_change_events_table_is_migrated():
    print("\n[F1i] A database predating the retry columns is migrated in place")
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE change_events ("
            " id INTEGER NOT NULL PRIMARY KEY, url_id INTEGER NOT NULL,"
            " detected_at DATETIME, old_hash VARCHAR(64), new_hash VARCHAR(64),"
            " old_content TEXT, new_content TEXT, diff_summary TEXT,"
            " alerted BOOLEAN)"
        ))
        conn.execute(text(
            "INSERT INTO change_events (id, url_id, detected_at, new_hash, alerted)"
            " VALUES (1, 1, '2026-01-01 00:00:00', 'H', 0)"
        ))
    init_db(engine)
    db = get_session(engine)
    row = db.query(ChangeEvent).filter(ChangeEvent.id == 1).one()
    check("the legacy row survived", row.new_hash == "H")
    check("alert_attempts backfilled to 0", row.alert_attempts == 0, str(row.alert_attempts))
    check("last_alert_attempt_at defaults to NULL", row.last_alert_attempt_at is None)
    check("a backfilled row is retryable once it is recent enough",
          row.needs_alert_retry(row.detected_at + timedelta(hours=1)) is True)
    db.close()
    init_db(engine)  # idempotent
    check("re-running the migration is a no-op", True)


# ---------------------------------------------------------- (F1j) it is visible

def test_detail_page_shows_undelivered_alerts():
    print("\n[F1j] The detail page distinguishes sent, retrying, and failed alerts")
    from fastapi.testclient import TestClient

    engine, (user_id, url_id) = fresh_db()
    add_pending_change(engine, url_id, diff_summary="still queued")
    add_pending_change(engine, url_id, attempts=MAX_ALERT_ATTEMPTS,
                       last_attempt_at=utcnow(), diff_summary="given up")
    db = get_session(engine)
    db.add(ChangeEvent(url_id=url_id, new_hash="DONE", alerted=True,
                       diff_summary="delivered", detected_at=utcnow()))
    db.commit()
    db.close()

    real_engine = main.engine
    main.engine = engine
    try:
        client = TestClient(main.app)
        client.__enter__()
        client.get("/login")
        client.cookies.set("token", main.make_token(user_id))
        r = client.get(f"/urls/{url_id}")
        check("the detail page renders", r.status_code == 200, str(r.status_code))
        check("a delivered change says so", "Alert sent" in r.text)
        check("a queued change says it is retrying", "Alert retrying" in r.text)
        check("an abandoned change says it failed", "Alert failed" in r.text)
        client.__exit__(None, None, None)
    finally:
        main.engine = real_engine


if __name__ == "__main__":
    try:
        test_failed_alert_is_retried_on_the_next_sweep()
        test_a_raising_send_is_retried()
        test_retry_backoff_is_exponential()
        test_retries_stop_after_the_attempt_cap()
        test_stale_changes_are_not_resent()
        test_unpaid_accounts_get_no_retries()
        test_one_sweep_cannot_flood()
        test_pending_alert_events_ignores_delivered_rows()
        test_legacy_change_events_table_is_migrated()
        test_detail_page_shows_undelivered_alerts()
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
