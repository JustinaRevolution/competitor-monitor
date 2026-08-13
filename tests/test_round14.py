"""
Verification for the round-14 fixes.

Run from the repo root:  python3 tests/test_round14.py

Finding 1 — delete + re-add reset the failure backoff and the auto-pause.
Both lived only on the MonitoredUrl row, so POST /urls/{id}/delete followed by
POST /urls/new with the same URL produced a row with consecutive_failures=0 and
an immediate first fetch. A monitor auto-paused for 24h against a dead or
hostile target could therefore be fetched ~20x/hour forever. Failure state is
now parked in `url_backoff` on delete and inherited on re-add.

Finding 2 — the `max_urls` check was racy across an await. `validate_url_async`
resolves DNS on a worker thread, so the event loop was free between the count
and the insert: concurrent adds from one account each read the same count and
all inserted, doubling the per-account monitor ceiling.

Finding 6 — a monitored URL containing control characters was printed raw to
journald, letting a stored URL forge log lines.
"""

import asyncio
import os
import sys
import tempfile
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

import app.main as main  # noqa: E402
import app.monitor as monitor  # noqa: E402
import app.security as security  # noqa: E402
from app.models import (  # noqa: E402
    Base, MonitoredUrl, UrlBackoff, User,
    FAILURE_PAUSE_THRESHOLD, MAX_BACKOFF_MEMORY_PER_USER,
    backoff_key, get_session, remember_failure_state, utcnow,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ------------------------------------------------------------------ fixtures

_tmpfiles = []

TARGET = "https://example.com/p0"


def fresh_db(paid: bool = True, max_urls: int = 10):
    """A throwaway database with one paid account and no monitors."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    _tmpfiles.append(tmp.name)
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = get_session(engine)
    user = User(email=f"r14-{len(_tmpfiles)}@test.local", password_hash="x",
                is_active=paid, max_urls=max_urls)
    db.add(user)
    db.commit()
    user_id = user.id
    db.close()
    return engine, user_id


def add_monitor(engine, user_id, url=TARGET, failures=0, failed_ago_hours=0.0,
                is_active=True):
    """Insert a monitor, optionally already deep in its failure backoff."""
    db = get_session(engine)
    # A marker hash the replacement row cannot have: SQLite reuses the freed
    # rowid, so this is what tells the two rows apart.
    monitored = MonitoredUrl(user_id=user_id, label="Target", url=url,
                             is_active=is_active, last_hash="seed-hash",
                             last_checked_at=utcnow() - timedelta(hours=1))
    if failures:
        monitored.consecutive_failures = failures
        monitored.last_failure_at = utcnow() - timedelta(hours=failed_ago_hours)
        monitored.last_error = "Connection refused"
    db.add(monitored)
    db.commit()
    url_id = monitored.id
    db.close()
    return url_id


class FakeCheck:
    """Stand-in for check_url that records how many fetches were attempted."""

    def __init__(self, result=None):
        self.result = result or {"changed": False, "new_hash": "h",
                                 "new_content": "c", "error": None}
        self.calls = 0

    async def __call__(self, url, previous_hash, previous_content):
        self.calls += 1
        return dict(self.result)


async def _fake_validate(url):
    return url


def csrf_for(client):
    secret = client.cookies.get(security.CSRF_COOKIE)
    auth = client.cookies.get("token")
    return security.mint_csrf_token(secret, security.csrf_binding_for_auth(auth or ""))


def client_for(engine, user_id=None):
    main.engine = engine
    client = TestClient(main.app)
    client.__enter__()
    client.get("/login")  # seeds the CSRF cookie via the middleware
    if user_id is not None:
        client.cookies.set("token", main.make_token(user_id))
    return client, csrf_for(client)


def roomy_limiters():
    saved = (main.check_now_limiter, main.check_now_user_limiter,
             main.add_url_limiter, main.add_url_user_limiter, main.login_limiter)
    main.check_now_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.check_now_user_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.add_url_limiter = security.TokenBucket(capacity=10_000, refill_seconds=3600)
    main.add_url_user_limiter = security.TokenBucket(capacity=10_000, refill_seconds=3600)
    main.login_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    return saved


def restore_limiters(saved):
    (main.check_now_limiter, main.check_now_user_limiter,
     main.add_url_limiter, main.add_url_user_limiter, main.login_limiter) = saved


def monitors_for(engine, user_id):
    db = get_session(engine)
    rows = db.query(MonitoredUrl).filter(MonitoredUrl.user_id == user_id).all()
    db.expunge_all()
    db.close()
    return rows


def parked_for(engine, user_id):
    db = get_session(engine)
    rows = db.query(UrlBackoff).filter(UrlBackoff.user_id == user_id).all()
    db.expunge_all()
    db.close()
    return rows


def delete_and_readd(client, token, url_id, url=TARGET):
    """The exploit: drop the paused monitor, add the same target straight back."""
    r1 = client.post(f"/urls/{url_id}/delete", data={"csrf_token": token},
                     follow_redirects=False)
    r2 = client.post("/urls/new", data={
        "label": "Target", "url": url, "check_interval_hours": "24",
        "csrf_token": token,
    }, follow_redirects=False)
    return r1, r2


# ------------------------------------- (F1) backoff survives delete + re-add

def test_readd_inherits_the_cooldown():
    print("\n[F1] Re-adding a deleted, auto-paused monitor inherits its backoff")
    engine, user_id = fresh_db()
    # 5 failures, the newest a minute ago: a 24h cooldown with 23h59m left.
    url_id = add_monitor(engine, user_id, failures=FAILURE_PAUSE_THRESHOLD,
                         failed_ago_hours=1 / 60, is_active=False)
    fake = FakeCheck()
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        r1, r2 = delete_and_readd(client, token, url_id)
        check("the delete and the re-add both succeed",
              (r1.status_code, r2.status_code) == (303, 303),
              f"{r1.status_code}, {r2.status_code}")

        rows = monitors_for(engine, user_id)
        check("exactly one monitor exists again", len(rows) == 1, str(len(rows)))
        fresh = rows[0]
        # SQLite hands out the freed rowid again, so identity is checked by
        # content: this row was inserted by the re-add, not carried over.
        check("it is a new row, not the deleted one",
              fresh.last_hash is None and fresh.last_checked_at is None,
              f"hash={fresh.last_hash}, checked={fresh.last_checked_at}")
        check("the failure count carried over",
              fresh.consecutive_failures == FAILURE_PAUSE_THRESHOLD,
              str(fresh.consecutive_failures))
        check("the last-failure timestamp carried over",
              fresh.last_failure_at is not None
              and (utcnow() - fresh.last_failure_at).total_seconds() < 300,
              str(fresh.last_failure_at))
        check("the auto-pause stuck", fresh.is_active is False, str(fresh.is_active))
        check("the pause says why", bool(fresh.paused_reason), str(fresh.paused_reason))
        check("it is still inside the failure cooldown",
              fresh.is_in_failure_cooldown() is True)
        check("the scheduler will not fetch it", fresh.is_due() is False)
        check("NO immediate fetch was bought by the delete/re-add",
              fake.calls == 0, f"{fake.calls} fetches")
        check("the parked state was consumed, not left behind",
              len(parked_for(engine, user_id)) == 0)
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


def test_readd_loop_stays_bounded():
    print("\n[F1] Repeating the delete/re-add cycle never buys another fetch")
    engine, user_id = fresh_db()
    url_id = add_monitor(engine, user_id, failures=FAILURE_PAUSE_THRESHOLD,
                         failed_ago_hours=1 / 60, is_active=False)
    fake = FakeCheck()
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        for _ in range(10):
            _, r2 = delete_and_readd(client, token, url_id)
            url_id = monitors_for(engine, user_id)[0].id
            if r2.status_code != 303:
                break
        check("ten delete/re-add cycles produced zero fetches",
              fake.calls == 0, f"{fake.calls} fetches")
        rows = monitors_for(engine, user_id)
        check("the failure count is still at the pause threshold",
              rows[0].consecutive_failures == FAILURE_PAUSE_THRESHOLD,
              str(rows[0].consecutive_failures))
        check("only one parked entry at most is kept per target",
              len(parked_for(engine, user_id)) <= 1)
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


def test_readd_normalizes_the_url():
    print("\n[F1] Case and the default port don't buy a fresh retry budget")
    engine, user_id = fresh_db()
    url_id = add_monitor(engine, user_id, failures=3, failed_ago_hours=1 / 60)
    fake = FakeCheck()
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        _, r2 = delete_and_readd(client, token, url_id,
                                 url="HTTPS://EXAMPLE.COM:443/p0")
        check("the re-add with a different spelling succeeds",
              r2.status_code == 303, str(r2.status_code))
        rows = monitors_for(engine, user_id)
        check("the failure count still carried over",
              rows[0].consecutive_failures == 3, str(rows[0].consecutive_failures))
        check("no fetch was bought", fake.calls == 0, str(fake.calls))
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)

    check("backoff_key folds scheme case, host case and the default port",
          backoff_key("HTTPS://EXAMPLE.COM:443/p0") == backoff_key(TARGET),
          backoff_key("HTTPS://EXAMPLE.COM:443/p0"))
    check("backoff_key keeps a non-default port distinct",
          backoff_key("http://example.com:8080/p0") != backoff_key("http://example.com/p0"))
    check("backoff_key keeps the path case-sensitive",
          backoff_key("https://example.com/P0") != backoff_key(TARGET))
    check("backoff_key drops the fragment but keeps the query",
          backoff_key("https://example.com/p0?a=1#frag") == "https://example.com/p0?a=1",
          backoff_key("https://example.com/p0?a=1#frag"))


def test_expired_cooldown_is_not_inherited():
    print("\n[F1] An expired cooldown is not held against a re-add")
    engine, user_id = fresh_db()
    # One failure = a 1h cooldown, and it failed 3h ago: nothing left to serve.
    url_id = add_monitor(engine, user_id, failures=1, failed_ago_hours=3)
    fake = FakeCheck()
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        delete_and_readd(client, token, url_id)
        rows = monitors_for(engine, user_id)
        check("the replacement starts clean", rows[0].consecutive_failures == 0,
              str(rows[0].consecutive_failures))
        check("the first check ran normally", fake.calls == 1, str(fake.calls))
        check("nothing stale was parked", len(parked_for(engine, user_id)) == 0)
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


def test_healthy_delete_readd_is_unaffected():
    print("\n[F1] Deleting and re-adding a healthy monitor still works normally")
    engine, user_id = fresh_db()
    url_id = add_monitor(engine, user_id)
    fake = FakeCheck()
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        _, r2 = delete_and_readd(client, token, url_id)
        check("the re-add succeeds", r2.status_code == 303, str(r2.status_code))
        rows = monitors_for(engine, user_id)
        check("the new monitor is active", rows[0].is_active is True)
        check("its first check ran", fake.calls == 1, str(fake.calls))
        check("nothing was parked for a healthy monitor",
              len(parked_for(engine, user_id)) == 0)
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


def test_success_clears_inherited_state():
    print("\n[F1] A monitor that recovers doesn't drag old failures forever")
    engine, user_id = fresh_db()
    url_id = add_monitor(engine, user_id, failures=2, failed_ago_hours=1 / 60)
    fake = FakeCheck()
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.check_url, main.validate_url_async = fake, _fake_validate
    try:
        client, token = client_for(engine, user_id)
        delete_and_readd(client, token, url_id)  # inherits 2 failures
        db = get_session(engine)
        row = db.query(MonitoredUrl).filter(MonitoredUrl.user_id == user_id).first()
        check("the re-add inherited the failures", row.consecutive_failures == 2,
              str(row.consecutive_failures))
        row.record_success()  # as a successful check would
        db.commit()
        new_id = row.id
        db.close()

        _, r2 = delete_and_readd(client, token, new_id)
        check("the second re-add succeeds", r2.status_code == 303, str(r2.status_code))
        rows = monitors_for(engine, user_id)
        check("the recovered monitor comes back clean",
              rows[0].consecutive_failures == 0, str(rows[0].consecutive_failures))
        check("and gets its normal first check", fake.calls == 1, str(fake.calls))
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


def test_parked_state_is_capped_per_user():
    print("\n[F1] Parked failure state can't grow without bound")
    engine, user_id = fresh_db()
    db = get_session(engine)
    n = MAX_BACKOFF_MEMORY_PER_USER + 20
    for i in range(n):
        monitored = MonitoredUrl(user_id=user_id, label=f"T{i}",
                                 url=f"https://example.com/target-{i}")
        monitored.consecutive_failures = FAILURE_PAUSE_THRESHOLD
        monitored.last_failure_at = utcnow()
        monitored.last_error = "Connection refused"
        db.add(monitored)
        db.flush()
        remember_failure_state(db, monitored)
    db.commit()
    kept = db.query(UrlBackoff).filter(UrlBackoff.user_id == user_id).count()
    db.close()
    check(f"parked entries are capped at {MAX_BACKOFF_MEMORY_PER_USER}",
          kept <= MAX_BACKOFF_MEMORY_PER_USER, f"{kept} of {n} written")
    check("the cap still keeps a useful window", kept == MAX_BACKOFF_MEMORY_PER_USER,
          str(kept))


# ------------------------------------------------- (F2) the max_urls race

def _post_add(engine, user_id, label, url, token, cookies):
    """One POST /urls/new over ASGI, so several can be in flight at once."""
    async def run():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://testserver",
                                     cookies=cookies) as ac:
            return await ac.post("/urls/new", data={
                "label": label, "url": url, "check_interval_hours": "24",
                "csrf_token": token,
            }, follow_redirects=False)
    return run()


def test_max_urls_is_not_racy():
    print("\n[F2] Concurrent adds cannot overshoot max_urls")
    engine, user_id = fresh_db(max_urls=3)
    fake = FakeCheck()
    real = (main.engine, main.check_url, main.validate_url_async)
    saved = roomy_limiters()
    main.engine = engine
    main.check_url = fake

    async def slow_validate(url):
        # What the real one does to the loop: DNS runs on a worker thread, so
        # the loop is free to start every other queued add in the meantime.
        await asyncio.sleep(0.05)
        return url

    main.validate_url_async = slow_validate
    try:
        client, token = client_for(engine, user_id)
        cookies = dict(client.cookies)

        async def burst():
            return await asyncio.gather(*[
                _post_add(engine, user_id, f"T{i}", f"https://example.com/race-{i}",
                          token, cookies)
                for i in range(8)
            ])

        responses = asyncio.run(burst())
        codes = sorted(r.status_code for r in responses)
        stored = len(monitors_for(engine, user_id))
        check("the account is left at exactly its max_urls ceiling",
              stored == 3, f"{stored} stored, max_urls=3")
        check("the adds over the ceiling were refused with 400",
              codes.count(400) == 5 and codes.count(303) == 3, str(codes))
        check("no fetch happened for a refused add", fake.calls == 3,
              f"{fake.calls} fetches")
        client.__exit__(None, None, None)
    finally:
        main.engine, main.check_url, main.validate_url_async = real
        restore_limiters(saved)


# --------------------------------------------------- (F6) log injection

def test_fetch_logs_cannot_be_forged():
    print("\n[F6] A URL with control characters can't forge log lines")
    hostile = "https://example.com/p?x=1\n[FETCH] Blocked unsafe URL: totally fine"
    line = monitor._log_safe(hostile)
    check("newlines are stripped from a logged URL", "\n" not in line, repr(line[:60]))
    check("carriage returns and NULs go too",
          "\r" not in monitor._log_safe("a\rb\x00c")
          and "\x00" not in monitor._log_safe("a\rb\x00c"))
    check("the field is length-capped",
          len(monitor._log_safe("https://example.com/" + "a" * 5000)) <= 300,
          str(len(monitor._log_safe("https://example.com/" + "a" * 5000))))
    check("an ordinary URL is left alone", monitor._log_safe(TARGET) == TARGET,
          monitor._log_safe(TARGET))

    async def blocked():
        # The unsafe-URL path prints the exception text, which carries the URL.
        return await monitor.fetch_page("http://127.0.0.1:22/\nforged", timeout=5)

    import io, contextlib  # noqa: E401
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        asyncio.run(blocked())
    logged = buf.getvalue().strip()
    check("the real blocked-URL log line is a single line",
          logged.count("\n") == 0, repr(logged))


# ------------------------------------------------------------------ runner

def main_runner():
    tests = [
        test_readd_inherits_the_cooldown,
        test_readd_loop_stays_bounded,
        test_readd_normalizes_the_url,
        test_expired_cooldown_is_not_inherited,
        test_healthy_delete_readd_is_unaffected,
        test_success_clears_inherited_state,
        test_parked_state_is_capped_per_user,
        test_max_urls_is_not_racy,
        test_fetch_logs_cannot_be_forged,
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
