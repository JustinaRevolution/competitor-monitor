"""
Verification for the second-round security/correctness fixes.

Run from the repo root:  python3 tests/test_fixes.py
Covers: the scheduled-check cycle (datetime convention + ChangeEvent history),
SSRF IP pinning and redirect re-validation, the response size cap, and the
per-user rate limit on /urls/{id}/check.
"""

import asyncio
import ipaddress
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ---------------------------------------------------------------- (b) scheduled cycle

def test_scheduled_cycle():
    print("\n[b] scheduled-style check runs end-to-end and commits")
    import app.main as main
    from app.models import Base, User, MonitoredUrl, ChangeEvent, get_session, utcnow
    from sqlalchemy import create_engine

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)

    db = get_session(engine)
    user = User(email="sched@test.local", password_hash="x", is_active=True)
    db.add(user)
    db.flush()
    stale = utcnow().replace(year=utcnow().year - 1)  # long overdue
    db.add(MonitoredUrl(
        user_id=user.id, label="Test", url="https://example.com/pricing",
        check_interval_hours=24, last_checked_at=stale,
        last_hash="OLDHASH", last_content="Old price: $10",
    ))
    db.commit()
    url_id = db.query(MonitoredUrl).one().id
    db.close()

    async def fake_check_url(url, previous_hash, previous_content):
        return {"changed": True, "new_hash": "NEWHASH", "new_content": "New price: $20",
                "diff_summary": "price changed", "pricing_changes": "$20", "error": None}

    async def fake_alert(**kwargs):
        return True

    real_engine, real_check, real_alert = main.engine, main.check_url, main.send_change_alert
    main.engine, main.check_url, main.send_change_alert = engine, fake_check_url, fake_alert
    try:
        asyncio.run(main.run_scheduled_checks())
    finally:
        main.engine, main.check_url, main.send_change_alert = real_engine, real_check, real_alert

    # Re-open a fresh session so we read what was actually committed.
    db = get_session(engine)
    row = db.query(MonitoredUrl).filter(MonitoredUrl.id == url_id).one()
    check("last_checked_at advanced past the stale value", row.last_checked_at > stale,
          f"{row.last_checked_at}")
    check("monitor row committed with new hash", row.last_hash == "NEWHASH")

    events = db.query(ChangeEvent).all()
    check("exactly one ChangeEvent was committed", len(events) == 1, f"got {len(events)}")
    if events:
        e = events[0]
        check("ChangeEvent old_hash is the OLD value", e.old_hash == "OLDHASH", f"got {e.old_hash!r}")
        check("ChangeEvent new_hash is the NEW value", e.new_hash == "NEWHASH", f"got {e.new_hash!r}")
        check("ChangeEvent old != new (history is real)",
              e.old_hash != e.new_hash and e.old_content != e.new_content)
        check("ChangeEvent old_content is the OLD content", e.old_content == "Old price: $10")
        check("alert flag persisted", e.alerted is True)
    db.close()
    os.unlink(tmp.name)


def test_startup_smoke_check():
    print("\n[b] startup smoke check")
    import app.main as main
    try:
        main._smoke_check_scheduled_cycle()
        check("_smoke_check_scheduled_cycle() passes", True)
    except Exception as e:
        check("_smoke_check_scheduled_cycle() passes", False, repr(e))


# ---------------------------------------------------------------------- (c) SSRF

def test_ssrf_validation():
    print("\n[c] SSRF: private/non-global addresses rejected")
    from app.security import UnsafeUrlError, validate_url

    blocked = [
        ("loopback", "http://127.0.0.1/"),
        ("loopback v6", "http://[::1]/"),
        ("RFC1918", "http://10.0.0.1/admin"),
        ("RFC1918 /16", "http://192.168.1.1/"),
        ("link-local / cloud metadata", "http://169.254.169.254/latest/meta-data/"),
        ("IPv4-mapped v6 loopback", "http://[::ffff:127.0.0.1]/"),
        ("CGNAT 100.64/10 (M2)", "http://100.64.0.1/"),
        ("benchmark 198.18/15 (M2)", "http://198.18.0.1/"),
        ("TEST-NET-1 192.0.2.0/24 (M2)", "http://192.0.2.1/"),
        ("unspecified", "http://0.0.0.0/"),
        ("bad scheme", "file:///etc/passwd"),
        ("bad scheme gopher", "gopher://127.0.0.1/"),
    ]
    for name, url in blocked:
        try:
            validate_url(url)
            check(f"blocks {name}", False, f"{url} was allowed")
        except UnsafeUrlError:
            check(f"blocks {name}", True)

    try:
        validate_url("http://93.184.216.34/")  # public literal
        check("allows a public IP literal", True)
    except UnsafeUrlError as e:
        check("allows a public IP literal", False, str(e))


class _Handler(BaseHTTPRequestHandler):
    """Records the Host header it was reached with; can redirect or send a big body."""
    seen_host = None
    mode = "ok"

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        _Handler.seen_host = self.headers.get("Host")
        if _Handler.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if _Handler.mode == "huge_chunked":
            # No Content-Length at all, so only the streaming cap can stop this.
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"A" * 65536
            try:
                for _ in range(200):  # would be 12MB if nobody stopped it
                    self.wfile.write(b"%X\r\n" % len(chunk) + chunk + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass  # expected: the client hit its cap and hung up
            return

        body = b"<html><body>hello</body></html>"
        if _Handler.mode == "huge":
            body = b"<html>" + b"A" * (3 * 1024 * 1024) + b"</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


def test_ssrf_pinning():
    print("\n[c] SSRF: connection is pinned to the validated IP")
    import app.security as security
    from app.monitor import fetch_page

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    real_resolve, real_disallowed = security._resolve, security._ip_is_disallowed
    real_ports = security.ALLOWED_PORTS
    loopback = ipaddress.ip_address("127.0.0.1")

    # The stub server listens on an ephemeral port, which the production
    # allow-list (80/443 only) rightly refuses. Widen it just for this test so
    # what is being exercised is the pinning, not the port check.
    security.ALLOWED_PORTS = set(real_ports) | {port}

    # Simulate: "pinned.test" resolved to a public-looking address at validation
    # time. Loopback is treated as allowed *only* so the pinned target is
    # reachable in-test; everything else keeps its real verdict.
    security._resolve = lambda host: [loopback]
    security._ip_is_disallowed = lambda ip: False if ip == loopback else real_disallowed(ip)
    try:
        _Handler.mode, _Handler.seen_host = "ok", None
        html = asyncio.run(fetch_page(f"http://pinned.test:{port}/pricing"))
        check("fetch reached the pinned IP (not a re-resolved one)",
              html is not None and "hello" in html, repr(html)[:80])
        check("Host header carried the original hostname",
              _Handler.seen_host == f"pinned.test:{port}", f"got {_Handler.seen_host!r}")

        _Handler.mode = "redirect"
        out = asyncio.run(fetch_page(f"http://pinned.test:{port}/pricing"))
        check("redirect hop into link-local is re-validated and blocked", out is None,
              repr(out)[:80])

        _Handler.mode = "huge"
        out = asyncio.run(fetch_page(f"http://pinned.test:{port}/pricing"))
        check("3MB response with Content-Length is rejected (M4)", out is None, repr(out)[:80])

        _Handler.mode = "huge_chunked"
        out = asyncio.run(fetch_page(f"http://pinned.test:{port}/pricing"))
        check("chunked response with no Content-Length is capped mid-stream (M4)",
              out is None, repr(out)[:80])
    finally:
        security._resolve, security._ip_is_disallowed = real_resolve, real_disallowed
        security.ALLOWED_PORTS = real_ports
        server.shutdown()


# ------------------------------------------------------------- (d) per-user rate limit

def test_check_now_user_rate_limit():
    print("\n[d] check_now per-user rate limit")
    from fastapi.testclient import TestClient
    import app.main as main
    import app.security as security
    from app.models import Base, User, MonitoredUrl, get_session
    from sqlalchemy import create_engine

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    engine = create_engine(f"sqlite:///{tmp.name}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = get_session(engine)
    user = User(email="rl@test.local", password_hash="x", is_active=True)
    db.add(user)
    db.flush()
    db.add(MonitoredUrl(user_id=user.id, label="RL", url="https://example.com/p"))
    db.commit()
    user_id, url_id = user.id, db.query(MonitoredUrl).one().id
    db.close()

    async def fake_check_url(url, previous_hash, previous_content):
        return {"changed": False, "new_hash": "H", "new_content": "C", "error": None}

    async def fake_validate(url):
        return url

    # Give the per-IP bucket lots of room so this exercises the per-user bucket.
    real = (main.engine, main.check_url, main.validate_url_async, main.check_now_limiter)
    main.engine = engine
    main.check_url = fake_check_url
    main.validate_url_async = fake_validate
    main.check_now_limiter = security.TokenBucket(capacity=10_000, refill_seconds=300)
    main.check_now_user_limiter = security.TokenBucket(capacity=10, refill_seconds=300)
    try:
        with TestClient(main.app) as client:
            client.get("/login")  # seeds the CSRF cookie via middleware
            secret = client.cookies.get(security.CSRF_COOKIE)
            client.cookies.set("token", main.make_token(user_id))
            # Tokens are bound to the auth cookie too, so mint after logging in.
            token = security.mint_csrf_token(
                secret, security.csrf_binding_for_auth(client.cookies.get("token")))

            codes = []
            for _ in range(13):
                r = client.post(f"/urls/{url_id}/check", data={"csrf_token": token},
                                follow_redirects=False)
                codes.append(r.status_code)

            allowed = sum(1 for c in codes if c == 303)
            limited = sum(1 for c in codes if c == 429)
            check("first 10 checks allowed", allowed == 10, f"got {allowed}: {codes}")
            check("further checks return 429", limited == 3, f"got {limited}: {codes}")
            check("limit is keyed per user", not main.check_now_user_limiter.allow(f"check_now:user:{user_id}")
                  and main.check_now_user_limiter.allow("check_now:user:999999"))
    finally:
        main.engine, main.check_url, main.validate_url_async, main.check_now_limiter = real
        os.unlink(tmp.name)


if __name__ == "__main__":
    test_scheduled_cycle()
    test_startup_smoke_check()
    test_ssrf_validation()
    test_ssrf_pinning()
    test_check_now_user_rate_limit()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED: " + ", ".join(FAIL))
    sys.exit(1 if FAIL else 0)
