"""
Verification for the seventh-round review fix.

Run from the repo root:  python3 tests/test_round13.py

Covers §1 — event-loop stall via oversized HTML:
  F1  `check_url` runs extraction off the event loop, so a slow parse no longer
      freezes logins, /health and every other customer's checks.
  F2  Extraction uses its own pool, not the default executor that bcrypt and DNS
      validation share, so a sweep of large pages cannot queue a login behind it.
  F3  A real page at the size cap is parsed without stalling the loop.
  F4  `MAX_RESPONSE_BYTES` is bounded to 512 KB and enforced against both a
      declared content-length and an undeclared streamed body.
"""

import asyncio
import ipaddress
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
os.environ.setdefault("SECRET_KEY", "x" * 64)

import app.monitor as monitor  # noqa: E402
import app.security as security  # noqa: E402
from app.monitor import (  # noqa: E402
    MAX_RESPONSE_BYTES, check_url, extract_meaningful_content,
    extract_meaningful_content_async, fetch_page,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


class Heartbeat:
    """Ticks on the event loop and records the longest gap between ticks.

    A coroutine doing CPU work inline shows up here directly: the loop cannot
    reschedule this task while a synchronous call is running, so the gap becomes
    the duration of that call.
    """

    def __init__(self, interval=0.01):
        self.interval = interval
        self.max_gap = 0.0
        self._task = None
        self._ticking = None

    async def _run(self):
        last = time.monotonic()
        while True:
            await asyncio.sleep(self.interval)
            now = time.monotonic()
            self.max_gap = max(self.max_gap, now - last - self.interval)
            last = now
            self._ticking.set()

    async def __aenter__(self):
        # The task must be *running* before the measured work starts. Scheduling
        # it and immediately awaiting a coroutine that never yields would leave
        # it un-started, its first tick landing after the stall — a gap of zero
        # no matter how long the loop was blocked, i.e. a test that proves
        # nothing. Wait for a real tick, then discard the startup gap.
        self._ticking = asyncio.Event()
        self._task = asyncio.ensure_future(self._run())
        await self._ticking.wait()
        self.max_gap = 0.0
        return self

    async def __aexit__(self, *exc):
        # And the last gap has to be *collected*. A blocking call leaves the
        # ticker's overdue sleep pending; if the block is the last thing the
        # scenario does, cancelling here would throw that tick away and report
        # a gap of zero for a loop that was frozen the whole time. Let it fire
        # once more first. Read `max_gap` after the block, not inside it.
        try:
            self._ticking.clear()
            await asyncio.wait_for(self._ticking.wait(), timeout=5)
        except (asyncio.TimeoutError, TimeoutError):
            pass
        finally:
            self._task.cancel()
        return False


def _patch_fetch(html):
    """Point `check_url` at a fixed body — this file tests extraction, not I/O."""
    async def fake_fetch(url, timeout=None):
        return html
    real = monitor.fetch_page
    monitor.fetch_page = fake_fetch
    return real


# ---------------------------------------------------------------- F1, F2, F3

def test_extraction_is_off_the_event_loop():
    print("\n[1] extraction does not run on the event loop")

    seen_threads = []
    entered = threading.Event()

    def slow_extract(html):
        """Stand-in for a large parse: same blocking shape, fixed duration."""
        seen_threads.append(threading.current_thread())
        entered.set()
        time.sleep(1.0)
        return "text", "hash"

    real_extract = monitor.extract_meaningful_content
    real_fetch = _patch_fetch("<html><body><p>$9</p></body></html>")
    monitor.extract_meaningful_content = slow_extract

    async def scenario():
        hb = Heartbeat()
        async with hb:
            start = time.monotonic()
            result = await check_url("https://example.com/pricing", None, None)
            elapsed = time.monotonic() - start
        return hb.max_gap, elapsed, result

    try:
        gap, elapsed, result = asyncio.run(scenario())
    finally:
        monitor.extract_meaningful_content = real_extract
        monitor.fetch_page = real_fetch

    check("the extraction really ran (and took its full second)",
          elapsed >= 1.0 and result.get("new_hash") == "hash", f"{elapsed:.2f}s")
    check("event loop kept ticking through a 1.0s extraction",
          gap < 0.3, f"longest loop gap {gap:.2f}s")
    check("extraction ran on a worker thread, not the main thread",
          bool(seen_threads) and seen_threads[0] is not threading.main_thread(),
          seen_threads[0].name if seen_threads else "never called")
    check("worker came from the dedicated extraction pool",
          bool(seen_threads) and seen_threads[0].name.startswith("extract"),
          seen_threads[0].name if seen_threads else "never called")


def test_extraction_does_not_starve_the_shared_thread_pool():
    print("\n[2] extraction leaves the bcrypt/DNS pool alone")

    def slow_extract(html):
        time.sleep(1.0)
        return "text", "hash"

    real_extract = monitor.extract_meaningful_content
    real_fetch = _patch_fetch("<html><body><p>$9</p></body></html>")
    monitor.extract_meaningful_content = slow_extract

    async def scenario():
        # More concurrent checks than the app's own cap, all parsing at once.
        checks = [
            asyncio.ensure_future(check_url(f"https://example.com/{n}", None, None))
            for n in range(8)
        ]
        await asyncio.sleep(0.2)  # let them all reach extraction

        # `asyncio.to_thread` is exactly how password hashing (main.py) and DNS
        # validation (security.py) run. If extraction shared that pool, this
        # would block behind the parses above.
        start = time.monotonic()
        await asyncio.to_thread(lambda: None)
        latency = time.monotonic() - start

        await asyncio.gather(*checks)
        return latency

    try:
        latency = asyncio.run(scenario())
    finally:
        monitor.extract_meaningful_content = real_extract
        monitor.fetch_page = real_fetch

    check("a bcrypt/DNS-shaped to_thread call is not queued behind extractions",
          latency < 0.3, f"waited {latency:.2f}s")
    check("the extraction pool is bounded",
          monitor._EXTRACT_POOL._max_workers <= 2,
          f"max_workers={monitor._EXTRACT_POOL._max_workers}")


def test_real_page_at_the_cap_does_not_stall_the_loop():
    print("\n[3] a real page at the size cap keeps the loop responsive")

    # Worst case measured in the review: many tiny tags, one per parse event.
    html = "<html><body>" + "<p>hi</p>" * (MAX_RESPONSE_BYTES // 9) + "</body></html>"

    solo = time.monotonic()
    extract_meaningful_content(html)
    solo = time.monotonic() - solo

    real_fetch = _patch_fetch(html)

    async def scenario():
        hb = Heartbeat()
        async with hb:
            start = time.monotonic()
            result = await check_url("https://example.com/pricing", None, None)
            elapsed = time.monotonic() - start
        return hb.max_gap, elapsed, result

    try:
        gap, elapsed, result = asyncio.run(scenario())
    finally:
        monitor.fetch_page = real_fetch

    check("the page really was parsed",
          bool(result.get("new_hash")) and result.get("first_check") is True,
          f"{len(html)} bytes in {elapsed:.2f}s")
    # Pure-Python parsing holds the GIL between switch intervals, so the loop is
    # slowed, not free. What must not happen is the whole parse landing in one
    # unbroken gap, which is what running it inline did.
    check("loop gap stays far below the parse time",
          gap < max(0.5, solo / 3), f"gap {gap:.2f}s vs {solo:.2f}s of parsing")


def test_async_wrapper_matches_the_sync_extractor():
    print("\n[4] extract_meaningful_content_async returns the same result")
    html = "<html><body><nav>skip</nav><p>Pro plan $49/mo</p></body></html>"
    sync = extract_meaningful_content(html)
    asyncd = asyncio.run(extract_meaningful_content_async(html))
    check("same (text, hash) as the synchronous extractor", sync == asyncd,
          f"{sync!r} vs {asyncd!r}")


# -------------------------------------------------------------------- F4 cap

OVER_CAP = MAX_RESPONSE_BYTES + 64 * 1024


class _SizeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/declared":
            body = b"x" * OVER_CAP
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass
        elif self.path == "/undeclared":
            # No content-length: the cap has to be enforced while streaming.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            chunk = b"y" * 16384
            try:
                for _ in range(OVER_CAP // len(chunk) + 1):
                    self.wfile.write(chunk)
            except Exception:
                pass
        else:
            body = b"<html><body><p>$9 plan</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_response_size_cap():
    print("\n[5] MAX_RESPONSE_BYTES is small and enforced")

    check("cap is at most 512 KB",
          MAX_RESPONSE_BYTES <= 512 * 1024, f"{MAX_RESPONSE_BYTES} bytes")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _SizeHandler)
    server.daemon_threads = True
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    real_resolve, real_disallowed = security._resolve, security._ip_is_disallowed
    real_ports = security.ALLOWED_PORTS
    loopback = ipaddress.ip_address("127.0.0.1")
    # Same staging as test_round10: the stub listens on loopback and an ephemeral
    # port, neither of which production would fetch. Widened so what is under
    # test is the size cap, not the SSRF guard.
    security.ALLOWED_PORTS = set(real_ports) | {port}
    security._resolve = lambda host: [loopback]
    security._ip_is_disallowed = lambda ip: False if ip == loopback else real_disallowed(ip)

    try:
        small = asyncio.run(fetch_page(f"http://big.test:{port}/small", timeout=10))
        check("an under-cap page still fetches", small is not None and "$9 plan" in small,
              repr(small)[:60])

        declared = asyncio.run(fetch_page(f"http://big.test:{port}/declared", timeout=10))
        check("a declared over-cap content-length is refused", declared is None,
              f"got {len(declared or '')} chars")

        undeclared = asyncio.run(fetch_page(f"http://big.test:{port}/undeclared", timeout=10))
        check("an undeclared over-cap body is cut off mid-stream", undeclared is None,
              f"got {len(undeclared or '')} chars")
    finally:
        security._resolve, security._ip_is_disallowed = real_resolve, real_disallowed
        security.ALLOWED_PORTS = real_ports
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    test_extraction_is_off_the_event_loop()
    test_extraction_does_not_starve_the_shared_thread_pool()
    test_real_page_at_the_cap_does_not_stall_the_loop()
    test_async_wrapper_matches_the_sync_extractor()
    test_response_size_cap()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for name in FAIL:
            print(f"  FAILED: {name}")
        sys.exit(1)
