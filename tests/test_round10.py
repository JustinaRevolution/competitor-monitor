"""
Verification for the round-10 fixes.

Run from the repo root:  python3 tests/test_round10.py
Covers:
  (1) the test suite is no longer vacuous under pytest — a recorded `check()`
      failure now fails the pytest run, not just the script runner;
  (2) `fetch_page` honours a *total* wall-clock budget: a slow-drip body and a
      chain of slow redirects both give up inside the budget instead of holding
      the sweep open indefinitely.
"""

import asyncio
import ipaddress
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
os.environ.setdefault("SECRET_KEY", "x" * 64)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# ------------------------------------------------- (1) the suite is not vacuous

_PROBE = """
# Written by tests/test_round10.py. Mimics the check()/FAIL convention every
# test module here uses, with one deliberately failing check.
FAIL = []


def test_probe():
    FAIL.append({recorded!r})
"""


def _run_pytest_on_probe(recorded_failures: bool):
    """Run pytest over a throwaway module that records `recorded_failures`, return CompletedProcess."""
    probe = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         f"vacuity_probe_tmp_{os.getpid()}.py")
    body = _PROBE.format(recorded="a check that should fail the run")
    if not recorded_failures:
        body = body.replace("    FAIL.append", "    pass  # FAIL.append")
    with open(probe, "w") as fh:
        fh.write(body)
    try:
        return subprocess.run(
            [sys.executable, "-m", "pytest", probe, "-q", "-p", "no:cacheprovider"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=180,
        )
    finally:
        os.unlink(probe)


def test_recorded_check_failures_fail_pytest():
    print("\n[1] a failed check() is a failed pytest run")

    failing = _run_pytest_on_probe(recorded_failures=True)
    check("pytest exits non-zero when a check() was recorded as failed",
          failing.returncode != 0, f"rc={failing.returncode}\n{failing.stdout[-400:]}")
    check("pytest reports it as a failure, not a pass",
          "1 failed" in failing.stdout and "1 passed" not in failing.stdout,
          failing.stdout[-400:])
    check("the failure message names the failed check",
          "a check that should fail the run" in failing.stdout,
          failing.stdout[-400:])

    clean = _run_pytest_on_probe(recorded_failures=False)
    check("a test that records nothing still passes",
          clean.returncode == 0 and "1 passed" in clean.stdout,
          f"rc={clean.returncode}\n{clean.stdout[-400:]}")


# ------------------------------------------------- (2) total fetch time is bounded

class _SlowHandler(BaseHTTPRequestHandler):
    """Serves the shapes that defeat a per-operation timeout."""

    mode = "drip"          # drip | slow_redirect | slow_headers
    drip_seconds = 60.0    # far past any budget under test
    hop_delay = 1.0

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        try:
            if _SlowHandler.mode == "slow_headers":
                # Connection accepted, response never begins.
                time.sleep(_SlowHandler.drip_seconds)
                return

            if _SlowHandler.mode == "slow_redirect":
                # Every hop is individually well inside a per-read timeout; the
                # chain of them is not.
                time.sleep(_SlowHandler.hop_delay)
                nxt = int(self.path.rsplit("/", 1)[-1] or 0) + 1
                self.send_response(302)
                self.send_header("Location", f"/hop/{nxt}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            # drip: a valid response that never ends, one byte at a time. Each
            # write resets httpx's read clock, so only a total budget stops it.
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            deadline = time.monotonic() + _SlowHandler.drip_seconds
            while time.monotonic() < deadline:
                self.wfile.write(b"1\r\na\r\n")
                self.wfile.flush()
                time.sleep(0.2)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Expected: the client gave up on us, which is the point.
            pass


def test_fetch_has_a_total_time_budget():
    print("\n[2] fetch_page gives up inside its total budget")
    import app.security as security
    from app.monitor import fetch_page

    server = ThreadingHTTPServer(("127.0.0.1", 0), _SlowHandler)
    server.daemon_threads = True
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()

    real_resolve, real_disallowed = security._resolve, security._ip_is_disallowed
    real_ports = security.ALLOWED_PORTS
    loopback = ipaddress.ip_address("127.0.0.1")
    # Same staging as the SSRF pinning test: the stub listens on an ephemeral
    # port and on loopback, neither of which production would fetch. Widened
    # here so what is under test is the timing, not the SSRF guard.
    security.ALLOWED_PORTS = set(real_ports) | {port}
    security._resolve = lambda host: [loopback]
    security._ip_is_disallowed = lambda ip: False if ip == loopback else real_disallowed(ip)

    budget = 2.0
    # Generous ceiling: what is being proven is "bounded", not "prompt to the ms".
    ceiling = budget + 3.0
    try:
        for mode, label in (
            ("drip", "slow-drip body"),
            ("slow_headers", "response that never starts"),
            ("slow_redirect", "chain of slow redirects"),
        ):
            _SlowHandler.mode = mode
            start = time.monotonic()
            out = asyncio.run(fetch_page(f"http://slow.test:{port}/hop/0", timeout=budget))
            elapsed = time.monotonic() - start
            check(f"{label}: fetch returns within the {budget}s budget",
                  elapsed < ceiling, f"took {elapsed:.1f}s")
            check(f"{label}: fetch reports failure rather than partial content",
                  out is None, repr(out)[:80])

        # The default budget is a real number, not httpx's per-read one.
        from app.config import FETCH_TIMEOUT_SECONDS
        import inspect
        default = inspect.signature(fetch_page).parameters["timeout"].default
        check("fetch_page defaults to the configured total budget",
              default == FETCH_TIMEOUT_SECONDS and 1 <= FETCH_TIMEOUT_SECONDS <= 300,
              f"default={default!r}, configured={FETCH_TIMEOUT_SECONDS!r}")
    finally:
        security._resolve, security._ip_is_disallowed = real_resolve, real_disallowed
        security.ALLOWED_PORTS = real_ports
        server.shutdown()


def test_a_stalled_url_does_not_stall_the_sweep():
    """The sweep is sequential, so bounded fetches are what bound the sweep."""
    print("\n[2b] one stalled monitor cannot hold the whole sweep open")
    import app.monitor as monitor

    budget = 1.0
    stalls = []

    async def scenario():
        # Stand in for a target that never answers: without a total budget this
        # await never returns and every later customer's check waits behind it.
        async def hang(*a, **kw):
            await asyncio.sleep(3600)

        real_inner = monitor._fetch_page
        monitor._fetch_page = hang
        try:
            start = time.monotonic()
            for _ in range(3):
                stalls.append(await monitor.fetch_page("https://example.com/pricing",
                                                       timeout=budget))
            return time.monotonic() - start
        finally:
            monitor._fetch_page = real_inner

    elapsed = asyncio.run(scenario())
    check("three hung checks in a row are each cut off at the budget",
          elapsed < (budget * 3) + 2.0, f"took {elapsed:.1f}s for 3 checks")
    check("each hung check reports failure", stalls == [None, None, None], repr(stalls))


if __name__ == "__main__":
    test_recorded_check_failures_fail_pytest()
    test_fetch_has_a_total_time_budget()
    test_a_stalled_url_does_not_stall_the_sweep()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED: " + ", ".join(FAIL))
    sys.exit(1 if FAIL else 0)
