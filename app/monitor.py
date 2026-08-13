"""
Core monitoring engine: fetch a page, extract meaningful content, hash it, diff it.
"""

import asyncio
import hashlib
import difflib
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple, Optional

import httpx
from bs4 import BeautifulSoup, Tag

from app.config import FETCH_TIMEOUT_SECONDS
from app.security import MAX_REDIRECTS, UnsafeUrlError, header_safe, validate_and_pin_async

# Log lines below carry a user-supplied URL (and exception text derived from
# one). journald keeps whatever bytes it is handed, so a URL containing a
# newline would forge log entries. Strip control characters and cap the length.
_LOG_FIELD_LEN = 300


def _log_safe(value) -> str:
    return header_safe(str(value), limit=_LOG_FIELD_LEN)


# Default headers to look like a real browser
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


# A monitored pricing page is a few hundred KB at worst. Anything past this is
# either a mistake or someone pointing us at a bottomless stream.
#
# The cap is a CPU budget, not just a bandwidth one. `extract_meaningful_content`
# is pure-Python BeautifulSoup, and its cost grows with the size of the body:
# 1.8 MB of repeated tags measured ~11.7s of solid parsing. Even off the event
# loop that is a thread pinned and the GIL contended for the whole time, so the
# ceiling on the body is what bounds the damage. Half a megabyte is far more
# than any real pricing page and keeps a worst-case parse in the low seconds.
MAX_RESPONSE_BYTES = 512 * 1024

# Every ChangeEvent stores an old *and* a new copy of the extracted text, so an
# unbounded extract is an unbounded database: a couple of large pages changing
# often is enough to fill the disk, no malice required. Keep the head of the
# text — headings and prices live near the top — and say so in the stored copy.
MAX_STORED_CONTENT_CHARS = 10_000
TRUNCATION_NOTE = "\n\n[... truncated: only the first {n} characters are stored ...]"


def _pinned_url(url: httpx.URL, ip: ipaddress._BaseAddress) -> httpx.URL:
    """Rewrite `url` to address the validated IP literally, keeping scheme/port/path."""
    return url.copy_with(host=str(ip))


async def fetch_page(url: str, timeout: float = FETCH_TIMEOUT_SECONDS) -> Optional[str]:
    """
    Fetch a URL and return raw HTML, or None on failure or on running out of time.

    `timeout` is the **total** budget for the whole fetch, not a per-read one.
    httpx's own timeout is per-I/O-operation, so a server that answers with one
    byte every few seconds — or a chain of slow redirects — resets that clock
    indefinitely and holds the fetch open for as long as it likes. The scheduled
    sweep checks monitors one at a time, so a single such target stops alerting
    for every other customer until it lets go. The outer deadline below is what
    makes "30 seconds" mean thirty seconds.
    """
    try:
        async with asyncio.timeout(timeout):
            return await _fetch_page(url, timeout)
    except TimeoutError:
        # Only *our* deadline lands here. A cancellation from the caller stays a
        # CancelledError and propagates, as it must.
        print(f"[FETCH] {_log_safe(url)}: exceeded the {timeout}s total fetch budget")
        return None


async def _fetch_page(url: str, timeout: float) -> Optional[str]:
    """
    The fetch itself. Always run under the deadline in `fetch_page`.

    Every hop is resolved and validated here, and then the connection is *pinned*
    to the address that was validated: we dial the IP directly and carry the
    original hostname in the Host header (and in SNI, so TLS still verifies
    against the real name). Letting httpx re-resolve the name would reopen the
    DNS-rebinding window — public answer at validation, private answer at connect.

    Redirects are followed manually for the same reason: an allowed public URL
    must not be able to bounce us into the private network.
    """
    try:
        # Per-operation limits under the total deadline: no single connect or
        # read may eat the whole budget, and a stalled socket fails fast instead
        # of waiting for the umbrella above to expire.
        limits = httpx.Timeout(timeout, connect=min(10.0, timeout))
        async with httpx.AsyncClient(headers=_HEADERS, follow_redirects=False, timeout=limits) as client:
            current = httpx.URL(url)
            for _ in range(MAX_REDIRECTS + 1):
                ip = await validate_and_pin_async(str(current))

                hostname = current.host
                # Host header must carry the name (and non-default port) the
                # origin expects, not the IP we are dialing.
                host_header = current.netloc.decode("ascii")
                request_url = _pinned_url(current, ip)

                async with client.stream(
                    "GET",
                    request_url,
                    headers={"Host": host_header},
                    extensions={"sni_hostname": hostname},
                ) as resp:
                    if resp.is_redirect:
                        location = resp.headers.get("location")
                        if not location:
                            return None
                        # Resolve relative redirects against the URL we just
                        # fetched — the hostname one, not the pinned-IP one.
                        current = current.join(location)
                        continue

                    resp.raise_for_status()

                    declared = resp.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                        print(f"[FETCH] Response too large ({declared} bytes): {_log_safe(current)}")
                        return None

                    chunks = []
                    total = 0
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > MAX_RESPONSE_BYTES:
                            print(f"[FETCH] Response exceeded {MAX_RESPONSE_BYTES} bytes: {_log_safe(current)}")
                            return None
                        chunks.append(chunk)

                    body = b"".join(chunks)
                    try:
                        return body.decode(resp.charset_encoding or "utf-8", errors="replace")
                    except LookupError:  # server declared a charset Python has no codec for
                        return body.decode("utf-8", errors="replace")

            # Too many redirects.
            return None
    except UnsafeUrlError as e:
        print(f"[FETCH] Blocked unsafe URL: {_log_safe(e)}")
        return None
    except Exception as e:
        # Timeouts, connection resets, TLS failures, 4xx/5xx from
        # raise_for_status. Swallowing these silently made a permanently broken
        # target indistinguishable from a healthy unchanged one.
        print(f"[FETCH] {_log_safe(url)}: {type(e).__name__}: {_log_safe(e)}")
        return None


# Extraction is the one heavy CPU step in a check, and it must not run on the
# event loop: a synchronous call cannot be interrupted by `asyncio.timeout`, so
# every parse froze the whole single-worker process — logins, /health, the
# dashboard and every other customer's alerts — for as long as it took.
#
# It gets its own small pool rather than `asyncio.to_thread`'s default executor.
# That default is shared with bcrypt hashing (main.py) and DNS validation
# (security.py) and is sized `min(32, cpu + 4)`, which on the 1-vCPU box this
# deploys to is *five* threads — exactly MAX_CONCURRENT_CHECKS. A sweep of large
# pages would have taken every one of them and queued logins behind the parses.
# Two workers keep parsing bounded and leave the shared pool untouched.
_EXTRACT_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="extract")


async def extract_meaningful_content_async(html: str) -> Tuple[str, str]:
    """`extract_meaningful_content` off the event loop. Use this from coroutines."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_EXTRACT_POOL, extract_meaningful_content, html)


def extract_meaningful_content(html: str) -> Tuple[str, str]:
    """
    Strip noise (nav, header, footer, scripts, styles) from HTML.
    Returns (stripped_text, content_hash).

    Blocking and CPU-bound — never call this directly from a coroutine, use
    `extract_meaningful_content_async`.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Remove non-content elements
    for tag in soup.select("script, style, nav, header, footer, iframe, noscript, svg, img, figure, form"):
        tag.decompose()

    # Remove common noise classes/ids — heuristic, catch common patterns
    for selector in [
        "[class*=nav]", "[class*=menu]", "[class*=header]", "[class*=footer]",
        "[class*=sidebar]", "[class*=widget]", "[class*=cookie]", "[class*=popup]",
        "[class*=modal]", "[id*=nav]", "[id*=menu]", "[id*=header]", "[id*=footer]",
        "[id*=sidebar]", "[id*=cookie]",
    ]:
        for el in soup.select(selector):
            # Only remove if it's a container (div, nav, aside, section)
            if isinstance(el, Tag) and el.name in ("div", "nav", "aside", "section", "header", "footer"):
                el.decompose()

    # Get the text
    text = soup.get_text(separator="\n", strip=True)

    # Normalize whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()

    # Hash the *whole* extract, so a change past the storage cap is still
    # detected; only the copy we keep on disk is truncated.
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    if len(text) > MAX_STORED_CONTENT_CHARS:
        text = text[:MAX_STORED_CONTENT_CHARS] + TRUNCATION_NOTE.format(n=MAX_STORED_CONTENT_CHARS)

    return text, content_hash


def generate_diff_summary(old_text: str, new_text: str) -> str:
    """Generate a human-readable summary of what changed."""
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()

    diff = list(difflib.unified_diff(
        old_lines, new_lines,
        fromfile="before", tofile="after",
        lineterm="",
    ))

    # Summarize
    added = [l[1:] for l in diff if l.startswith("+") and not l.startswith("+++")]
    removed = [l[1:] for l in diff if l.startswith("-") and not l.startswith("---")]

    parts = []
    if added:
        parts.append(f"New content added ({len(added)} lines)")
        # Show first few meaningful additions
        significant = [a for a in added if len(a) > 10][:5]
        for s in significant:
            parts.append(f"  + {s.strip()[:120]}")
    if removed:
        parts.append(f"Content removed ({len(removed)} lines)")
        significant = [r for r in removed if len(r) > 10][:5]
        for s in significant:
            parts.append(f"  - {s.strip()[:120]}")

    if not parts:
        return "Content changed (minor formatting differences)"

    return "\n".join(parts)


def extract_pricing_specific(text: str) -> str:
    """
    Try to find pricing-related content specifically.
    Looks for dollar amounts, price patterns, plan names.
    """
    lines = text.splitlines()
    price_lines = []
    for line in lines:
        # Line has a dollar amount
        if re.search(r"\$\d+", line):
            price_lines.append(line.strip())

    if price_lines:
        return "\n".join(price_lines[:20])
    return ""


async def check_url(url: str, previous_hash: Optional[str], previous_content: Optional[str]) -> dict:
    """
    Check a single URL for changes.
    Returns a dict with keys: changed, new_hash, new_content, diff_summary, error, status_code
    """
    html = await fetch_page(url)
    if html is None:
        return {"changed": False, "error": "Failed to fetch page"}

    text, content_hash = await extract_meaningful_content_async(html)

    if previous_hash is None:
        # First check — no history to compare
        return {
            "changed": False,
            "new_hash": content_hash,
            "new_content": text,
            "error": None,
            "first_check": True,
        }

    if content_hash == previous_hash:
        return {
            "changed": False,
            "new_hash": content_hash,
            "new_content": text,
            "error": None,
        }

    # Something changed
    summary = generate_diff_summary(previous_content or "", text)

    return {
        "changed": True,
        "new_hash": content_hash,
        "new_content": text,
        "diff_summary": summary,
        "pricing_changes": extract_pricing_specific(text),
        "error": None,
    }
