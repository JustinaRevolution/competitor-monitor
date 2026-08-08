"""
Core monitoring engine: fetch a page, extract meaningful content, hash it, diff it.
"""

import hashlib
import difflib
import re
from datetime import datetime, timezone
from typing import Tuple, Optional

import httpx
from bs4 import BeautifulSoup, Tag

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


async def fetch_page(url: str, timeout: int = 30) -> Optional[str]:
    """Fetch a URL and return raw HTML, or None on failure."""
    try:
        async with httpx.AsyncClient(headers=_HEADERS, follow_redirects=True, timeout=timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.text
    except Exception as e:
        return None


def extract_meaningful_content(html: str) -> Tuple[str, str]:
    """
    Strip noise (nav, header, footer, scripts, styles) from HTML.
    Returns (stripped_text, content_hash).
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

    # Hash it
    content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

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

    text, content_hash = extract_meaningful_content(html)

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
