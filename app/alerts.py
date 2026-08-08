"""
Email alert system. Sends change notifications via Resend API.
Permanent free tier: 3,000 emails/month (100/day) — perfect for launch.
"""

import os

import httpx

from app.config import RESEND_API_KEY, FROM_EMAIL


async def send_change_alert(
    to_email: str,
    url_label: str,
    url: str,
    diff_summary: str,
    pricing_changes: str = "",
) -> bool:
    """Send an email alert about a detected change. Returns True on success."""
    subject = f"🚨 Change detected: {url_label}"
    
    body_parts = [f"Your monitored page has changed!\n"]
    body_parts.append(f"Label: {url_label}")
    body_parts.append(f"URL: {url}")
    body_parts.append("")
    body_parts.append("--- What changed ---")
    body_parts.append(diff_summary)
    
    if pricing_changes:
        body_parts.append("")
        body_parts.append("--- Pricing-specific changes ---")
        body_parts.append(pricing_changes)
    
    body_parts.append("")
    body_parts.append(f"View full history: {os.getenv('APP_URL', 'http://localhost:8000')}/dashboard")
    
    body = "\n".join(body_parts)
    
    return await _send_email(to_email, subject, body)


async def send_welcome_email(to_email: str) -> bool:
    """Send a welcome/onboarding email."""
    subject = "Your competitor monitor is set up!"
    body = (
        "Welcome to Competitor Monitor!\n\n"
        "You're all set. We'll watch your competitor pages and alert you "
        "whenever something changes.\n\n"
        "Add your first URL from the dashboard:\n"
        f"{os.getenv('APP_URL', 'http://localhost:8000')}/dashboard\n\n"
        "Your first check will run automatically. Questions? Just reply to this email."
    )
    return await _send_email(to_email, subject, body)


async def _send_email(to: str, subject: str, body: str) -> bool:
    """Send via Resend API (resend.com). Permanent free tier: 3,000 emails/mo."""
    if not RESEND_API_KEY:
        print(f"[EMAIL] Would send to {to}: {subject}")
        print(f"[EMAIL] Body:\n{body[:500]}...")
        return True  # Dev mode — pretend success

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": FROM_EMAIL,
                    "to": [to],
                    "subject": subject,
                    "text": body,
                },
            )
            return resp.status_code in (200, 201)
    except Exception as e:
        print(f"[EMAIL] Failed to send to {to}: {e}")
        return False
