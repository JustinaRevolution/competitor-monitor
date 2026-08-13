"""
Verification for the round-11 fix.

Run from the repo root:  python3 tests/test_round11.py
Covers the missing production guard on `RESEND_API_KEY`:
  (1) production with an empty RESEND_API_KEY refuses to boot, the way a weak
      SECRET_KEY or a missing STRIPE_WEBHOOK_SECRET already does;
  (2) production with a key set still boots;
  (3) development with no key still boots, and `_send_email` keeps its
      print-and-pretend-success shortcut so the app works without Resend;
  (4) belt-and-braces: with no key, `_send_email` reports *failure* when
      IS_PRODUCTION is true, so `_deliver_change_alert` leaves the change
      un-alerted and the retry sweep keeps it.
"""

import asyncio
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
os.environ.setdefault("SECRET_KEY", "x" * 64)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")


# --------------------------------------------------------- (1)-(3) boot guard

def _boot(**env_overrides):
    """Import app.config in a fresh interpreter with a controlled environment."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "SECRET_KEY": "y" * 64,
        # Billing fully configured, so the Stripe guards stay quiet and the only
        # thing under test is the Resend one.
        "STRIPE_SECRET_KEY": "sk_test_round11",
        "STRIPE_PRICE_ID": "price_round11",
        "STRIPE_WEBHOOK_SECRET": "whsec_round11",
    }
    env.update(env_overrides)
    return subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, '.'); import app.config; print('BOOTED')"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        # `-E` alone is not enough: config.py calls load_dotenv(), and a real
        # .env in the repo root would override everything set here.
        env={**env, "DOTENV_PATH_UNUSED": "1"},
    )


def test_production_without_resend_key_refuses_to_boot():
    proc = _boot(APP_ENV="production", RESEND_API_KEY="")
    check("production + empty RESEND_API_KEY fails to boot",
          proc.returncode != 0, f"rc={proc.returncode} out={proc.stdout.strip()!r}")
    check("the failure names RESEND_API_KEY",
          "RESEND_API_KEY" in proc.stderr, proc.stderr.strip()[-200:])
    check("the failure is a RuntimeError, matching the other config guards",
          "RuntimeError" in proc.stderr, proc.stderr.strip()[-200:])

    # Whitespace is not a key either — the operator who pasted a stray space.
    proc = _boot(APP_ENV="production", RESEND_API_KEY="   ")
    check("production + whitespace-only RESEND_API_KEY fails to boot",
          proc.returncode != 0 and "RESEND_API_KEY" in proc.stderr,
          f"rc={proc.returncode}")


def test_production_with_resend_key_boots():
    proc = _boot(APP_ENV="production", RESEND_API_KEY="re_round11_key")
    check("production + RESEND_API_KEY set boots",
          proc.returncode == 0 and "BOOTED" in proc.stdout,
          f"rc={proc.returncode} err={proc.stderr.strip()[-200:]!r}")


def test_development_without_resend_key_still_boots():
    proc = _boot(APP_ENV="development", RESEND_API_KEY="")
    check("development + no RESEND_API_KEY still boots",
          proc.returncode == 0 and "BOOTED" in proc.stdout,
          f"rc={proc.returncode} err={proc.stderr.strip()[-200:]!r}")


# ------------------------------------------------ (4) _send_email return value

def _send_with(is_production, api_key=""):
    """Call _send_email with patched module globals, restoring them after."""
    from app import alerts
    real = (alerts.RESEND_API_KEY, alerts.IS_PRODUCTION)
    alerts.RESEND_API_KEY, alerts.IS_PRODUCTION = api_key, is_production
    try:
        return asyncio.run(alerts._send_email("nobody@example.com", "subj", "body"))
    finally:
        (alerts.RESEND_API_KEY, alerts.IS_PRODUCTION) = real


def test_keyless_send_reports_failure_in_production():
    check("keyless _send_email returns False when IS_PRODUCTION",
          _send_with(is_production=True) is False)
    check("keyless _send_email still returns True in dev",
          _send_with(is_production=False) is True)


def test_failed_send_leaves_change_unalerted():
    """The whole point: a keyless production send must not burn the change."""
    from app import alerts, main
    from app.models import ChangeEvent

    change = ChangeEvent(url_id=1, new_hash="a" * 64,
                         diff_summary="price moved", alerted=False)

    class _U:
        email = "customer@example.com"

    class _M:
        label = "Competitor pricing"
        url = "https://example.com/pricing"

    real = (alerts.RESEND_API_KEY, alerts.IS_PRODUCTION, main.send_change_alert)
    alerts.RESEND_API_KEY, alerts.IS_PRODUCTION = "", True
    main.send_change_alert = alerts.send_change_alert
    try:
        sent = asyncio.run(main._deliver_change_alert(change, _M(), _U(), {}))
    finally:
        (alerts.RESEND_API_KEY, alerts.IS_PRODUCTION, main.send_change_alert) = real

    check("_deliver_change_alert reports the send failed", sent is False)
    check("the change is NOT marked alerted", change.alerted is False)
    check("an attempt was recorded, so the retry sweep picks it up",
          change.alert_attempts == 1, f"attempts={change.alert_attempts}")


if __name__ == "__main__":
    for fn in (test_production_without_resend_key_refuses_to_boot,
               test_production_with_resend_key_boots,
               test_development_without_resend_key_still_boots,
               test_keyless_send_reports_failure_in_production,
               test_failed_send_leaves_change_unalerted):
        print(f"\n{fn.__name__}")
        fn()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    sys.exit(1 if FAIL else 0)
