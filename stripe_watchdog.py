#!/usr/bin/env python3
"""Stripe watchdog for PriceGazer + creator income streams.

Runs on the droplet (key stays here). Prints a report ONLY when something
meaningful happened since the last run; silent otherwise. State (last event
id) persists in stripe_watchdog_state.json next to this script.

Watched signals:
  - new checkout.session.completed      (someone paid / signed up)
  - invoice.payment_failed / charge.failed  (money trouble)
  - customer.subscription.created/updated/deleted  (membership changes)
  - webhook endpoint disabled           (integration broken)
  - app health endpoint down            (whole site unreachable)

Stdlib only.
"""
import base64
import datetime
import json
import os
import pathlib
import urllib.request

ENV_FILE = pathlib.Path("/opt/competitor-monitor/.env")
STATE_FILE = pathlib.Path("/opt/competitor-monitor/stripe_watchdog_state.json")
HEALTH_URL = "https://pricegazer.com/"
WATCHED_EVENTS = {
    "checkout.session.completed",
    "invoice.payment_failed",
    "charge.failed",
    "payment_intent.payment_failed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.subscription.paused",
    "customer.subscription.resumed",
}


def load_key():
    for line in ENV_FILE.read_text().splitlines():
        if line.startswith("STRIPE_SECRET_KEY="):
            return line.split("=", 1)[1].strip()
    raise SystemExit("no STRIPE_SECRET_KEY in .env")


def api(sk, path, params=""):
    url = f"https://api.stripe.com/v1{path}"
    if params:
        url += "?" + params
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{sk}:".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:300]
        return {"error": body}


def fmt_ts(ts):
    return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def main():
    sk = load_key()

    # ---- state ----
    state = {}
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            state = {}
    last_id = state.get("last_event_id", "")

    report = []
    problems = []

    # ---- app health ----
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=15) as r:
            if r.status != 200:
                problems.append(f"pricegazer.com responded HTTP {r.status}")
    except Exception as e:
        problems.append(f"pricegazer.com unreachable: {getattr(e, 'reason', e)}")

    # ---- webhook endpoint ----
    we = api(sk, "/webhook_endpoints", "limit=10")
    if "error" in we:
        problems.append(f"webhook query failed: {we['error']}")
    else:
        for w in we.get("data", []):
            if w.get("status") != "enabled":
                problems.append(f"webhook {w.get('url')} status={w.get('status')}")

    # ---- events since last check ----
    ev = api(sk, "/events", "limit=100")
    if "error" in ev:
        problems.append(f"events query failed: {ev['error']}")
    else:
        new_events = []
        for e in ev.get("data", []):
            if e["id"] == last_id:
                break
            new_events.append(e)
        new_events.reverse()  # oldest first
        for e in new_events:
            t = e.get("type", "?")
            if t in WATCHED_EVENTS:
                created = fmt_ts(e.get("created"))
                report.append(f"  {created}  {t}")
        if new_events:
            state["last_event_id"] = new_events[-1]["id"]
            STATE_FILE.write_text(json.dumps(state, indent=2))

    # ---- output ----
    if problems:
        print("STRIPE WATCHDOG — PROBLEMS")
        for p in problems:
            print(f"  ! {p}")
        if report:
            print("  recent events:")
            for r in report:
                print(r)
        return 1
    if report:
        print("STRIPE WATCHDOG — new activity since last check")
        for r in report:
            print(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
