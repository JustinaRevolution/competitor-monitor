# AGENTS.md — PriceGazer

Cross-agent context file (read by Claude Code, Codex, OpenCode, and any coding agent). Read this at session start before touching code.

## What this is

PriceGazer: a $19/month SaaS that watches competitor pricing pages and emails you when they change. One problem, one tool.

- Stack: FastAPI (Python) + SQLite + Stripe billing + Resend email. APScheduler for the monitor sweep. Jinja2 templates, no JS framework.
- Production: DigitalOcean VPS 157.245.128.60, systemd service `competitor-monitor`, nginx + Let's Encrypt TLS, live at https://pricegazer.com
- The server copy is NOT a git checkout — deploy by pushing files (below).

## House doctrine (applies to everything you write here)

1. Version control everything. Small, single-purpose commits; messages say what and why. Never commit secrets.
2. Small slices, ship often. One vertical slice at a time.
3. Tests prove it works. "Done" means proven. Every bug fix adds a regression test. Red build = nothing ships.
4. Keep it simple. YAGNI, KISS, DRY, orthogonality. Working over perfect.
5. Fail loudly, fail safely. Never swallow exceptions. Fail fast at startup (the app already refuses to start without required config — keep it that way). Logs say something.
6. Security by default. Secrets in .env, never in repo. Validate all input. OWASP awareness. TLS is already in prod — don't break it.
7. Reproducible builds and deploys. Config from env (.env.example is the contract). Pinned deps in requirements.txt.
8. Data is sacred. The production DB has real users. Backups run daily 02:30 (server cron → backup.sh, 14-day rotation, restore tested 2026-08-20). Never break the backup path.
9. Review before it ships. Read your own diff. Small changes.
10. Debt is tracked, not hidden. Log hacks in DEBT.md with a plan.

## Commands

```bash
# Install
python3 -m venv venv && venv/bin/pip install -r requirements.txt -r requirements-dev.txt

# Run dev server (http://localhost:8000)
venv/bin/uvicorn app.main:app --reload

# Run tests (85 passing as of 2026-08-20 — keep it green)
venv/bin/python -m pytest tests/ -q

# Deploy to production (from a machine with this repo)
scp -r app deploy requirements.txt stripe_watchdog.py root@157.245.128.60:/opt/competitor-monitor/
ssh root@157.245.128.60 'systemctl restart competitor-monitor'

# Server-side ops
ssh root@157.245.128.60 'journalctl -u competitor-monitor -f'   # logs
ssh root@157.245.128.60 '/opt/competitor-monitor/backup.sh'      # manual backup
```

## Structure

```
app/
  main.py       # FastAPI app + all routes
  models.py     # DB models (User, MonitoredUrl, ChangeEvent, referrals)
  monitor.py    # Core engine: fetch → hash → diff → detect changes
  alerts.py     # Email via Resend
  config.py     # Config from .env, fail-fast validation
  security.py   # Password hashing, rate limiting
  templates/    # Jinja2 HTML
  static/       # CSS
deploy/setup.sh # One-command fresh-VPS bootstrap
tests/          # pytest suite
DEBT.md         # Known technical debt (tracked, not hidden)
stripe_watchdog.py  # Ops watchdog on the server (payment + health signals)
```

## Standards

- Python: 4-space indent, type hints on public functions, docstrings where non-obvious.
- Tests: pytest, files named test_*.py in tests/. Auth flows and payment flows are the critical paths — changes there need tests.
- Config: every new config key goes in .env.example with a comment, and config.py's fail-fast checks.
- Security: never weaken the startup guards (STRIPE_WEBHOOK_SECRET, RESEND_API_KEY, SECRET_KEY length). Input validation on every route that takes user input.

## Pre-ship gate

Before any commit that touches behavior:
- [ ] Tests green (venv/bin/python -m pytest tests/ -q)
- [ ] No secrets in the diff
- [ ] No swallowed exceptions added
- [ ] Migration-safe: existing data rows survive (SQLite)
- [ ] README/DEBT.md updated if the change affects them
- [ ] Diff read top to bottom
