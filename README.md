# PriceGazer

A simple SaaS that watches competitor pricing pages and alerts you when they change.

$19/month. One problem. One tool.

## Quick Start (Development)

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://localhost:8000

In dev mode (no Stripe key), users are activated immediately on signup.

## Deployment (One Command)

On a fresh Ubuntu 22.04/24.04 VPS:

```bash
sudo apt update && sudo apt install -y git
git clone <repo-url> competitor-monitor
cd competitor-monitor
sudo bash deploy/setup.sh
```

The script will ask for:
- Domain name (e.g., pricegazer.com)
- Resend API key (resend.com — free tier: 3,000 emails/month)
- Stripe keys (stripe.com)
- Email for SSL notifications

The server copy is NOT a git checkout. To update a deployed instance, push the
app files from your local repo (or any machine with this repo):

```bash
scp -r app deploy requirements.txt stripe_watchdog.py root@<vps-ip>:/opt/competitor-monitor/
ssh root@<vps-ip> 'systemctl restart competitor-monitor'
```

(The README's older "git pull" update path only works if the server copy was
cloned with git; the current deploy script copies files instead.)

## Architecture

```
User visits https://pricegazer.com
  → FastAPI backend (Python)
  → SQLite database (zero infra)
  → Monitors competitor URLs on schedule
  → Sends email alerts on change via Resend
  → Stripe for billing
```

## Costs to Run

| Item | Cost | Notes |
|------|------|-------|
| Domain (pricegazer.com) | $17.29/yr | NameSilo, flat pricing |
| VPS hosting | $3-5/mo | InterServer, Hetzner, or DigitalOcean |
| Email (Resend) | $0/mo | 3,000 emails/month free |
| Stripe fees | 2.9% + $0.30 | Per-transaction |

**Break-even: 1 customer at $19/month covers everything.**

## Project Structure

```
app/
  main.py          # FastAPI app + routes
  models.py        # Database models (User, MonitoredUrl, ChangeEvent)
  monitor.py       # Core engine: fetch → hash → diff → detect changes
  alerts.py        # Email alerts via Resend
  config.py        # Configuration from .env
  templates/       # Jinja2 HTML templates
  static/          # CSS
deploy/
  setup.sh         # One-command deployment script
data/              # SQLite database (created at runtime)
```

## Tech Stack

- **Backend:** Python + FastAPI
- **Database:** SQLite (no server process needed)
- **Templates:** Jinja2 (no JS framework)
- **Email:** Resend API
- **Billing:** Stripe
- **Scheduler:** APScheduler (in-process)
- **Content diffing:** BeautifulSoup + difflib
