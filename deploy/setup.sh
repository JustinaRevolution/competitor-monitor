#!/usr/bin/env bash
# ============================================================
# PriceGazer — One-Command Deployment Script
# ============================================================
# Usage on a fresh Ubuntu 22.04/24.04 VPS:
#
#   1. SSH into your VPS
#   2. Run:
#      sudo apt update && sudo apt install -y git
#      git clone https://github.com/YOUR_USER/competitor-monitor.git
#      cd competitor-monitor
#      bash deploy/setup.sh
#
# The script will prompt you for API keys, then set everything up.
# ============================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  PriceGazer — Server Setup${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# ---- Pre-flight checks ----
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root (use sudo).${NC}"
    exit 1
fi

if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}Warning: This script is designed for Ubuntu. Proceeding anyway...${NC}"
fi

# ---- Collect configuration ----
echo -e "${GREEN}Step 1: Configuration${NC}"
echo "Enter your domain (e.g., pricegazer.com):"
read -p "> " DOMAIN_NAME

echo ""
echo "Enter your Resend API key (from resend.com):"
read -p "> " RESEND_API_KEY

echo ""
echo "Enter your Stripe Secret Key (sk_live_...):"
read -p "> " STRIPE_SECRET_KEY

echo ""
echo "Enter your Stripe Publishable Key (pk_live_...):"
read -p "> " STRIPE_PUBLISHABLE_KEY

echo ""
echo "Enter your Stripe Price ID (price_... for $19/mo product):"
read -p "> " STRIPE_PRICE_ID

echo ""
echo "Enter your Stripe Webhook Signing Secret (whsec_...):"
echo "  Stripe Dashboard → Developers → Webhooks → your https://${DOMAIN_NAME}/stripe-webhook endpoint."
echo "  Required — without it the app refuses to start and /stripe-webhook rejects every event."
read -p "> " STRIPE_WEBHOOK_SECRET

echo ""
echo "Enter your email address for Let's Encrypt SSL notifications:"
read -p "> " LETSENCRYPT_EMAIL

APP_DIR="/opt/competitor-monitor"
APP_USER="competitor"

# ---- System packages ----
echo -e "${GREEN}Step 2: Installing system packages...${NC}"
apt update
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx curl

# ---- Create app user ----
echo -e "${GREEN}Step 3: Creating app user...${NC}"
id -u $APP_USER &>/dev/null || useradd -m -s /bin/bash -d $APP_DIR $APP_USER

# ---- Set up app ----
echo -e "${GREEN}Step 4: Setting up application...${NC}"
mkdir -p $APP_DIR/data
cp -r "$(dirname "$0")/../app" $APP_DIR/app/
cp "$(dirname "$0")/../requirements.txt" $APP_DIR/
cp "$(dirname "$0")/../.env.example" $APP_DIR/.env

# Set up virtualenv
python3 -m venv $APP_DIR/venv
$APP_DIR/venv/bin/pip install -r $APP_DIR/requirements.txt

# ---- Configure .env ----
echo -e "${GREEN}Step 5: Configuring environment...${NC}"
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
cat > $APP_DIR/.env << EOF
SECRET_KEY=${SECRET_KEY}
DATABASE_URL=sqlite:///${APP_DIR}/data/monitor.db
APP_URL=https://${DOMAIN_NAME}

# Secure cookies, strict startup checks, and trust nginx's X-Forwarded-For.
APP_ENV=production

# Stripe
STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}
STRIPE_PUBLISHABLE_KEY=${STRIPE_PUBLISHABLE_KEY}
STRIPE_PRICE_ID=${STRIPE_PRICE_ID}
STRIPE_WEBHOOK_SECRET=${STRIPE_WEBHOOK_SECRET}

# Email (Resend)
RESEND_API_KEY=${RESEND_API_KEY}
FROM_EMAIL=alerts@${DOMAIN_NAME}
EOF

chown -R $APP_USER:$APP_USER $APP_DIR
chmod 600 $APP_DIR/.env

# ---- Systemd service ----
echo -e "${GREEN}Step 6: Creating systemd service...${NC}"
cat > /etc/systemd/system/competitor-monitor.service << EOF
[Unit]
Description=PriceGazer
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable competitor-monitor

# ---- Nginx ----
echo -e "${GREEN}Step 7: Configuring nginx...${NC}"
cat > /etc/nginx/sites-available/competitor-monitor << EOF
server {
    listen 80;
    server_name ${DOMAIN_NAME};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN_NAME};

    # SSL will be configured by certbot below

    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static/ {
        alias ${APP_DIR}/app/static/;
        expires 7d;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/competitor-monitor /etc/nginx/sites-enabled/

# ---- SSL ----
echo -e "${GREEN}Step 8: Setting up SSL with Let's Encrypt...${NC}"
certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos --email $LETSENCRYPT_EMAIL

# ---- Start service ----
echo -e "${GREEN}Step 9: Starting application...${NC}"
systemctl start competitor-monitor
systemctl reload nginx

# ---- Done ----
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "Your app is live at: ${BLUE}https://${DOMAIN_NAME}${NC}"
echo ""
echo -e "Useful commands:"
echo -e "  View logs:  ${YELLOW}sudo journalctl -u competitor-monitor -f${NC}"
echo -e "  Restart:    ${YELLOW}sudo systemctl restart competitor-monitor${NC}"
echo -e "  Update:     ${YELLOW}cd $APP_DIR && git pull && sudo systemctl restart competitor-monitor${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo -e "  1. Set up Stripe webhook: https://dashboard.stripe.com/webhooks"
echo -e "     Endpoint: https://${DOMAIN_NAME}/stripe-webhook"
echo -e "     Events: checkout.session.completed, customer.subscription.deleted"
echo -e "     Copy the signing secret to ${APP_DIR}/.env as STRIPE_WEBHOOK_SECRET"
echo -e "  2. Test by visiting https://${DOMAIN_NAME} and signing up"
echo ""
