#!/usr/bin/env bash
# One-time setup on a fresh Ubuntu 22.04/24.04 VM (Azure, or any cloud). Run from the
# repository folder:   bash deploy/setup.sh securewallet.uaenorth.cloudapp.azure.com
# Re-running it is safe: it keeps the existing .env (and so the existing passwords).
set -euo pipefail
DOMAIN="${1:?usage: bash deploy/setup.sh <your-domain>}"
cd "$(dirname "$0")/.."

# 1. Docker Engine + Compose plugin (official convenience script)
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
fi

# 2. Swap, so the front-end build fits on a 1 GB VM
if ! swapon --show | grep -q /swapfile; then
  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi

# 3. .env with fresh random database passwords (never committed to git)
if [ ! -f .env ]; then
  pw() { openssl rand -base64 33 | tr -d '/+=' | cut -c1-32; }
  umask 077
  cat > .env <<ENV
POSTGRES_PASSWORD=$(pw)
OWNER_DB_PASSWORD=$(pw)
APP_DB_PASSWORD=$(pw)
DOMAIN=$DOMAIN
DEMO_MODE=true
SESSION_IDLE_SECONDS=300
ENV
  echo "Wrote .env with new random passwords."
else
  sed -i "s/^DOMAIN=.*/DOMAIN=$DOMAIN/" .env
  grep -q '^DOMAIN=' .env || echo "DOMAIN=$DOMAIN" >> .env
fi

# 4. Firewall on the VM itself: SSH + web only
if command -v ufw >/dev/null; then
  sudo ufw allow OpenSSH >/dev/null && sudo ufw allow 80/tcp >/dev/null && sudo ufw allow 443 >/dev/null
  sudo ufw --force enable >/dev/null
fi

# 5. Build and start
sudo docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
echo
echo "Done. Open https://$DOMAIN (the certificate can take a minute on first start)."
