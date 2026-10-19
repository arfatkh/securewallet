#!/usr/bin/env bash
# Pull the latest code from GitHub and redeploy. Data and certificates are kept.
set -euo pipefail
cd "$(dirname "$0")/.."
git pull --ff-only
sudo docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
