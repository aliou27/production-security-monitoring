#!/usr/bin/env bash
set -euo pipefail

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 51820/udp
ufw allow in on wg0 to any port 1514,1515 proto tcp
ufw --force enable
ufw status verbose
