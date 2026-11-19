#!/usr/bin/env bash
set -euo pipefail

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw --force enable
ufw status verbose
