#!/bin/bash
set -euo pipefail
# Сбросить UFW и настроить правильно (запускать через консоль хостинга)
ufw --force disable 2>/dev/null || true
ufw --force reset 2>/dev/null || true
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 443/tcp comment 'HTTPS/Reality'
ufw allow 80/tcp comment 'HTTP (acme)'
# custom SSH port, если не 22
grep -qE '^Port\s+\d+' /etc/ssh/sshd_config && grep -qE '^Port\s+(?!22)\d+' /etc/ssh/sshd_config && ufw allow "$(grep -E '^Port\s+\d+' /etc/ssh/sshd_config | awk '{print $2}')/tcp" comment 'SSH custom' || true
ufw --force enable
ufw status
