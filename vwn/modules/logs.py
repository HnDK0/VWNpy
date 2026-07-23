"""Logs: clear, logrotate, SSL auto-renew, auto-clear cron."""

import os
import time

from vwn.core import shell

LOG_FILES = [
    "/var/log/xray/access.log", "/var/log/xray/error.log",
    "/var/log/xray/reality-error.log", "/var/log/nginx/access.log",
    "/var/log/nginx/error.log", "/var/log/psiphon/psiphon.log",
    "/var/log/tor/notices.log", "/var/log/acme_cron.log",
]

_LOGROTATE_CONF = "/etc/logrotate.d/xray"
_SSL_CRON = "/etc/cron.d/acme-renew"
_CLEAR_SCRIPT = "/usr/local/bin/clear-logs.sh"
_CLEAR_CRON = "/etc/cron.d/clear-logs"


def clear() -> dict:
    total_before = 0
    for f in LOG_FILES:
        if os.path.isfile(f):
            total_before += os.path.getsize(f)
            with open(f, "w"):
                pass
    shell.run(["journalctl", "--vacuum-size=50M"], check=False)
    shell.run(["journalctl", "--vacuum-time=7d"], check=False)
    total_after = 0
    for f in LOG_FILES:
        if os.path.isfile(f):
            total_after += os.path.getsize(f)
    freed_kb = (total_before - total_after) // 1024
    return {"freed_kb": freed_kb}


def setup_logrotate() -> None:
    cfg = (
        "/var/log/xray/*.log {\n"
        "    daily\n    rotate 7\n    missingok\n    notifempty\n"
        "    compress\n    delaycompress\n    dateext\n"
        "    sharedscripts\n"
        "    postrotate\n"
        "        systemctl kill -s USR1 xray || true\n"
        "        systemctl kill -s USR1 xray-reality || true\n"
        "    endscript\n"
        "}\n\n"
        "/var/log/nginx/*.log {\n"
        "    daily\n    rotate 7\n    missingok\n    notifempty\n"
        "    compress\n    delaycompress\n    dateext\n"
        "    sharedscripts\n"
        "    postrotate\n"
        "        systemctl reload nginx || true\n"
        "    endscript\n"
        "}\n\n"
        "/var/log/psiphon/*.log /var/log/tor/*.log {\n"
        "    weekly\n    rotate 4\n    missingok\n    notifempty\n"
        "    compress\n    delaycompress\n"
        "}\n"
    )
    with open(_LOGROTATE_CONF, "w") as f:
        f.write(cfg)


def logrotate_status() -> bool:
    return os.path.isfile(_LOGROTATE_CONF)


def setup_ssl_cron() -> None:
    cron = (
        "# SSL auto-renew — every 35 days at 03:00\n"
        "0 3 */35 * * root "
        "/root/.acme.sh/acme.sh --cron --home /root/.acme.sh "
        "--pre-hook \"/usr/local/bin/vwn open-80\" "
        "--post-hook \"/usr/local/bin/vwn close-80\" "
        ">> /var/log/acme_cron.log 2>&1\n"
    )
    with open(_SSL_CRON, "w") as f:
        f.write(cron)
    os.chmod(_SSL_CRON, 0o644)


def remove_ssl_cron() -> None:
    if os.path.isfile(_SSL_CRON):
        os.remove(_SSL_CRON)


def ssl_cron_status() -> bool:
    return os.path.isfile(_SSL_CRON)


def setup_clear_cron() -> None:
    script = "#!/bin/bash\n"
    for f in LOG_FILES:
        script += f'[ -f "{f}" ] && : > "{f}"\n'
    script += (
        "journalctl --vacuum-size=50M\n"
        "journalctl --vacuum-time=7d\n"
    )
    with open(_CLEAR_SCRIPT, "w") as f:
        f.write(script)
    os.chmod(_CLEAR_SCRIPT, 0o755)

    cron = (
        "# Auto-clear logs — every Sunday at 04:00\n"
        "0 4 * * 0 root /usr/local/bin/clear-logs.sh\n"
    )
    with open(_CLEAR_CRON, "w") as f:
        f.write(cron)
    os.chmod(_CLEAR_CRON, 0o644)


def remove_clear_cron() -> None:
    for f in [_CLEAR_CRON, _CLEAR_SCRIPT]:
        if os.path.isfile(f):
            os.remove(f)


def clear_cron_status() -> bool:
    return os.path.isfile(_CLEAR_CRON)
