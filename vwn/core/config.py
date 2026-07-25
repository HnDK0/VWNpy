"""Единый источник путей и CRUD для vwn.conf."""

import base64
import os
import re

XRAY_DIR = "/usr/local/etc/xray"
XRAY_BIN = "/usr/local/bin/xray"

def vwn_conf_path() -> str:
    return os.path.join(XRAY_DIR, "vwn.conf")

VWN_LIB = "/usr/local/lib/vwn"
CONFIG_DIR = os.path.join(VWN_LIB, "config")
NGINX_CONF_DIR = "/etc/nginx/conf.d"
NGINX_LOOPBACK_CONF = os.path.join(NGINX_CONF_DIR, "xray.conf")
NGINX_MAIN_CONF = "/etc/nginx/nginx.conf"
SYSTEMD_DIR = "/etc/systemd/system"
CERT_DIR = "/etc/nginx/cert"

def connect_host_file_path() -> str:
    return os.path.join(XRAY_DIR, "connect_host")

# Внутренние порты (loopback, в UFW не идут)
NGINX_LOOPBACK_PORT = 8443
XRAY_WS_PORT = 50001
XRAY_XHTTP_PORT = 50002
REALITY_PUBLIC_PORT = 443

KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_B64_PREFIX = "@b64:"


def vwn_conf_get(key: str) -> "str | None":
    """Прочитать значение из vwn.conf (с декодом @b64)."""
    if not os.path.isfile(vwn_conf_path()):
        return None
    with open(vwn_conf_path(), encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k == key:
                v = v.strip()
                if v.startswith(_B64_PREFIX):
                    try:
                        return base64.b64decode(v[len(_B64_PREFIX):]).decode("utf-8")
                    except Exception:
                        return v[len(_B64_PREFIX):]
                return v
    return None


def vwn_conf_set(key: str, value: str) -> None:
    """Записать/обновить значение в vwn.conf. Небезопасные значения кодируются в @b64."""
    if not KEY_RE.match(key):
        raise ValueError(f"Недопустимый ключ: {key}")
    value = "" if value is None else str(value)
    safe = value
    if re.search(r"[^a-zA-Z0-9_=.,:@%/\-]", value):
        safe = _B64_PREFIX + base64.b64encode(value.encode("utf-8")).decode("ascii")

    os.makedirs(os.path.dirname(vwn_conf_path()), exist_ok=True)
    lines = []
    found = False
    if os.path.isfile(vwn_conf_path()):
        with open(vwn_conf_path(), encoding="utf-8") as fh:
            for raw in fh:
                line = raw.rstrip("\n")
                if line.split("=", 1)[0] == key:
                    lines.append(f"{key}={safe}")
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append(f"{key}={safe}")

    tmp = f"{vwn_conf_path()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, vwn_conf_path())
    os.chmod(vwn_conf_path(), 0o600)


def vwn_conf_del(key: str) -> None:
    """Удалить ключ из vwn.conf."""
    if not os.path.isfile(vwn_conf_path()):
        return
    lines = []
    with open(vwn_conf_path(), encoding="utf-8") as fh:
        for raw in fh:
            if raw.rstrip("\n").split("=", 1)[0] == key:
                continue
            lines.append(raw.rstrip("\n"))
    tmp = f"{vwn_conf_path()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(tmp, vwn_conf_path())
