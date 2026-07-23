"""Генерация конфигов Xray (Reality / WS / XHTTP) и loopback-nginx.

Архитектура (план §2): 443 → Xray(Reality) → fallback 127.0.0.1:8443 (nginx)
→ location /ws → Xray(WS) :50001, /xhttp (grpc) → Xray(XHTTP) :50002.

Настройки максимально близки к боевым шаблонам оригинального VWN
(sockopt BBR, routeOnly-sniffing, dns, outbounds туннелей, блокировки
mail/bt/private, policy). Каждый протокол — отдельный конфиг-файл.
"""

import json
import os
import secrets
import urllib.parse
import uuid

from vwn.core import config, render, shell, system
from vwn.core.validate import validate_domain, validate_url

_SNIFFING = {
    "enabled": True,
    "destOverride": ["http", "tls"],
    "routeOnly": True,
}


def _sockopt() -> dict:
    return {
        "tcpFastOpen": True,
        "tcpKeepAliveIdle": 60,
        "tcpKeepAliveInterval": 10,
        "tcpCongestion": "bbr",
    }


def _dns() -> dict:
    return {"servers": ["127.0.0.53", "1.1.1.1"], "queryStrategy": "UseIPv4"}


def _outbounds() -> list:
    return [
        {"tag": "dns-out", "protocol": "dns"},
        {"tag": "free", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
        {"tag": "warp", "protocol": "socks",
         "settings": {"servers": [{"address": "127.0.0.1", "port": 40000}]}},
        {"tag": "psiphon", "protocol": "socks",
         "settings": {"servers": [{"address": "127.0.0.1", "port": 40002}]}},
        {"tag": "tor", "protocol": "socks",
         "settings": {"servers": [{"address": "127.0.0.1", "port": 40003}]}},
        {"tag": "block", "protocol": "blackhole"},
    ]


def _routing_base() -> dict:
    return {
        "domainStrategy": "AsIs",
        "rules": [
            {"type": "field", "ip": ["127.0.0.53"], "outboundTag": "dns-out"},
            {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "port": "25, 587, 465, 2525", "network": "tcp",
             "outboundTag": "block"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
            {"type": "field", "port": "0-65535", "outboundTag": "free"},
        ],
    }


def _policy(conn_idle: int = 3600) -> dict:
    return {"levels": {"0": {
        "handshake": 8, "connIdle": conn_idle, "uplinkOnly": 3,
        "downlinkOnly": 5, "bufferSize": 512,
    }}}


def _log(error_path: str) -> dict:
    return {"loglevel": "warning", "error": error_path}


def generate_uuid() -> str:
    return str(uuid.uuid4())


def generate_short_id() -> str:
    return secrets.token_hex(8)


def generate_reality_keypair() -> "tuple[str, str]":
    """Сгенерировать (private, public) через `xray x25519`."""
    r = shell.run([config.XRAY_BIN, "x25519"], capture=True)
    priv = pub = None
    for line in (r.stdout or "").splitlines():
        # Старые/новые версии xray выводят по-разному:
        #   "Private key:" / "Public key:"   либо
        #   "PrivateKey:" / "Password (PublicKey):"
        if line.startswith("Private key:") or line.startswith("PrivateKey:"):
            priv = line.split(":", 1)[1].strip()
        elif line.startswith("Public key:") or line.startswith("Password (PublicKey):"):
            pub = line.split(":", 1)[1].strip()
    if not priv or not pub:
        raise RuntimeError("Не удалось сгенерировать Reality-ключи (xray недоступен)")
    return priv, pub


def reality_config(uuid: str, dest: str, server_name: str,
                   private_key: str, short_id: str,
                   port: int = config.REALITY_PUBLIC_PORT,
                   fallback_port: int = config.NGINX_LOOPBACK_PORT) -> dict:
    """Reality на 443 публично, fallback (dest) → nginx на localhost:fallback_port."""
    return {
        "log": _log("/var/log/xray/reality-error.log"),
        "dns": _dns(),
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id": uuid, "flow": "xtls-rprx-vision", "email": "default",
                    "minClientVer": "1.0.0", "maxClientVer": "99.99.99",
                }],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": f"127.0.0.1:{fallback_port}",
                    "xver": 0,
                    "serverNames": [server_name],
                    "privateKey": private_key,
                    "shortIds": [short_id],
                },
                "sockopt": _sockopt(),
            },
            "sniffing": _SNIFFING,
            "tag": "reality-inbound",
        }],
        "outbounds": _outbounds(),
        "routing": _routing_base(),
        "policy": _policy(conn_idle=300),
    }


def ws_config(uuid: str, port: int, ws_path: str, domain: str) -> dict:
    return {
        "log": _log("/var/log/xray/error.log"),
        "dns": _dns(),
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": uuid, "level": 0}], "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": ws_path, "host": domain},
                "sockopt": _sockopt(),
            },
            "sniffing": _SNIFFING,
            "tag": "ws-inbound",
        }],
        "outbounds": _outbounds(),
        "routing": _routing_base(),
        "policy": _policy(),
    }


def xhttp_config(uuid: str, port: int, xhttp_path: str, domain: str,
                 mode: str = "auto") -> dict:
    # Только gRPC-вариант (по решению): mode=auto + nginx grpc_pass.
    return {
        "log": _log("/var/log/xray/error.log"),
        "dns": _dns(),
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": uuid, "level": 0}], "decryption": "none"},
            "streamSettings": {
                "network": "xhttp",
                "security": "none",
                "xhttpSettings": {"path": xhttp_path, "mode": mode},
                "sockopt": _sockopt(),
            },
            "sniffing": _SNIFFING,
            "tag": "xhttp-inbound",
        }],
        "outbounds": _outbounds(),
        "routing": _routing_base(),
        "policy": _policy(),
    }


def _write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def write_reality_config(path: str, *a, **kw) -> None:
    _write_json(path, reality_config(*a, **kw))


def write_ws_config(path: str, *a, **kw) -> None:
    _write_json(path, ws_config(*a, **kw))


def write_xhttp_config(path: str, *a, **kw) -> None:
    _write_json(path, xhttp_config(*a, **kw))


# ── Reality management helpers ──────────────────────────────────────

def _read_json(path: str) -> dict | None:
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def read_reality_info(path: str | None = None) -> dict | None:
    cfg = _read_json(path or os.path.join(config.XRAY_DIR, "xray-reality.json"))
    if cfg is None:
        return None
    ib = cfg.get("inbounds", [{}])[0]
    ss = ib.get("streamSettings", {})
    rs = ss.get("realitySettings", {})
    mode = config.vwn_conf_get("REALITY_MODE") or "tcp"
    info = {
        "port": ib.get("port"),
        "dest": rs.get("dest", ""),
        "server_name": (rs.get("serverNames") or [""])[0],
        "uuid": (ib.get("settings", {}).get("clients") or [{}])[0].get("id", ""),
        "short_id": (rs.get("shortIds") or [""])[0],
        "private_key": rs.get("privateKey", ""),
        "pub_key": config.vwn_conf_get("REALITY_PUBKEY") or "",
        "mode": mode,
    }
    if mode == "xhttp":
        info["xhttp_path"] = config.vwn_conf_get("REALITY_XHTTP_PATH") or "/r"
        info["xhttp_mode"] = config.vwn_conf_get("REALITY_XHTTP_MODE") or "auto"
    return info


def update_reality_port(port: int) -> None:
    path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    cfg = _read_json(path)
    if cfg is None:
        raise RuntimeError("Reality не установлен")
    old = cfg["inbounds"][0]["port"]
    cfg["inbounds"][0]["port"] = port
    _write_json(path, cfg)
    shell.run(["ufw", "delete", "allow", f"{old}/tcp"], check=False)
    shell.run(["ufw", "allow", f"{port}/tcp"], check=False)
    config.vwn_conf_set("REALITY_PORT", str(port))
    shell.run(["systemctl", "restart", "xray-reality"], check=False)


def update_reality_dest(dest: str) -> None:
    path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    cfg = _read_json(path)
    if cfg is None:
        raise RuntimeError("Reality не установлен")
    host = dest.split(":", 1)[0]
    ib = cfg["inbounds"][0]
    ib["streamSettings"]["realitySettings"]["dest"] = dest
    ib["streamSettings"]["realitySettings"]["serverNames"] = [host]
    _write_json(path, cfg)
    config.vwn_conf_set("REALITY_DEST", dest)
    shell.run(["systemctl", "restart", "xray-reality"], check=False)


def set_reality_mode(mode: str, xhttp_path: str | None = None,
                     xhttp_mode: str | None = None) -> None:
    path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    cfg = _read_json(path)
    if cfg is None:
        raise RuntimeError("Reality не установлен")
    ib = cfg["inbounds"][0]
    ss = ib.setdefault("streamSettings", {})
    if mode == "xhttp":
        p = xhttp_path or config.vwn_conf_get("REALITY_XHTTP_PATH") or "/r"
        xm = xhttp_mode or config.vwn_conf_get("REALITY_XHTTP_MODE") or "auto"
        ss["network"] = "xhttp"
        ss["xhttpSettings"] = {"path": p, "mode": xm}
        ss.pop("sockopt", None)
        for c in ib.get("settings", {}).get("clients", []):
            c.pop("flow", None)
        config.vwn_conf_set("REALITY_MODE", "xhttp")
        config.vwn_conf_set("REALITY_XHTTP_PATH", p)
        config.vwn_conf_set("REALITY_XHTTP_MODE", xm)
    else:
        ss["network"] = "tcp"
        ss.pop("xhttpSettings", None)
        ss["sockopt"] = {
            "tcpFastOpen": True,
            "tcpKeepAliveIdle": 60,
            "tcpKeepAliveInterval": 10,
            "tcpCongestion": "bbr",
        }
        clients = ib.get("settings", {}).get("clients", [])
        if clients:
            clients[0]["flow"] = "xtls-rprx-vision"
        config.vwn_conf_set("REALITY_MODE", "tcp")
    _write_json(path, cfg)
    shell.run(["systemctl", "restart", "xray-reality"], check=False)


def remove_reality() -> None:
    cfg = _read_json(os.path.join(config.XRAY_DIR, "xray-reality.json"))
    if cfg:
        port = cfg["inbounds"][0].get("port")
        if port:
            shell.run(["ufw", "delete", "allow", f"{port}/tcp"], check=False)
    shell.run(["systemctl", "stop", "xray-reality"], check=False)
    shell.run(["systemctl", "disable", "xray-reality"], check=False)
    for f in [os.path.join(config.XRAY_DIR, "xray-reality.json"),
              "/usr/local/etc/xray/reality_client.txt",
              "/etc/systemd/system/xray-reality.service"]:
        if os.path.isfile(f):
            os.remove(f)
    for k in ["REALITY_MODE", "REALITY_XHTTP_PATH", "REALITY_XHTTP_MODE",
              "REALITY_PORT", "REALITY_DEST", "REALITY_PUBKEY", "REALITY_SHORT_ID"]:
        config.vwn_conf_del(k)
    shell.run(["systemctl", "daemon-reload"], check=False)


def set_xhttp_mode(mode: str) -> None:
    path = os.path.join(config.XRAY_DIR, "xhttp.json")
    cfg = _read_json(path)
    if cfg is None:
        raise RuntimeError("XHTTP не установлен")
    ib = cfg.get("inbounds", [{}])[0]
    ss = ib.setdefault("streamSettings", {})
    xhs = ss.setdefault("xhttpSettings", {})
    xhs["mode"] = mode
    _write_json(path, cfg)
    config.vwn_conf_set("XHTTP_MODE", mode)
    shell.run(["systemctl", "restart", "xray-xhttp"], check=False)


def write_nginx_loopback_config(template: str, output: str, **kw) -> None:
    os.makedirs(os.path.dirname(output), exist_ok=True)
    render.render_config(template, output, kw)


# Unit-шаблон (по образцу оригинала, reality.sh:279-297): отдельный процесс
# на каждый inbound, чтобы TUI мог стартовать/стопать их независимо.
_UNIT_TPL = """[Unit]
Description={desc}
After=network.target nss-lookup.target

[Service]
User=xray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart={xray_bin} run -config {config_path}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
"""


def write_xray_units(units_dir: "str | None" = None,
                     xray_bin: "str | None" = None,
                     config_dir: "str | None" = None) -> "list[str]":
    """Создать 3 unit-файла: reality (443), ws (50001), xhttp-grpc (50002).

    Пути берутся из config.* внутри функции (не в дефолтах), чтобы
    монkeypatch в тестах работал корректно.
    """
    units_dir = units_dir or config.SYSTEMD_DIR
    xray_bin = xray_bin or config.XRAY_BIN
    config_dir = config_dir or config.XRAY_DIR
    specs = [
        ("xray-reality.service", "Xray Reality Service",
         os.path.join(config_dir, "xray-reality.json")),
        ("xray-ws.service", "Xray WS Service",
         os.path.join(config_dir, "config.json")),
        ("xray-xhttp.service", "Xray XHTTP-gRPC Service",
         os.path.join(config_dir, "xhttp.json")),
    ]
    written = []
    os.makedirs(units_dir, exist_ok=True)
    for name, desc, cfg in specs:
        content = _UNIT_TPL.format(desc=desc, xray_bin=xray_bin,
                                   config_path=cfg)
        path = os.path.join(units_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        written.append(path)
    return written


def provision_configs(domain: str, stub: str, reality_dest: str,
                      reality_port: int = config.REALITY_PUBLIC_PORT,
                      xhttp_mode: str = "auto",
                      private_key: "str | None" = None,
                      server_name: "str | None" = None) -> dict:
    """Сгенерировать ВСЕ конфиги сразу (полные, см. план §2).

    Возвращает словарь с параметрами (uuid, пути), сохранёнными в vwn.conf.
    """
    validate_domain(domain)
    validate_url(stub)

    os.makedirs(config.XRAY_DIR, exist_ok=True)
    uuid_ = generate_uuid()
    ws_path = system.generate_random_path()
    xhttp_path = system.generate_random_path()
    short_id = generate_short_id()

    if private_key:
        priv = private_key
        pub = config.vwn_conf_get("REALITY_PUBKEY") or "unknown"
    else:
        priv, pub = generate_reality_keypair()
    # Reality: serverNames (и клиентский SNI) ДОЛЖНЫ совпадать с dest-хостом,
    # иначе сервер проксирует ClientHello не туда и handshake рвётся.
    sname = server_name or reality_dest.split(":", 1)[0]
    proxy_host = urllib.parse.urlparse(stub).netloc or domain

    write_reality_config(os.path.join(config.XRAY_DIR, "xray-reality.json"),
                         uuid_, reality_dest, sname, priv, short_id,
                         port=reality_port)
    write_ws_config(os.path.join(config.XRAY_DIR, "config.json"),
                    uuid_, config.XRAY_WS_PORT, ws_path, domain)
    write_xhttp_config(os.path.join(config.XRAY_DIR, "xhttp.json"),
                       uuid_, config.XRAY_XHTTP_PORT, xhttp_path, domain,
                       mode=xhttp_mode)

    tpl = os.path.join(os.path.dirname(__file__), "..", "data", "nginx_loopback.conf")
    write_nginx_loopback_config(
        tpl, config.NGINX_LOOPBACK_CONF,
        NGINX_LOOPBACK_PORT=config.NGINX_LOOPBACK_PORT, DOMAIN=domain, STUB=stub,
        PROXY_HOST=proxy_host, WS_PATH=ws_path, XHTTP_PATH=xhttp_path,
        XRAY_WS_PORT=config.XRAY_WS_PORT, XRAY_XHTTP_PORT=config.XRAY_XHTTP_PORT,
    )

    config.vwn_conf_set("DOMAIN", domain)
    config.vwn_conf_set("STUB_URL", stub)
    config.vwn_conf_set("UUID", uuid_)
    config.vwn_conf_set("WS_PATH", ws_path)
    config.vwn_conf_set("XHTTP_PATH", xhttp_path)
    config.vwn_conf_set("REALITY_DEST", reality_dest)
    config.vwn_conf_set("REALITY_PORT", str(reality_port))
    config.vwn_conf_set("XHTTP_MODE", xhttp_mode)
    config.vwn_conf_set("REALITY_PUBKEY", pub)
    config.vwn_conf_set("SHORT_ID", short_id)

    units = write_xray_units()
    return {
        "uuid": uuid_, "ws_path": ws_path, "xhttp_path": xhttp_path,
        "reality_port": reality_port, "short_id": short_id,
        "units": units,
    }


# ── WS / XHTTP management ──────────────────────────────────────────

def _re_render_nginx(**overrides) -> None:
    from urllib.parse import urlparse
    tpl = os.path.join(os.path.dirname(__file__), "..", "data", "nginx_loopback.conf")
    domain = overrides.get("domain") or config.vwn_conf_get("DOMAIN") or "example.com"
    stub = overrides.get("stub") or config.vwn_conf_get("STUB_URL") or "https://example.com"
    ws_path = overrides.get("ws_path") or config.vwn_conf_get("WS_PATH") or "/ws"
    xhttp_path = overrides.get("xhttp_path") or config.vwn_conf_get("XHTTP_PATH") or "/xhttp"
    proxy_host = overrides.get("proxy_host") or urlparse(stub).netloc or domain
    write_nginx_loopback_config(
        tpl, config.NGINX_LOOPBACK_CONF,
        NGINX_LOOPBACK_PORT=config.NGINX_LOOPBACK_PORT, DOMAIN=domain, STUB=stub,
        PROXY_HOST=proxy_host, WS_PATH=ws_path, XHTTP_PATH=xhttp_path,
        XRAY_WS_PORT=config.XRAY_WS_PORT, XRAY_XHTTP_PORT=config.XRAY_XHTTP_PORT,
    )


def read_ws_xhttp_info() -> dict:
    ws_cfg = _read_json(os.path.join(config.XRAY_DIR, "config.json"))
    xh_cfg = _read_json(os.path.join(config.XRAY_DIR, "xhttp.json"))
    info = {
        "domain": config.vwn_conf_get("DOMAIN") or "",
        "stub_url": config.vwn_conf_get("STUB_URL") or "",
        "uuid": config.vwn_conf_get("UUID") or "",
        "ws_active": ws_cfg is not None,
        "xhttp_active": xh_cfg is not None,
    }
    if ws_cfg:
        ib = ws_cfg.get("inbounds", [{}])[0]
        ss = ib.get("streamSettings", {})
        info["ws_path"] = ss.get("wsSettings", {}).get("path", "")
        info["ws_port"] = ib.get("port")
    else:
        info["ws_path"] = config.vwn_conf_get("WS_PATH") or ""
    if xh_cfg:
        ib = xh_cfg.get("inbounds", [{}])[0]
        ss = ib.get("streamSettings", {})
        info["xhttp_path"] = ss.get("xhttpSettings", {}).get("path", "")
        info["xhttp_port"] = ib.get("port")
        info["xhttp_mode"] = ss.get("xhttpSettings", {}).get("mode", "auto")
    else:
        info["xhttp_path"] = config.vwn_conf_get("XHTTP_PATH") or ""
        info["xhttp_mode"] = config.vwn_conf_get("XHTTP_MODE") or "auto"
    return info


def update_uuid_all(new_uuid: str | None = None) -> str:
    """Сменить UUID первого пользователя."""
    from vwn.modules import users as usr
    usr.init_users_file()
    user_list = usr.list_users()
    if user_list:
        uuid_val = usr.rekey_user(1)
        if uuid_val:
            config.vwn_conf_set("UUID", uuid_val)
            from vwn.modules.sub import rebuild_all_sub_files
            rebuild_all_sub_files()
        return uuid_val or ""
    uuid_val = new_uuid or generate_uuid()
    config.vwn_conf_set("UUID", uuid_val)
    return uuid_val


def update_ws_path(path: str) -> None:
    p = os.path.join(config.XRAY_DIR, "config.json")
    cfg = _read_json(p)
    if cfg is None:
        raise RuntimeError("WS не установлен")
    path = "/" + path.lstrip("/")
    ib = cfg.get("inbounds", [{}])[0]
    ss = ib.setdefault("streamSettings", {})
    wss = ss.setdefault("wsSettings", {})
    wss["path"] = path
    _write_json(p, cfg)
    config.vwn_conf_set("WS_PATH", path)
    _re_render_nginx()
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    shell.run(["systemctl", "restart", "xray-ws"], check=False)
    shell.run(["systemctl", "reload", "nginx"], check=False)


def update_xhttp_path(path: str) -> None:
    p = os.path.join(config.XRAY_DIR, "xhttp.json")
    cfg = _read_json(p)
    if cfg is None:
        raise RuntimeError("XHTTP не установлен")
    path = "/" + path.lstrip("/")
    ib = cfg.get("inbounds", [{}])[0]
    ss = ib.setdefault("streamSettings", {})
    xhs = ss.setdefault("xhttpSettings", {})
    xhs["path"] = path
    _write_json(p, cfg)
    config.vwn_conf_set("XHTTP_PATH", path)
    _re_render_nginx()
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    shell.run(["systemctl", "restart", "xray-xhttp"], check=False)
    shell.run(["systemctl", "reload", "nginx"], check=False)


def update_domain(domain: str) -> None:
    config.vwn_conf_set("DOMAIN", domain)
    _re_render_nginx(domain=domain)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    shell.run(["systemctl", "reload", "nginx"], check=False)


def update_stub_url(url: str) -> None:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Неверный URL — нужен https://...")
    proxy_host = parsed.netloc
    config.vwn_conf_set("STUB_URL", url)
    _re_render_nginx(stub=url, proxy_host=proxy_host)
    shell.run(["systemctl", "reload", "nginx"], check=False)


def check_cert(domain: str) -> dict:
    import re
    from datetime import datetime
    cert = os.path.join(config.CERT_DIR, "cert.pem")
    if not os.path.isfile(cert):
        return {"valid": False, "reason": "no_cert"}
    try:
        r = shell.run(["openssl", "x509", "-in", cert, "-noout",
                        "-enddate", "-subject", "-ext", "subjectAltName"],
                       capture=True, check=False)
        if r.returncode != 0:
            return {"valid": False, "reason": "openssl_error"}
        lines = r.stdout or ""
        end_date = ""
        for line in lines.splitlines():
            if line.startswith("notAfter="):
                end_date = line.split("=", 1)[1]
        if not end_date:
            return {"valid": False, "reason": "no_enddate"}
        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            expires = datetime.strptime(end_date, fmt)
            days_left = (expires - datetime.now()).days
        except ValueError:
            return {"valid": False, "reason": "parse_error"}
        cert_domain = ""
        for line in lines.splitlines():
            if "DNS:" in line:
                m = re.search(r"DNS:([^,\s]+)", line)
                if m:
                    cert_domain = m.group(1)
                    break
        return {
            "valid": True,
            "domain": cert_domain,
            "days_left": days_left,
            "expires": end_date,
        }
    except Exception:
        return {"valid": False, "reason": "error"}


def renew_ssl(domain: str, method: str = "standalone",
              cf_email: str = "", cf_key: str = "") -> None:
    from vwn.core.cert import provision_cert
    provision_cert(domain, method=method, cf_email=cf_email, cf_key=cf_key)
    shell.run(["systemctl", "reload", "nginx"], check=False)


def remove_ws() -> None:
    shell.run(["systemctl", "stop", "xray-ws"], check=False)
    shell.run(["systemctl", "disable", "xray-ws"], check=False)
    p = os.path.join(config.XRAY_DIR, "config.json")
    if os.path.isfile(p):
        os.remove(p)
    config.vwn_conf_del("WS_PATH")
    shell.run(["systemctl", "daemon-reload"], check=False)


def remove_xhttp() -> None:
    shell.run(["systemctl", "stop", "xray-xhttp"], check=False)
    shell.run(["systemctl", "disable", "xray-xhttp"], check=False)
    p = os.path.join(config.XRAY_DIR, "xhttp.json")
    if os.path.isfile(p):
        os.remove(p)
    config.vwn_conf_del("XHTTP_PATH")
    config.vwn_conf_del("XHTTP_MODE")
    shell.run(["systemctl", "daemon-reload"], check=False)
