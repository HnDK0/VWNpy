"""Генерация конфигов Xray (Reality / gRPC / XHTTP) и loopback-nginx.

Архитектура (план §2): 443 → Xray(Reality) → fallback 127.0.0.1:8443 (nginx)
→ location /<serviceName> (grpc_pass) → Xray(gRPC) :50001,
/xhttp (grpc_pass) → Xray(XHTTP) :50002.

Настройки максимально близки к боевым шаблонам оригинального VWN
(sockopt BBR, routeOnly-sniffing, dns, outbounds туннелей, блокировки
mail/bt/private, policy). Каждый протокол — отдельный конфиг-файл.
"""

import json
import os
import secrets
import shutil
import urllib.parse
import uuid

from vwn.core import config, render, shell, system
from vwn.core.validate import validate_domain, validate_grpc_service, validate_url

_SNIFFING = {
    "enabled": True,
    "destOverride": ["http", "tls"],
    "routeOnly": True,
}


def _bbr_available() -> bool:
    """BBR реально доступен в ядре (иначе Xray падает на TCP_CONGESTION)."""
    p = "/proc/sys/net/ipv4/tcp_available_congestion_control"
    try:
        if "bbr" not in open(p).read().split():
            shell.run(["modprobe", "tcp_bbr"], check=False)
        return "bbr" in open(p).read().split()
    except OSError:
        return False


def _tfo_server_ok() -> bool:
    try:
        return int(open("/proc/sys/net/ipv4/tcp_fastopen").read().strip()) & 2 != 0
    except (OSError, ValueError):
        return False


def _sockopt(public: bool = True) -> dict:
    """sockopt inbound'а.

    loopback-inbound'ы (grpc/xhttp за nginx): только keepalive — TFO/BBR там
    бессмысленны. Публичный Reality: TFO/BBR только если их поддерживает ядро
    этого сервера, иначе Xray не может выставить опцию сокета.
    """
    opt = {"tcpKeepAliveIdle": 60, "tcpKeepAliveInterval": 10}
    if public:
        if _tfo_server_ok():
            opt["tcpFastOpen"] = True
        if _bbr_available():
            opt["tcpCongestion"] = "bbr"
    return opt


def _xhttp_server_settings(path: str) -> dict:
    """Серверный XHTTP всегда mode=auto: принимает stream-one/stream-up/
    packet-up. Закреплённый режим режет клиентов (auto по TLS = stream-up).
    Версионно-зависимые поля (scMax*) не пишем."""
    return {"path": path, "mode": "auto"}


def _dns() -> dict:
    """DNS конфиг для Xray. Читает выбор пользователя из vwn.conf."""
    from vwn.core import config
    v4_primary = config.vwn_conf_get("DNS_V4_PRIMARY") or "1.1.1.1"
    v4_fallback = config.vwn_conf_get("DNS_V4_FALLBACK") or "9.9.9.9"
    v6_primary = config.vwn_conf_get("DNS_V6_PRIMARY") or ""
    servers = [v4_primary, v4_fallback]
    if v6_primary:
        servers.append(v6_primary)
        query_strategy = "UseIP"
    else:
        query_strategy = "UseIPv4"
    # системный резолвер — последний шанс, если провайдер режет 1.1.1.1/9.9.9.9
    servers.append("localhost")
    return {"servers": servers, "queryStrategy": query_strategy}


def _outbounds() -> list:
    # ponytail: outbound'ы туннелей (warp/psiphon/tor) добавляются
    # модулями при установке через add_outbound(). Здесь только базовые.
    from vwn.core import config
    v6 = config.vwn_conf_get("DNS_V6_PRIMARY") or ""
    strategy = "UseIP" if v6 else "UseIPv4"
    return [
        {"tag": "dns-out", "protocol": "dns"},
        {"tag": "free", "protocol": "freedom", "settings": {"domainStrategy": strategy}},
        {"tag": "block", "protocol": "blackhole"},
    ]


def _routing_base() -> dict:
    return {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
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
        "handshake": 15, "connIdle": conn_idle, "uplinkOnly": 0,
        "downlinkOnly": 0, "bufferSize": 512,
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


def reality_config(uuid: str, server_name: str,
                   private_key: str, short_id: str,
                   port: int = config.REALITY_PUBLIC_PORT,
                   fallback_port: int = config.NGINX_LOOPBACK_PORT) -> dict:
    """Reality на 443 публично, fallback → nginx на localhost:fallback_port."""
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
                    "minClientVer": "", "maxClientVer": "",
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
                "sockopt": _sockopt(public=True),
            },
            "sniffing": _SNIFFING,
            "tag": "reality-inbound",
        }],
        "outbounds": _outbounds(),
        "routing": _routing_base(),
        "policy": _policy(conn_idle=3600),
    }


def grpc_config(uuid: str, port: int, service_name: str) -> dict:
    """VLESS+gRPC за nginx: Xray слушает h2c на loopback, TLS терминирует nginx.

    serviceName — один сегмент пути без "/" (Xray трактует имя с ведущим "/"
    как собственный путь). Клиент ходит на /<serviceName>/Tun (gun) или
    /<serviceName>/TunMulti (multi); сервер принимает оба, режим выбирает
    клиентская ссылка.
    """
    return {
        "log": _log("/var/log/xray/error.log"),
        "dns": _dns(),
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": uuid, "level": 0}], "decryption": "none"},
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {"serviceName": service_name},
                "sockopt": _sockopt(public=False),
            },
            "sniffing": _SNIFFING,
            "tag": "grpc-inbound",
        }],
        "outbounds": _outbounds(),
        "routing": _routing_base(),
        "policy": _policy(),
    }


def xhttp_config(uuid: str, port: int, xhttp_path: str, domain: str,
                 mode: str = "auto") -> dict:
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
                "xhttpSettings": _xhttp_server_settings(xhttp_path),
                "sockopt": _sockopt(public=False),
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


def write_grpc_config(path: str, *a, **kw) -> None:
    _write_json(path, grpc_config(*a, **kw))


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
        "sni": (rs.get("serverNames") or [""])[0],
        "uuid": (ib.get("settings", {}).get("clients") or [{}])[0].get("id", ""),
        "short_id": (rs.get("shortIds") or [""])[0],
        "private_key": rs.get("privateKey", ""),
        "pub_key": config.vwn_conf_get("REALITY_PUBKEY") or "",
        "mode": mode,
    }
    if mode == "xhttp":
        info["xhttp_path"] = config.vwn_conf_get("REALITY_XHTTP_PATH") or ""
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
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def update_reality_sni(dest: str) -> None:
    """Сменить домен-камуфляж (SNI). Формат: host:port (напр. microsoft.com:443).
    dest (127.0.0.1:8443) — nginx loopback — не трогает."""
    path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    cfg = _read_json(path)
    if cfg is None:
        raise RuntimeError("Reality не установлен")
    host = dest.split(":", 1)[0]
    ib = cfg["inbounds"][0]
    ib["streamSettings"]["realitySettings"]["serverNames"] = [host]
    _write_json(path, cfg)
    config.vwn_conf_set("REALITY_DEST", dest)
    shell.run(["systemctl", "restart", "xray-reality"], check=False)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def set_reality_mode(mode: str, xhttp_path: str | None = None,
                     xhttp_mode: str | None = None,
                     restart: bool = True) -> None:
    path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    cfg = _read_json(path)
    if cfg is None:
        raise RuntimeError("Reality не установлен")
    ib = cfg["inbounds"][0]
    ss = ib.setdefault("streamSettings", {})
    if mode == "xhttp":
        p = xhttp_path or config.vwn_conf_get("REALITY_XHTTP_PATH")
        if not p or p == "/r":
            p = system.generate_random_path()
        xm = xhttp_mode or config.vwn_conf_get("REALITY_XHTTP_MODE") or "auto"
        ss["network"] = "xhttp"
        ss["xhttpSettings"] = _xhttp_server_settings(p)
        ss["sockopt"] = _sockopt(public=True)
        for c in ib.get("settings", {}).get("clients", []):
            c.pop("flow", None)
        config.vwn_conf_set("REALITY_MODE", "xhttp")
        config.vwn_conf_set("REALITY_XHTTP_PATH", p)
        config.vwn_conf_set("REALITY_XHTTP_MODE", xm)
    else:
        ss["network"] = "tcp"
        ss.pop("xhttpSettings", None)
        ss["sockopt"] = _sockopt(public=True)
        for c in ib.get("settings", {}).get("clients", []):
            c["flow"] = "xtls-rprx-vision"
        config.vwn_conf_set("REALITY_MODE", "tcp")
    _write_json(path, cfg)
    if restart:
        shell.run(["systemctl", "restart", "xray-reality"], check=False)


def _add_disabled(protocol: str) -> None:
    from vwn.modules.sub import get_disabled_protocols
    disabled = get_disabled_protocols()
    disabled.add(protocol)
    config.vwn_conf_set("DISABLED_PROTOCOLS", ",".join(sorted(disabled)))


def _del_disabled(protocol: str) -> None:
    from vwn.modules.sub import get_disabled_protocols
    disabled = get_disabled_protocols()
    disabled.discard(protocol)
    if disabled:
        config.vwn_conf_set("DISABLED_PROTOCOLS", ",".join(sorted(disabled)))
    else:
        config.vwn_conf_del("DISABLED_PROTOCOLS")


# ── Миграция WebSocket → gRPC ──────────────────────────────────────

LEGACY_WS_SERVICE = "xray-ws"


def legacy_ws_present() -> bool:
    """Установка ещё на WebSocket: есть WS_PATH, юнит xray-ws или старый config.json."""
    return bool(
        config.vwn_conf_get("WS_PATH")
        or os.path.isfile(os.path.join(config.SYSTEMD_DIR, LEGACY_WS_SERVICE + ".service"))
        or os.path.isfile(os.path.join(config.XRAY_DIR, "config.json"))
        or os.path.isfile(os.path.join(config.XRAY_DIR, "config.json.disabled"))
    )


def migrate_ws_to_grpc() -> bool:
    """Перевести существующую установку с WebSocket на gRPC (идемпотентно).

    Останавливает и удаляет xray-ws, убирает старый config.json (inbound WS;
    его outbound'ы туннелей заново проставят reapply_* в rebuild), заводит
    GRPC_SERVICE, переносит флаг отключения ws→grpc, пишет юнит xray-grpc.
    WS_PATH удаляется ПОСЛЕДНИМ: при обрыве на полпути повторный запуск
    продолжит миграцию. Возвращает True, если миграция выполнялась.
    """
    if not legacy_ws_present():
        return False

    shell.run(["systemctl", "stop", LEGACY_WS_SERVICE], check=False)
    shell.run(["systemctl", "disable", LEGACY_WS_SERVICE], check=False)

    if not config.vwn_conf_get("GRPC_SERVICE"):
        config.vwn_conf_set("GRPC_SERVICE", system.generate_grpc_service())

    from vwn.modules.sub import get_disabled_protocols
    disabled = get_disabled_protocols()
    if "ws" in disabled:
        disabled.discard("ws")
        disabled.add("grpc")
        config.vwn_conf_set("DISABLED_PROTOCOLS", ",".join(sorted(disabled)))

    for name in ("config.json", "config.json.disabled"):
        p = os.path.join(config.XRAY_DIR, name)
        if os.path.isfile(p):
            os.remove(p)

    unit = os.path.join(config.SYSTEMD_DIR, LEGACY_WS_SERVICE + ".service")
    if os.path.isfile(unit):
        os.remove(unit)
    shutil.rmtree(os.path.join(config.SYSTEMD_DIR, LEGACY_WS_SERVICE + ".service.d"),
                  ignore_errors=True)

    write_xray_units()
    shell.run(["systemctl", "daemon-reload"], check=False)
    if "grpc" not in disabled:
        shell.run(["systemctl", "enable", "xray-grpc"], check=False)

    # CPU Guard включён → распространить на новый сервис (drop-in xray-ws удалён выше)
    try:
        from vwn.modules import security
        if security.cpu_guard_status():
            security.cpu_guard_enable()
    except Exception:
        pass

    config.vwn_conf_del("WS_PATH")
    return True


def disable_reality() -> None:
    shell.run(["systemctl", "stop", "xray-reality"], check=False)
    shell.run(["systemctl", "disable", "xray-reality"], check=False)
    p = os.path.join(config.XRAY_DIR, "xray-reality.json")
    if os.path.isfile(p):
        os.rename(p, p + ".disabled")
    _add_disabled("reality")
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def enable_reality() -> None:
    p = os.path.join(config.XRAY_DIR, "xray-reality.json.disabled")
    if os.path.isfile(p):
        os.rename(p, p.removesuffix(".disabled"))
    shell.run(["systemctl", "enable", "xray-reality"], check=False)
    shell.run(["systemctl", "start", "xray-reality"], check=False)
    _del_disabled("reality")
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def set_xhttp_mode(mode: str) -> None:
    """Режим XHTTP для КЛИЕНТСКИХ ссылок. Серверный inbound всегда auto,
    поэтому JSON и сервис не трогаем."""
    if _read_json(os.path.join(config.XRAY_DIR, "xhttp.json")) is None:
        raise RuntimeError("XHTTP не установлен")
    config.vwn_conf_set("XHTTP_MODE", mode)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def write_nginx_loopback_config(template: str, output: str, **kw) -> None:
    os.makedirs(os.path.dirname(output), exist_ok=True)
    # 127.0.0.53 в resolver nginx — только если там реально слушает резолвер
    kw.setdefault("RESOLVER", "127.0.0.53 1.1.1.1" if system.local_resolver_active() else "1.1.1.1 9.9.9.9")
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
    """Создать 3 unit-файла: reality (443), grpc (50001), xhttp (50002).

    Пути берутся из config.* внутри функции (не в дефолтах), чтобы
    монkeypatch в тестах работал корректно.
    """
    units_dir = units_dir or config.SYSTEMD_DIR
    xray_bin = xray_bin or config.XRAY_BIN
    config_dir = config_dir or config.XRAY_DIR
    specs = [
        ("xray-reality.service", "Xray Reality Service",
         os.path.join(config_dir, "xray-reality.json")),
        ("xray-grpc.service", "Xray gRPC Service",
         os.path.join(config_dir, "grpc.json")),
        ("xray-xhttp.service", "Xray XHTTP Service",
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
    grpc_service = system.generate_grpc_service()
    xhttp_path = system.generate_random_path()
    short_id = generate_short_id()

    if private_key:
        priv = private_key
        pub = config.vwn_conf_get("REALITY_PUBKEY") or "unknown"
    else:
        priv, pub = generate_reality_keypair()
    # Reality: serverNames (клиентский SNI) = sname (домен-камуфляж).
    sname = server_name or reality_dest.split(":", 1)[0]
    proxy_host = urllib.parse.urlparse(stub).netloc or domain

    write_reality_config(os.path.join(config.XRAY_DIR, "xray-reality.json"),
                         uuid_, sname, priv, short_id,
                         port=reality_port)
    write_grpc_config(os.path.join(config.XRAY_DIR, "grpc.json"),
                      uuid_, config.XRAY_GRPC_PORT, grpc_service)
    write_xhttp_config(os.path.join(config.XRAY_DIR, "xhttp.json"),
                       uuid_, config.XRAY_XHTTP_PORT, xhttp_path, domain,
                       mode=xhttp_mode)

    tpl = os.path.join(os.path.dirname(__file__), "..", "data", "nginx_loopback.conf")
    write_nginx_loopback_config(
        tpl, config.NGINX_LOOPBACK_CONF,
        NGINX_LOOPBACK_PORT=config.NGINX_LOOPBACK_PORT, DOMAIN=domain, STUB=stub,
        PROXY_HOST=proxy_host, GRPC_SERVICE=grpc_service, XHTTP_PATH=xhttp_path,
        XRAY_GRPC_PORT=config.XRAY_GRPC_PORT, XRAY_XHTTP_PORT=config.XRAY_XHTTP_PORT,
    )

    config.vwn_conf_set("DOMAIN", domain)
    config.vwn_conf_set("STUB_URL", stub)
    config.vwn_conf_set("UUID", uuid_)
    config.vwn_conf_set("GRPC_SERVICE", grpc_service)
    config.vwn_conf_set("XHTTP_PATH", xhttp_path)
    config.vwn_conf_set("REALITY_DEST", reality_dest)
    config.vwn_conf_set("REALITY_PORT", str(reality_port))
    config.vwn_conf_set("XHTTP_MODE", xhttp_mode)
    config.vwn_conf_set("REALITY_PUBKEY", pub)
    config.vwn_conf_set("SHORT_ID", short_id)

    units = write_xray_units()

    from vwn.modules.warp import reapply_warp
    reapply_warp()
    from vwn.modules.psiphon import reapply_routing as reapply_psiphon
    reapply_psiphon()
    from vwn.modules.tor import reapply_routing as reapply_tor
    reapply_tor()
    from vwn.modules.relay import reapply_routing as reapply_relay
    reapply_relay()

    return {
        "uuid": uuid_, "grpc_service": grpc_service, "xhttp_path": xhttp_path,
        "reality_port": reality_port, "short_id": short_id,
        "units": units,
    }


def rebuild_configs() -> None:
    """Пересобрать все конфиги Xray из сохранённых параметров vwn.conf.

    Перезаписывает JSON-конфиги текущими шаблонами (подхватывая новые
    поля из обновлений), затем применяет пользователей из users.conf,
    пересоздаёт nginx loopback и файлы подписок.
    """
    # установки до перехода на gRPC: WS_PATH/xray-ws/config.json → gRPC
    migrate_ws_to_grpc()

    domain = config.vwn_conf_get("DOMAIN")
    stub = config.vwn_conf_get("STUB_URL")
    reality_dest = config.vwn_conf_get("REALITY_DEST")
    uuid_ = config.vwn_conf_get("UUID")
    grpc_service = config.vwn_conf_get("GRPC_SERVICE")
    xhttp_path = config.vwn_conf_get("XHTTP_PATH")
    short_id = config.vwn_conf_get("SHORT_ID")
    reality_port = int(config.vwn_conf_get("REALITY_PORT") or config.REALITY_PUBLIC_PORT)
    xhttp_mode = config.vwn_conf_get("XHTTP_MODE") or "auto"
    if not all([domain, stub, reality_dest, uuid_, grpc_service, xhttp_path, short_id]):
        raise RuntimeError("Конфиг неполный — сначала выполните vwn install")

    r_cfg = _read_json(os.path.join(config.XRAY_DIR, "xray-reality.json"))
    if r_cfg is None:
        raise RuntimeError("xray-reality.json не найден — невозможно пересобрать")
    private_key = (r_cfg.get("inbounds", [{}])[0]
                   .get("streamSettings", {}).get("realitySettings", {})
                   .get("privateKey", ""))
    if not private_key:
        raise RuntimeError("Reality private_key не найден в текущем конфиге")

    server_name = reality_dest.split(":", 1)[0]
    write_reality_config(os.path.join(config.XRAY_DIR, "xray-reality.json"),
                         uuid_, server_name,
                         private_key, short_id, port=reality_port)

    reality_mode = config.vwn_conf_get("REALITY_MODE") or "tcp"
    if reality_mode != "tcp":
        set_reality_mode(reality_mode, restart=False)

    write_grpc_config(os.path.join(config.XRAY_DIR, "grpc.json"),
                      uuid_, config.XRAY_GRPC_PORT, grpc_service)
    write_xhttp_config(os.path.join(config.XRAY_DIR, "xhttp.json"),
                       uuid_, config.XRAY_XHTTP_PORT, xhttp_path, domain,
                       mode=xhttp_mode)

    from vwn.modules.users import apply_users_to_configs
    apply_users_to_configs()
    _re_render_nginx()
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()

    from vwn.modules.warp import reapply_warp
    reapply_warp()
    from vwn.modules.psiphon import reapply_routing as reapply_psiphon
    reapply_psiphon()
    from vwn.modules.tor import reapply_routing as reapply_tor
    reapply_tor()
    from vwn.modules.relay import reapply_routing as reapply_relay
    reapply_relay()


# ── gRPC / XHTTP management ────────────────────────────────────────

def _re_render_nginx(**overrides) -> None:
    from urllib.parse import urlparse
    tpl = os.path.join(os.path.dirname(__file__), "..", "data", "nginx_loopback.conf")
    domain = overrides.get("domain") or config.vwn_conf_get("DOMAIN") or "example.com"
    stub = overrides.get("stub") or config.vwn_conf_get("STUB_URL") or "https://example.com"
    grpc_service = (overrides.get("grpc_service")
                    or config.vwn_conf_get("GRPC_SERVICE") or "grpc")
    xhttp_path = overrides.get("xhttp_path") or config.vwn_conf_get("XHTTP_PATH") or "/xhttp"
    proxy_host = overrides.get("proxy_host") or urlparse(stub).netloc or domain
    try:
        system._write_nginx_main_conf()
    except OSError:
        pass
    write_nginx_loopback_config(
        tpl, config.NGINX_LOOPBACK_CONF,
        NGINX_LOOPBACK_PORT=config.NGINX_LOOPBACK_PORT, DOMAIN=domain, STUB=stub,
        PROXY_HOST=proxy_host, GRPC_SERVICE=grpc_service, XHTTP_PATH=xhttp_path,
        XRAY_GRPC_PORT=config.XRAY_GRPC_PORT, XRAY_XHTTP_PORT=config.XRAY_XHTTP_PORT,
    )


def read_grpc_xhttp_info() -> dict:
    grpc_cfg = _read_json(os.path.join(config.XRAY_DIR, "grpc.json"))
    xh_cfg = _read_json(os.path.join(config.XRAY_DIR, "xhttp.json"))
    info = {
        "domain": config.vwn_conf_get("DOMAIN") or "",
        "stub_url": config.vwn_conf_get("STUB_URL") or "",
        "uuid": config.vwn_conf_get("UUID") or "",
        "grpc_active": grpc_cfg is not None,
        "xhttp_active": xh_cfg is not None,
    }
    info["grpc_mode"] = config.vwn_conf_get("GRPC_MODE") or "gun"
    if grpc_cfg:
        ib = grpc_cfg.get("inbounds", [{}])[0]
        ss = ib.get("streamSettings", {})
        info["grpc_service"] = ss.get("grpcSettings", {}).get("serviceName", "")
        info["grpc_port"] = ib.get("port")
    else:
        info["grpc_service"] = config.vwn_conf_get("GRPC_SERVICE") or ""
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


def update_grpc_service(name: str) -> None:
    """Сменить serviceName gRPC (путь в nginx, grpc.json, подписки)."""
    name = validate_grpc_service(name)
    p = os.path.join(config.XRAY_DIR, "grpc.json")
    cfg = _read_json(p)
    if cfg is None:
        raise RuntimeError("gRPC не установлен")
    ib = cfg.get("inbounds", [{}])[0]
    ss = ib.setdefault("streamSettings", {})
    gs = ss.setdefault("grpcSettings", {})
    gs["serviceName"] = name
    _write_json(p, cfg)
    config.vwn_conf_set("GRPC_SERVICE", name)
    _re_render_nginx()
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    shell.run(["systemctl", "restart", "xray-grpc"], check=False)
    shell.run(["systemctl", "reload", "nginx"], check=False)


def set_grpc_mode(mode: str) -> None:
    """Режим gRPC для КЛИЕНТСКИХ ссылок (gun / multi). Серверный inbound
    принимает оба (/Tun и /TunMulti), поэтому JSON и сервис не трогаем."""
    if mode not in ("gun", "multi"):
        raise ValueError("Режим gRPC: gun или multi")
    if _read_json(os.path.join(config.XRAY_DIR, "grpc.json")) is None:
        raise RuntimeError("gRPC не установлен")
    config.vwn_conf_set("GRPC_MODE", mode)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


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


def disable_grpc() -> None:
    shell.run(["systemctl", "stop", "xray-grpc"], check=False)
    shell.run(["systemctl", "disable", "xray-grpc"], check=False)
    p = os.path.join(config.XRAY_DIR, "grpc.json")
    if os.path.isfile(p):
        os.rename(p, p + ".disabled")
    _add_disabled("grpc")
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def enable_grpc() -> None:
    p = os.path.join(config.XRAY_DIR, "grpc.json.disabled")
    if os.path.isfile(p):
        os.rename(p, p.removesuffix(".disabled"))
    shell.run(["systemctl", "enable", "xray-grpc"], check=False)
    shell.run(["systemctl", "start", "xray-grpc"], check=False)
    _del_disabled("grpc")
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def disable_xhttp() -> None:
    shell.run(["systemctl", "stop", "xray-xhttp"], check=False)
    shell.run(["systemctl", "disable", "xray-xhttp"], check=False)
    p = os.path.join(config.XRAY_DIR, "xhttp.json")
    if os.path.isfile(p):
        os.rename(p, p + ".disabled")
    _add_disabled("xhttp")
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def enable_xhttp() -> None:
    p = os.path.join(config.XRAY_DIR, "xhttp.json.disabled")
    if os.path.isfile(p):
        os.rename(p, p.removesuffix(".disabled"))
    shell.run(["systemctl", "enable", "xray-xhttp"], check=False)
    shell.run(["systemctl", "start", "xray-xhttp"], check=False)
    _del_disabled("xhttp")
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
