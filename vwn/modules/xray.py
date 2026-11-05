"""Генерация конфигов Xray (Reality / gRPC / XHTTP) и loopback-nginx.

Архитектура (self-steal): 443 → Xray(Reality, serverNames=[DOMAIN],
dest=127.0.0.1:8443) → не прошедшие Reality-аутентификацию уходят в nginx
(loopback, настоящий сертификат DOMAIN) → location /<serviceName> (grpc_pass)
→ Xray(gRPC) :50001, /xhttp (grpc_pass) → Xray(XHTTP) :50002.

SNI Reality всегда равен DOMAIN: зонд получает ваш реальный сайт с
сертификатом, совпадающим с SNI. Менять SNI отдельно от домена нельзя —
используйте update_domain().

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


def _norm_path(path: str) -> str:
    """Путь XHTTP для nginx-bound inbound'а: с ведущим "/", без хвостового.

    Хвостовой "/" в prefix-location с grpc_pass даёт 301 на запрос без слеша
    и выдаёт существование пути сканеру.
    """
    return "/" + (path or "").strip("/")


def all_config_paths() -> list[str]:
    return [os.path.join(config.XRAY_DIR, p) for p in config.XRAY_CONFIG_FILES]


def all_services() -> list[str]:
    return list(config.XRAY_SERVICES)


def generate_vless_keypair(strict: bool = False) -> "tuple[str | None, str | None]":
    """Обёртка над system.generate_vless_keypair (для единообразия и тестов)."""
    return system.generate_vless_keypair(strict=strict)


_XHTTP_SERVER_EXTRA = {"xPaddingBytes": "100-1000"}


def _xhttp_server_settings(path: str) -> dict:
    """Серверный XHTTP всегда mode=auto: принимает stream-one/stream-up/
    packet-up. Закреплённый режим режет клиентов (auto по TLS = stream-up).
    Версионно-зависимые поля (scMax*) не пишем. xmux/noGRPCHeader — только
    клиентские поля и на сервере не применяются."""
    return {"path": path, "mode": "auto", "extra": dict(_XHTTP_SERVER_EXTRA)}


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
    # uplinkOnly/downlinkOnly = 0 официальная документация советует только для
    # HTTP-браузинга: при half-close соединение рвётся мгновенно. Это общий
    # прокси, на нём бывают и протоколы с half-close, поэтому 1 с запаса.
    return {"levels": {"0": {
        "handshake": 15, "connIdle": conn_idle, "uplinkOnly": 1,
        "downlinkOnly": 1, "bufferSize": 512,
    }}}


def _log(error_path: str) -> dict:
    return {"loglevel": "warning", "error": error_path}


def generate_uuid() -> str:
    return str(uuid.uuid4())


def generate_short_id() -> str:
    return secrets.token_hex(8)


def _parse_reality_keypair(text: str) -> "tuple[str | None, str | None]":
    priv = pub = None
    for line in (text or "").splitlines():
        # Старые/новые версии xray выводят по-разному:
        #   "Private key:" / "Public key:"   либо
        #   "PrivateKey:" / "Password:" / "Password (PublicKey):"
        if line.startswith("Private key:") or line.startswith("PrivateKey:"):
            priv = line.split(":", 1)[1].strip()
        elif (line.startswith("Public key:")
              or line.startswith("Password:")
              or line.startswith("Password (PublicKey):")):
            pub = line.split(":", 1)[1].strip()
    return priv, pub


def generate_reality_keypair() -> "tuple[str, str]":
    """Сгенерировать (private, public) через `xray x25519`."""
    r = shell.run([config.XRAY_BIN, "x25519"], capture=True)
    priv, pub = _parse_reality_keypair(r.stdout or "")
    if not priv or not pub:
        raise RuntimeError("Не удалось сгенерировать Reality-ключи (xray недоступен)")
    return priv, pub


def derive_reality_public(private_key: str) -> "str | None":
    """Получить public key из private через `xray x25519 -i`."""
    if not private_key or not os.path.isfile(config.XRAY_BIN):
        return None
    r = shell.run([config.XRAY_BIN, "x25519", "-i", private_key],
                  capture=True, check=False)
    _, pub = _parse_reality_keypair(r.stdout or "")
    return pub or None


def reality_config(uuid: str, server_name: str,
                    private_key: str, short_id: str,
                    port: int = config.REALITY_PUBLIC_PORT,
                    fallback_port: int = config.NGINX_LOOPBACK_PORT,
                    decryption: str = "none") -> dict:
    """Reality на 443 публично (self-steal).

    server_name — собственный домен (DOMAIN): он же в сертификате nginx.
    Не прошедшие Reality-аутентификацию уходят на target = nginx на
    localhost:fallback_port (xver=0: nginx не ждёт PROXY protocol).
    """
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
                }],
                "decryption": decryption,
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "target": f"127.0.0.1:{fallback_port}",
                    "xver": 0,
                    "serverNames": [server_name],
                    "privateKey": private_key,
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimeDiff": 0,
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


def grpc_config(uuid: str, port: int, service_name: str,
                decryption: str = "none") -> dict:
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
            "settings": {"clients": [{"id": uuid, "level": 0}], "decryption": decryption},
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
                  mode: str = "auto", decryption: str = "none") -> dict:
    return {
        "log": _log("/var/log/xray/error.log"),
        "dns": _dns(),
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": uuid, "level": 0}], "decryption": decryption},
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
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_reality_config(path: str, *a, **kw) -> None:
    _write_json(path, reality_config(*a, **kw))


def write_grpc_config(path: str, *a, **kw) -> None:
    _write_json(path, grpc_config(*a, **kw))


def write_xhttp_config(path: str, *a, **kw) -> None:
    _write_json(path, xhttp_config(*a, **kw))


def ws_config(uuid: str, port: int, ws_path: str,
              decryption: str = "none") -> dict:
    return {
        "log": _log("/var/log/xray/error.log"),
        "dns": _dns(),
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "vless",
            "settings": {"clients": [{"id": uuid, "level": 0}],
                         "decryption": decryption},
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": _norm_path(ws_path)},
                "sockopt": _sockopt(public=False),
            },
            "sniffing": _SNIFFING,
            "tag": "ws-inbound",
        }],
        "outbounds": _outbounds(),
        "routing": _routing_base(),
        "policy": _policy(),
    }


def write_ws_config(path: str, *a, **kw) -> None:
    _write_json(path, ws_config(*a, **kw))


# ── Reality management helpers ──────────────────────────────────────

def _read_json(path: str) -> dict | None:
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def read_reality_info(path: str | None = None) -> dict | None:
    p = path or os.path.join(config.XRAY_DIR, "xray-reality.json")
    cfg = _read_json(p)
    if cfg is None:
        cfg = _read_json(p + ".disabled")
    if cfg is None:
        return None
    ib = cfg.get("inbounds", [{}])[0]
    ss = ib.get("streamSettings", {})
    rs = ss.get("realitySettings", {})
    mode = ss.get("network") or config.vwn_conf_get("REALITY_MODE") or "tcp"
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
        xs = ss.get("xhttpSettings", {})
        info["xhttp_path"] = xs.get("path") or config.vwn_conf_get("REALITY_XHTTP_PATH") or ""
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
    """Отключено: при self-steal SNI Reality всегда равен DOMAIN.

    serverNames обязан совпадать с доменом сертификата nginx, иначе зонд
    увидит расхождение SNI и сертификата. Для смены используйте update_domain().
    """
    raise RuntimeError(
        "Self-steal: SNI Reality всегда равен DOMAIN. "
        "Чтобы сменить домен, используйте update_domain()."
    )


def _ensure_reality_fields(ib: dict) -> None:
    ss = ib.setdefault("streamSettings", {})
    ss["security"] = "reality"
    rs = ss.setdefault("realitySettings", {})
    rs.setdefault("show", False)
    if "target" not in rs:
        if "dest" in rs:
            rs["target"] = rs.pop("dest")
        else:
            rs["target"] = f"127.0.0.1:{config.NGINX_LOOPBACK_PORT}"
    else:
        rs.pop("dest", None)
    rs.setdefault("xver", 0)
    rs.setdefault("minClientVer", "")
    rs.setdefault("maxClientVer", "")
    if "maxTimeDiff" not in rs and "maxTimediff" in rs:
        rs["maxTimeDiff"] = rs.pop("maxTimediff")
    rs.setdefault("maxTimeDiff", 0)
    domain = config.vwn_conf_get("DOMAIN") or ""
    if domain and not rs.get("serverNames"):
        rs["serverNames"] = [domain]
    if not rs.get("privateKey"):
        raise RuntimeError("Reality privateKey отсутствует — нужен vwn rebuild")
    if not rs.get("shortIds"):
        sid = config.vwn_conf_get("SHORT_ID")
        if sid:
            rs["shortIds"] = [sid]
    ib.setdefault("settings", {})["decryption"] = "none"


def set_reality_mode(mode: str, xhttp_path: str | None = None,
                     xhttp_mode: str | None = None,
                     restart: bool = True) -> None:
    path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    cfg = _read_json(path)
    if cfg is None:
        raise RuntimeError("Reality не установлен")
    old = json.loads(json.dumps(cfg))
    ib = cfg["inbounds"][0]
    _ensure_reality_fields(ib)
    ss = ib["streamSettings"]
    p = xm = ""
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
    else:
        ss["network"] = "tcp"
        ss.pop("xhttpSettings", None)
        ss["sockopt"] = _sockopt(public=True)
        for c in ib.get("settings", {}).get("clients", []):
            c["flow"] = "xtls-rprx-vision"

    _write_json(path, cfg)
    if os.path.isfile(config.XRAY_BIN):
        r = shell.run([config.XRAY_BIN, "-test", "-config", path],
                      capture=True, check=False, timeout=15)
        if r is not None and r.returncode != 0:
            _write_json(path, old)
            raise RuntimeError(
                "Xray config invalid: xray-reality.json\n%s"
                % ((r.stdout or r.stderr or "").strip()[-500:])
            )

    config.vwn_conf_set("REALITY_MODE", "xhttp" if mode == "xhttp" else "tcp")
    if mode == "xhttp":
        config.vwn_conf_set("REALITY_XHTTP_PATH", p)
        config.vwn_conf_set("REALITY_XHTTP_MODE", xm)
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
    """Установка ещё на WebSocket: старый config.json или unit без ws.json/WS_PATH."""
    return bool(
        os.path.isfile(os.path.join(config.XRAY_DIR, "config.json"))
        or os.path.isfile(os.path.join(config.XRAY_DIR, "config.json.disabled"))
        or (
            os.path.isfile(os.path.join(config.SYSTEMD_DIR, LEGACY_WS_SERVICE + ".service"))
            and not os.path.isfile(os.path.join(config.XRAY_DIR, "ws.json"))
            and not config.vwn_conf_get("WS_PATH")
        )
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

    for name in ("config.json", "config.json.disabled", "ws.json", "ws.json.disabled"):
        p = os.path.join(config.XRAY_DIR, name)
        if os.path.isfile(p):
            os.remove(p)

    unit = os.path.join(config.SYSTEMD_DIR, LEGACY_WS_SERVICE + ".service")
    if os.path.isfile(unit):
        os.remove(unit)
    shutil.rmtree(os.path.join(config.SYSTEMD_DIR, LEGACY_WS_SERVICE + ".service.d"),
                  ignore_errors=True)

    write_xray_units(include_ws=False)
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


def _restart_nginx_checked() -> None:
    r = shell.run(["nginx", "-t"], capture=True, check=False, timeout=15)
    if r is not None and r.returncode != 0:
        raise RuntimeError("nginx config invalid: %s"
                           % ((r.stdout or r.stderr or "").strip()[-500:]))
    shell.run(["systemctl", "enable", "nginx"], check=False)
    shell.run(["systemctl", "restart", "nginx"], check=False)


def _read_nginx_conf() -> "str | None":
    try:
        with open(config.NGINX_LOOPBACK_CONF, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _restore_nginx_conf(old: "str | None") -> None:
    if old is None:
        return
    try:
        with open(config.NGINX_LOOPBACK_CONF, "w", encoding="utf-8") as fh:
            fh.write(old)
        shell.run(["systemctl", "restart", "nginx"], check=False)
    except OSError:
        pass


def disable_reality() -> None:
    from vwn.cores import registry
    backend = registry.get_core()
    if backend.name == "mihomo":
        backend.disable_protocol("reality")
        return
    old_conf = _read_nginx_conf()
    p = os.path.join(config.XRAY_DIR, "xray-reality.json")
    renamed = False
    try:
        shell.run(["systemctl", "stop", "xray-reality"], check=False)
        shell.run(["systemctl", "disable", "xray-reality"], check=False)
        if os.path.isfile(p):
            os.rename(p, p + ".disabled")
            renamed = True
        _add_disabled("reality")
        _re_render_nginx()
        _restart_nginx_checked()
    except Exception:
        if renamed and os.path.isfile(p + ".disabled"):
            os.rename(p + ".disabled", p)
        _del_disabled("reality")
        _restore_nginx_conf(old_conf)
        shell.run(["systemctl", "enable", "xray-reality"], check=False)
        shell.run(["systemctl", "start", "xray-reality"], check=False)
        raise
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def enable_reality() -> None:
    from vwn.cores import registry
    backend = registry.get_core()
    if backend.name == "mihomo":
        backend.enable_protocol("reality")
        return
    old_conf = _read_nginx_conf()
    try:
        _del_disabled("reality")
        _re_render_nginx()
        _restart_nginx_checked()
    except Exception:
        _add_disabled("reality")
        _restore_nginx_conf(old_conf)
        raise
    p = os.path.join(config.XRAY_DIR, "xray-reality.json.disabled")
    if os.path.isfile(p):
        os.rename(p, p.removesuffix(".disabled"))
    shell.run(["systemctl", "enable", "xray-reality"], check=False)
    shell.run(["systemctl", "start", "xray-reality"], check=False)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def set_xhttp_mode(mode: str) -> None:
    """Режим XHTTP для КЛИЕНТСКИХ ссылок (direct). Серверный inbound всегда auto,
    поэтому JSON и сервис не трогаем."""
    if _read_json(os.path.join(config.XRAY_DIR, "xhttp.json")) is None:
        raise RuntimeError("XHTTP не установлен")
    config.vwn_conf_set("XHTTP_MODE", mode)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def set_xhttp_cdn_mode(mode: str) -> None:
    """Режим XHTTP для КЛИЕНТСКИХ ссылок через CDN."""
    if _read_json(os.path.join(config.XRAY_DIR, "xhttp.json")) is None:
        raise RuntimeError("XHTTP не установлен")
    config.vwn_conf_set("XHTTP_CDN_MODE", mode)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()


def nginx_grpc_location(service: str, port: int) -> str:
    return (
        "location ^~ /" + service + " {\n"
        '    if ($content_type !~ "^application/grpc") {\n'
        "        return 404;\n"
        "    }\n"
        "    client_max_body_size 0;\n"
        "    client_body_buffer_size 0;\n"
        "    client_body_timeout 1w;\n"
        "    grpc_read_timeout 1w;\n"
        "    grpc_send_timeout 1w;\n"
        "    grpc_buffer_size 64k;\n"
        "    send_timeout 1w;\n"
        "    grpc_set_header Host $host;\n"
        "    access_log off;\n"
        "    grpc_pass grpc://127.0.0.1:" + str(port) + ";\n"
        "}"
    )


def nginx_xhttp_location(path: str, port: int) -> str:
    return (
        "location ^~ " + path + " {\n"
        "    if ($request_method !~ ^(GET|POST)$) { return 404; }\n"
        "    client_max_body_size 0;\n"
        "    client_body_buffer_size 0;\n"
        "    client_body_timeout 1w;\n"
        "    grpc_read_timeout 1w;\n"
        "    grpc_send_timeout 1w;\n"
        "    grpc_buffer_size 64k;\n"
        "    send_timeout 1w;\n"
        "    grpc_set_header Host $host;\n"
        "    grpc_pass grpc://127.0.0.1:" + str(port) + ";\n"
        "}"
    )


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
RestartSec=5
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
"""


def write_xray_units(units_dir: "str | None" = None,
                      xray_bin: "str | None" = None,
                      config_dir: "str | None" = None,
                      include_ws: "bool | None" = None) -> "list[str]":
    """Создать unit-файлы reality/grpc/xhttp и, при необходимости, ws."""
    units_dir = units_dir or config.SYSTEMD_DIR
    xray_bin = xray_bin or config.XRAY_BIN
    config_dir = config_dir or config.XRAY_DIR
    if include_ws is None:
        include_ws = os.path.isfile(os.path.join(config_dir, "ws.json"))
    names = ["xray-reality", "xray-grpc", "xray-xhttp"]
    if include_ws:
        names.append("xray-ws")
    descs = {
        "xray-reality": "Xray Reality Service",
        "xray-grpc": "Xray gRPC Service",
        "xray-xhttp": "Xray XHTTP Service",
        "xray-ws": "Xray WebSocket Service",
    }
    configs = {
        "xray-reality": "xray-reality.json",
        "xray-grpc": "grpc.json",
        "xray-xhttp": "xhttp.json",
        "xray-ws": "ws.json",
    }
    written = []
    os.makedirs(units_dir, exist_ok=True)
    for svc in names:
        cfg = os.path.join(config_dir, configs[svc])
        content = _UNIT_TPL.format(desc=descs[svc], xray_bin=xray_bin,
                                   config_path=cfg)
        path = os.path.join(units_dir, svc + ".service")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        written.append(path)
    if not include_ws:
        unit = os.path.join(units_dir, "xray-ws.service")
        if os.path.isfile(unit):
            os.remove(unit)
        shutil.rmtree(os.path.join(units_dir, "xray-ws.service.d"),
                      ignore_errors=True)
    return written


def provision_configs(domain: str, stub: str, reality_dest: str = "",
                      reality_port: int = config.REALITY_PUBLIC_PORT,
                      xhttp_mode: str = "auto",
                      private_key: "str | None" = None,
                      server_name: "str | None" = None,
                      vless_encryption: "bool | None" = None,
                      reality_mode: "str | None" = None) -> dict:
    """Сгенерировать ВСЕ конфиги сразу (полные, self-steal).

    Параметр reality_dest оставлен ради совместимости вызовов и не
    используется: SNI Reality всегда равен domain.

    Возвращает словарь с параметрами (uuid, пути), сохранёнными в vwn.conf.
    """
    validate_domain(domain)
    validate_url(stub)

    os.makedirs(config.XRAY_DIR, exist_ok=True)
    uuid_ = generate_uuid()
    grpc_service = system.generate_grpc_service()
    xhttp_path = _norm_path(system.generate_random_path())
    ws_path = _norm_path(system.generate_random_path())
    short_id = generate_short_id()

    if private_key:
        priv = private_key
        pub = config.vwn_conf_get("REALITY_PUBKEY") or "unknown"
    else:
        priv, pub = generate_reality_keypair()
    # Self-steal: serverNames (клиентский SNI) = собственный домен.
    sname = server_name or domain
    proxy_host = urllib.parse.urlparse(stub).netloc or domain

    if vless_encryption is False:
        config.vwn_conf_set("VLESS_DECRYPTION", "none")
        config.vwn_conf_del("VLESS_ENCRYPTION")
        decryption = "none"
    else:
        decryption = resolve_vless_policy(force=(vless_encryption is True))
    reality_decryption = "none"
    if reality_mode is None:
        if (config.vwn_conf_get("REALITY_MODE")
                or os.path.isfile(os.path.join(config.XRAY_DIR, "xray-reality.json"))
                or os.path.isfile(os.path.join(config.XRAY_DIR, "xray-reality.json.disabled"))):
            reality_mode = config.vwn_conf_get("REALITY_MODE") or "tcp"
        else:
            reality_mode = "xhttp"

    write_reality_config(os.path.join(config.XRAY_DIR, "xray-reality.json"),
                          uuid_, sname, priv, short_id,
                          port=reality_port, decryption=reality_decryption)
    write_grpc_config(os.path.join(config.XRAY_DIR, "grpc.json"),
                       uuid_, config.XRAY_GRPC_PORT, grpc_service,
                       decryption=decryption)
    write_xhttp_config(os.path.join(config.XRAY_DIR, "xhttp.json"),
                        uuid_, config.XRAY_XHTTP_PORT, xhttp_path, domain,
                        mode=xhttp_mode, decryption=decryption)
    write_ws_config(os.path.join(config.XRAY_DIR, "ws.json"),
                    uuid_, config.XRAY_WS_PORT, ws_path,
                    decryption=decryption)

    tpl = os.path.join(os.path.dirname(__file__), "..", "data", "nginx_loopback.conf")
    ws_map = ("map $http_upgrade $connection_upgrade {\n"
              "    default upgrade;\n"
              "    '' close;\n"
              "}")
    ws_location = ("location ^~ " + ws_path + " {\n"
                   '    if ($http_upgrade !~* "websocket") { return 404; }\n'
                   "    client_max_body_size 0;\n"
                   "    proxy_http_version 1.1;\n"
                   "    proxy_set_header Upgrade $http_upgrade;\n"
                   "    proxy_set_header Connection $connection_upgrade;\n"
                   "    proxy_set_header Host $host;\n"
                   "    proxy_set_header X-Real-IP $remote_addr;\n"
                   "    proxy_buffering off;\n"
                   "    proxy_read_timeout 1w;\n"
                   "    proxy_send_timeout 1w;\n"
                   "    access_log off;\n"
                   "    proxy_pass http://127.0.0.1:" + str(config.XRAY_WS_PORT) + ";\n"
                   "}")
    from vwn.modules.sub import get_disabled_protocols
    disabled = get_disabled_protocols()
    write_nginx_loopback_config(
        tpl, config.NGINX_LOOPBACK_CONF,
        NGINX_BIND="127.0.0.1",
        NGINX_LOOPBACK_PORT=config.NGINX_LOOPBACK_PORT, DOMAIN=domain, STUB=stub,
        PROXY_HOST=proxy_host, GRPC_SERVICE=grpc_service, XHTTP_PATH=xhttp_path,
        WS_PATH=ws_path, XRAY_WS_PORT=config.XRAY_WS_PORT,
        WS_MAP=ws_map, WS_LOCATION=ws_location,
        GRPC_LOCATION=("" if "grpc" in disabled else
                       nginx_grpc_location(grpc_service, config.XRAY_GRPC_PORT)),
        XHTTP_LOCATION=("" if "xhttp" in disabled else
                        nginx_xhttp_location(xhttp_path, config.XRAY_XHTTP_PORT)),
        XRAY_GRPC_PORT=config.XRAY_GRPC_PORT, XRAY_XHTTP_PORT=config.XRAY_XHTTP_PORT,
    )

    config.vwn_conf_set("DOMAIN", domain)
    config.vwn_conf_set("STUB_URL", stub)
    config.vwn_conf_set("UUID", uuid_)
    config.vwn_conf_set("GRPC_SERVICE", grpc_service)
    config.vwn_conf_set("XHTTP_PATH", xhttp_path)
    config.vwn_conf_set("WS_PATH", ws_path)
    config.vwn_conf_set("REALITY_DEST", f"{sname}:443")
    config.vwn_conf_set("REALITY_PORT", str(reality_port))
    config.vwn_conf_set("XHTTP_MODE", xhttp_mode)
    config.vwn_conf_set("REALITY_MODE", reality_mode)
    if reality_mode == "xhttp":
        config.vwn_conf_set("REALITY_XHTTP_PATH", xhttp_path)
        config.vwn_conf_set("REALITY_XHTTP_MODE", xhttp_mode)
    config.vwn_conf_set("REALITY_PUBKEY", pub)
    config.vwn_conf_set("SHORT_ID", short_id)

    if reality_mode == "xhttp":
        set_reality_mode("xhttp", xhttp_path=xhttp_path, xhttp_mode=xhttp_mode,
                         restart=False)
    units = write_xray_units(include_ws=True)

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


def rebuild_configs(refresh_ip: bool = False) -> None:
    """Пересобрать все конфиги Xray из сохранённых параметров vwn.conf.

    Перезаписывает JSON-конфиги текущими шаблонами (подхватывая новые
    поля из обновлений), затем применяет пользователей из users.conf,
    пересоздаёт nginx loopback и файлы подписок.

    Для уже установленных серверов это же миграция на self-steal: SNI Reality
    заменяется на DOMAIN. После пересборки нужен restart xray-reality.
    """
    from vwn.modules.sub import get_disabled_protocols
    reality_disabled = "reality" in get_disabled_protocols()
    from vwn.cores import keystore
    keystore.repair_reality_pubkey()

    # Сначала политика VLESS Encryption (fail-fast, до миграции и записи)
    decryption = resolve_vless_policy()
    reality_decryption = "none"

    # установки до перехода на gRPC: WS_PATH/xray-ws/config.json → gRPC
    had_legacy = migrate_ws_to_grpc()

    domain = config.vwn_conf_get("DOMAIN")
    stub = config.vwn_conf_get("STUB_URL")
    uuid_ = config.vwn_conf_get("UUID")
    grpc_service = config.vwn_conf_get("GRPC_SERVICE")
    xhttp_path = _norm_path(config.vwn_conf_get("XHTTP_PATH") or "")
    short_id = config.vwn_conf_get("SHORT_ID")
    reality_port = int(config.vwn_conf_get("REALITY_PORT") or config.REALITY_PUBLIC_PORT)
    xhttp_mode = config.vwn_conf_get("XHTTP_MODE") or "auto"
    ws_disabled = False
    try:
        from vwn.modules.sub import get_disabled_protocols
        ws_disabled = "ws" in get_disabled_protocols()
    except Exception:
        ws_disabled = False
    ws_on = (not had_legacy) and (not ws_disabled)
    ws_path = _norm_path(config.vwn_conf_get("WS_PATH") or "")
    if not all([domain, stub, uuid_, grpc_service, config.vwn_conf_get("XHTTP_PATH"),
                short_id]):
        raise RuntimeError("Конфиг неполный — сначала выполните vwn install")

    reality_path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    reality_disabled_path = reality_path + ".disabled"
    r_cfg = _read_json(reality_path) or _read_json(reality_disabled_path)
    private_key = ""
    if r_cfg:
        private_key = (r_cfg.get("inbounds", [{}])[0]
                       .get("streamSettings", {}).get("realitySettings", {})
                       .get("privateKey", ""))
    if not private_key:
        from vwn.cores import keystore
        private_key = keystore.reality_private_key() or ""
    if not private_key:
        raise RuntimeError("Reality private_key не найден (vwn.conf/xray-reality.json)")
    # Если Reality был отключён, пересборка не должна оставлять его выключенным
    # без явного пользователя; конфиг пересоздаётся, но статус сохраняется.

    # Self-steal: SNI Reality = DOMAIN.
    server_name = domain
    config.vwn_conf_set("REALITY_DEST", f"{domain}:443")
    config.vwn_conf_set("XHTTP_PATH", xhttp_path)
    reality_path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    if reality_disabled and os.path.isfile(reality_path):
        os.remove(reality_path)
    write_reality_config(reality_path, uuid_, server_name,
                          private_key, short_id, port=reality_port,
                          decryption=reality_decryption)

    reality_mode = config.vwn_conf_get("REALITY_MODE") or "tcp"
    if reality_mode != "tcp":
        set_reality_mode(reality_mode, restart=False)

    write_grpc_config(os.path.join(config.XRAY_DIR, "grpc.json"),
                       uuid_, config.XRAY_GRPC_PORT, grpc_service,
                       decryption=decryption)
    write_xhttp_config(os.path.join(config.XRAY_DIR, "xhttp.json"),
                        uuid_, config.XRAY_XHTTP_PORT, xhttp_path, domain,
                        mode=xhttp_mode, decryption=decryption)

    if ws_on:
        if not ws_path or ws_path == "/":
            ws_path = _norm_path(system.generate_random_path())
            config.vwn_conf_set("WS_PATH", ws_path)
        write_ws_config(os.path.join(config.XRAY_DIR, "ws.json"),
                        uuid_, config.XRAY_WS_PORT, ws_path,
                        decryption=decryption)
        shell.run(["systemctl", "enable", "xray-ws"], check=False)
    else:
        p = os.path.join(config.XRAY_DIR, "ws.json")
        if os.path.isfile(p):
            os.rename(p, p + ".disabled")
        shell.run(["systemctl", "disable", "xray-ws"], check=False)
        shell.run(["systemctl", "stop", "xray-ws"], check=False)

    write_xray_units(include_ws=ws_on)

    # Валидация конфигов до рестарта (на dev-машине без xray пропускаем)
    if os.path.isfile(config.XRAY_BIN):
        for _cfg_name in ("xray-reality.json", "grpc.json", "xhttp.json"):
            _p = os.path.join(config.XRAY_DIR, _cfg_name)
            if os.path.isfile(_p):
                _r = shell.run([config.XRAY_BIN, "-test", "-config", _p],
                               capture=True, check=False, timeout=15)
                if _r is not None and _r.returncode != 0:
                    raise RuntimeError(
                        "Xray config invalid: %s\n%s" % (_cfg_name, (_r.stdout or _r.stderr or "").strip()[-500:])
                    )
        if ws_on and os.path.isfile(os.path.join(config.XRAY_DIR, "ws.json")):
            _p = os.path.join(config.XRAY_DIR, "ws.json")
            _r = shell.run([config.XRAY_BIN, "-test", "-config", _p],
                           capture=True, check=False, timeout=15)
            if _r is not None and _r.returncode != 0:
                raise RuntimeError(
                    "Xray config invalid: ws.json\n%s" % ((_r.stdout or _r.stderr or "").strip()[-500:])
                )

    from vwn.modules.users import apply_users_to_configs
    apply_users_to_configs()
    if reality_disabled:
        os.replace(reality_path, reality_path + ".disabled")
    _re_render_nginx()
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files(refresh_ip=refresh_ip)

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
    xhttp_path = _norm_path(overrides.get("xhttp_path")
                            or config.vwn_conf_get("XHTTP_PATH") or "/xhttp")
    ws_path = _norm_path(overrides.get("ws_path")
                         or config.vwn_conf_get("WS_PATH") or "")
    proxy_host = overrides.get("proxy_host") or urlparse(stub).netloc or domain
    ws_on = os.path.isfile(os.path.join(config.XRAY_DIR, "ws.json")) and bool(ws_path)
    if ws_on:
        ws_map = ("map $http_upgrade $connection_upgrade {\n"
                  "    default upgrade;\n    '' close;\n}")
        ws_location = ("location ^~ " + ws_path + " {\n"
                       "    if ($http_upgrade !~* \"websocket\") { return 404; }\n"
                       "    client_max_body_size 0;\n"
                       "    proxy_http_version 1.1;\n"
                       "    proxy_set_header Upgrade $http_upgrade;\n"
                       "    proxy_set_header Connection $connection_upgrade;\n"
                       "    proxy_set_header Host $host;\n"
                       "    proxy_set_header X-Real-IP $remote_addr;\n"
                       "    proxy_buffering off;\n"
                       "    proxy_read_timeout 1w;\n"
                       "    proxy_send_timeout 1w;\n"
                       "    access_log off;\n"
                       "    proxy_pass http://127.0.0.1:" + str(config.XRAY_WS_PORT) + ";\n"
                       "}")
    else:
        ws_map = ""
        ws_location = ""
    try:
        system._write_nginx_main_conf()
    except OSError:
        pass
    from vwn.modules.sub import get_disabled_protocols
    disabled = get_disabled_protocols()
    public = "reality" in disabled
    bind = "0.0.0.0" if public else "127.0.0.1"
    nginx_port = 443 if public else config.NGINX_LOOPBACK_PORT
    write_nginx_loopback_config(
        tpl, config.NGINX_LOOPBACK_CONF,
        NGINX_BIND=bind,
        NGINX_LOOPBACK_PORT=nginx_port, DOMAIN=domain, STUB=stub,
        PROXY_HOST=proxy_host, GRPC_SERVICE=grpc_service, XHTTP_PATH=xhttp_path,
        WS_PATH=ws_path, XRAY_WS_PORT=config.XRAY_WS_PORT,
        WS_MAP=ws_map, WS_LOCATION=ws_location,
        GRPC_LOCATION=("" if "grpc" in disabled else
                       nginx_grpc_location(grpc_service, config.XRAY_GRPC_PORT)),
        XHTTP_LOCATION=("" if "xhttp" in disabled else
                        nginx_xhttp_location(xhttp_path, config.XRAY_XHTTP_PORT)),
        XRAY_GRPC_PORT=config.XRAY_GRPC_PORT, XRAY_XHTTP_PORT=config.XRAY_XHTTP_PORT,
    )


def read_grpc_xhttp_info() -> dict:
    grpc_cfg = _read_json(os.path.join(config.XRAY_DIR, "grpc.json"))
    xh_cfg = _read_json(os.path.join(config.XRAY_DIR, "xhttp.json"))
    ws_cfg = _read_json(os.path.join(config.XRAY_DIR, "ws.json"))
    info = {
        "domain": config.vwn_conf_get("DOMAIN") or "",
        "stub_url": config.vwn_conf_get("STUB_URL") or "",
        "uuid": config.vwn_conf_get("UUID") or "",
        "grpc_active": grpc_cfg is not None,
        "xhttp_active": xh_cfg is not None,
        "ws_active": ws_cfg is not None,
        "ws_path": (ws_cfg.get("inbounds", [{}])[0].get("streamSettings", {})
                    .get("wsSettings", {}).get("path", "")
                    if ws_cfg else (config.vwn_conf_get("WS_PATH") or "")),
        "vless_encryption": config.vwn_conf_get("VLESS_ENCRYPTION") or "none",
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
    else:
        info["xhttp_path"] = config.vwn_conf_get("XHTTP_PATH") or ""
    # mode — клиентский; серверный inbound всегда auto (см. _xhttp_server_settings)
    info["xhttp_mode"] = config.vwn_conf_get("XHTTP_MODE") or "auto"
    info["xhttp_cdn_mode"] = config.vwn_conf_get("XHTTP_CDN_MODE") or "auto"
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
    path = _norm_path(path)
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
    """Сменить домен. При self-steal он же SNI Reality, поэтому serverNames
    обновляется вместе с nginx и подписками.

    Порядок: сначала выпустите сертификат на новый домен (renew_ssl),
    затем вызывайте update_domain.
    """
    validate_domain(domain)
    config.vwn_conf_set("DOMAIN", domain)
    config.vwn_conf_set("REALITY_DEST", f"{domain}:443")
    p = os.path.join(config.XRAY_DIR, "xray-reality.json")
    cfg = _read_json(p)
    if cfg is not None:
        cfg["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"] = [domain]
        _write_json(p, cfg)
        shell.run(["systemctl", "restart", "xray-reality"], check=False)
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


_PROTOCOLS = {
    "grpc": ("xray-grpc", "grpc.json"),
    "xhttp": ("xray-xhttp", "xhttp.json"),
    "ws": ("xray-ws", "ws.json"),
}


def _toggle_protocol(proto: str, on: bool) -> None:
    from vwn.cores import registry

    backend = registry.get_core()
    if backend.name == "mihomo":
        if on:
            backend.enable_protocol(proto)
        else:
            backend.disable_protocol(proto)
        return
    svc, name = _PROTOCOLS[proto]
    p = os.path.join(config.XRAY_DIR, name)
    if on:
        if os.path.isfile(p + ".disabled"):
            os.rename(p + ".disabled", p)
        shell.run(["systemctl", "enable", svc], check=False)
        shell.run(["systemctl", "start", svc], check=False)
        _del_disabled(proto)
    else:
        shell.run(["systemctl", "stop", svc], check=False)
        shell.run(["systemctl", "disable", svc], check=False)
        if os.path.isfile(p):
            os.rename(p, p + ".disabled")
        _add_disabled(proto)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    _re_render_nginx()
    shell.run(["systemctl", "reload", "nginx"], check=False)


def disable_grpc() -> None:
    _toggle_protocol("grpc", False)


def enable_grpc() -> None:
    _toggle_protocol("grpc", True)


def disable_xhttp() -> None:
    _toggle_protocol("xhttp", False)


def enable_xhttp() -> None:
    _toggle_protocol("xhttp", True)


def disable_ws() -> None:
    _toggle_protocol("ws", False)


def enable_ws() -> None:
    _toggle_protocol("ws", True)


def update_ws_path(path: str) -> None:
    p = os.path.join(config.XRAY_DIR, "ws.json")
    cfg = _read_json(p)
    if cfg is None:
        raise RuntimeError("WS не установлен")
    path = _norm_path(path)
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


def read_vless_encryption() -> dict:
    dec = config.vwn_conf_get("VLESS_DECRYPTION") or "none"
    enc = config.vwn_conf_get("VLESS_ENCRYPTION") or "none"
    if dec == "none" or enc == "none":
        return {"enabled": False, "decryption": "none", "encryption": "none"}
    return {"enabled": True, "decryption": dec, "encryption": enc}


def _generate_and_store_vless() -> str:
    dec, enc = generate_vless_keypair(strict=True)
    if not (dec and enc):
        raise RuntimeError("xray vlessenc не вернул ключи")
    config.vwn_conf_set("VLESS_DECRYPTION", dec)
    config.vwn_conf_set("VLESS_ENCRYPTION", enc)
    from vwn.cores import keystore
    keystore.set("VLESS_DECRYPTION", dec)
    keystore.set("VLESS_ENCRYPTION", enc)
    return dec


def resolve_vless_policy(force_new_keys: bool = False,
                        force: bool = False) -> str:
    dec = config.vwn_conf_get("VLESS_DECRYPTION")
    enc = config.vwn_conf_get("VLESS_ENCRYPTION")
    if dec == "none":
        if force:
            return _generate_and_store_vless()
        return "none"
    if dec and enc:
        from vwn.cores import keystore
        keystore.set("VLESS_DECRYPTION", dec)
        keystore.set("VLESS_ENCRYPTION", enc)
        return dec
    if dec and not enc:
        if force or force_new_keys:
            return _generate_and_store_vless()
        raise RuntimeError(
            "VLESS_DECRYPTION есть, но VLESS_ENCRYPTION потерян. "
            "Запустите vwn vless-enc on --force-new-keys "
            "(все клиенты должны переимпортировать подписку)."
        )
    # ключа нет -> default-on
    return _generate_and_store_vless()


def enable_vless_encryption(force_new_keys: bool = False) -> None:
    print("  Внимание: старые клиенты без поддержки VLESS Encryption перестанут работать")
    resolve_vless_policy(force=True, force_new_keys=force_new_keys)
    from vwn.cores import registry
    backend = registry.get_core()
    backend.rebuild()
    for svc in backend.services:
        shell.run(["systemctl", "restart", svc], check=False)


def disable_vless_encryption() -> None:
    config.vwn_conf_set("VLESS_DECRYPTION", "none")
    config.vwn_conf_del("VLESS_ENCRYPTION")
    from vwn.cores import keystore, registry
    keystore.set("VLESS_DECRYPTION", "none", overwrite=True)
    backend = registry.get_core()
    backend.rebuild()
    for svc in backend.services:
        shell.run(["systemctl", "restart", svc], check=False)
