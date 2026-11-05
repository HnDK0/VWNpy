"""Генерация VLESS-ссылок, файлов подписок и HTML-страниц пользователей.

Зависит от vwn.conf (DOMAIN, UUID, GRPC_SERVICE, GRPC_MODE, XHTTP_PATH,
REALITY_DEST, REALITY_PORT, REALITY_PUBKEY, SHORT_ID, XHTTP_MODE) для построения URL.
"""

import base64
import json
import os
import re
import secrets
import string
import sys
from pathlib import Path

from vwn.core import config, render
from vwn.modules import users

SUB_DIR = "/usr/local/etc/xray/sub"


def _reality_xhttp_mode(mode: str) -> str:
    # клиентский auto с Reality ломается в новых Xray (#5635); серверный
    # auto принимает stream-one, поэтому указываем его явно.
    return mode if mode and mode != "auto" else "stream-one"


_XHTTP_CLIENT_EXTRA_BASE = {
    "xmux": {
        "cMaxReuseTimes": 0,
        "maxConcurrency": "16-32",
        "hKeepAlivePeriod": 15,
        "hMaxRequestTimes": "600-900",
        "hMaxReusableSecs": "1800-3000",
    },
    "xPaddingBytes": "100-1000",
}


def _xhttp_client_extra(cdn: bool = False) -> dict:
    return {**_XHTTP_CLIENT_EXTRA_BASE, "noGRPCHeader": not cdn}


def _xhttp_client_extra_json(cdn: bool = False) -> str:
    return json.dumps(_xhttp_client_extra(cdn), separators=(",", ":"))


def generate_reality_url(
    uuid_val: str,
    server_ip: str,
    port: int,
    short_id: str,
    dest_host: str,
    pub_key: str,
    name: str,
    mode: str = "tcp",
    xhttp_path: str = "",
    xhttp_mode: str = "",
    extra_json: str | None = None,
    vless_encryption: str = "none",
) -> str:
    base = (
        f"vless://{uuid_val}@{server_ip}:{port}"
        f"?encryption={_urlencode(vless_encryption)}&security=reality"
        f"&sni={dest_host}&fp=chrome&pbk={pub_key}&sid={short_id}&support-x25519mlkem768=true"
    )
    if mode == "xhttp":
        path = xhttp_path or "/r"
        rmode = _reality_xhttp_mode(xhttp_mode)
        extra = f"&alpn=h2&path={_urlencode(path)}&mode={rmode}&host={dest_host}"
        if extra_json:
            extra += f"&extra={_urlencode(extra_json)}"
        return f"{base}&type=xhttp{extra}#{_urlencode(name)}"
    return f"{base}&type=tcp&flow=xtls-rprx-vision#{_urlencode(name)}"


def generate_grpc_url(
    uuid_val: str,
    connect_host: str,
    port: int,
    service_name: str,
    domain: str,
    name: str,
    mode: str = "gun",
    vless_encryption: str = "none",
) -> str:
    """VLESS+gRPC+TLS. gRPC работает только поверх h2 → alpn=h2 обязателен.

    mode: gun (одиночный стрим /Tun, совместим со всеми клиентами) или multi
    (/TunMulti, меньше соединений, не везде поддерживается). authority = домен:
    через CDN/чужой connect_host :authority иначе был бы IP.
    """
    return (
        f"vless://{uuid_val}@{connect_host}:{port}"
        f"?encryption={_urlencode(vless_encryption)}&security=tls"
        f"&sni={domain}&fp=chrome&alpn=h2"
        f"&type=grpc&path={_urlencode(service_name)}&serviceName={_urlencode(service_name)}"
        f"&mode={mode}&authority={domain}"
        f"#{_urlencode(name)}"
    )

def generate_xhttp_url(
    uuid_val: str,
    connect_host: str,
    port: int,
    xhttp_path: str,
    domain: str,
    name: str,
    mode: str = "auto",
    extra_json: str | None = None,
    vless_encryption: str = "none",
) -> str:
    encoded_path = _urlencode(xhttp_path)
    url = (
        f"vless://{uuid_val}@{connect_host}:{port}"
        f"?encryption={_urlencode(vless_encryption)}&security=tls&type=xhttp&path={encoded_path}"
        f"&mode={mode}&alpn=h2&host={domain}&sni={domain}"
        f"&fp=chrome"
    )
    if extra_json:
        url += f"&extra={_urlencode(extra_json)}"
    return f"{url}#{_urlencode(name)}"


def generate_ws_url(
    uuid_val: str,
    connect_host: str,
    port: int,
    ws_path: str,
    domain: str,
    name: str,
    vless_encryption: str = "none",
) -> str:
    return (
        f"vless://{uuid_val}@{connect_host}:{port}"
        f"?encryption={_urlencode(vless_encryption)}&security=tls"
        f"&sni={domain}&fp=chrome&alpn=http%2F1.1"
        f"&type=ws&path={_urlencode(ws_path)}&host={domain}"
        f"#{_urlencode(name)}"
    )


def _urlencode(val: str) -> str:
    """URL-кодирование для фрагмента vless://."""
    from urllib.parse import quote
    return quote(val, safe="")


def safe_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "", label)


def sub_filename(label: str, token: str) -> str:
    return f"{safe_label(label)}_{token}.txt"


def html_filename(label: str, token: str) -> str:
    return f"{safe_label(label)}_{token}.html"


def generate_token(length: int = 32) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


def write_sub_file(output_dir: str, label: str, token: str, lines: list[str]) -> str:
    os.makedirs(output_dir, exist_ok=True)
    safe = safe_label(label)
    for f in os.listdir(output_dir):
        if users.is_sub_file_for(f, safe):
            os.remove(os.path.join(output_dir, f))
    filename = sub_filename(label, token)
    path = os.path.join(output_dir, filename)
    raw = "\n".join(lines)
    b64 = base64.b64encode(raw.encode()).decode()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(b64)
    os.chmod(path, 0o644)
    return path


def build_mihomo_proxies(
    uuid_val: str,
    label: str,
    domain: str,
    connect_host: str,
    server_ip: str,
    grpc_service: str,
    grpc_mode: str,
    xhttp_path: str,
    xhttp_mode: str,
    reality_port_str: str,
    reality_dest: str,
    pub_key: str,
    short_id: str,
    reality_mode: str,
    xhttp_path_reality: str,
    xhttp_extra_mode: str,
    disabled: set[str],
    ws_path: str = "",
    vless_encryption: str = "none",
    xhttp_cdn_mode: str = "auto",
) -> list[dict]:
    proxies: list[dict] = []
    enc = "" if vless_encryption in ("", "none") else vless_encryption
    cdn = connect_host != domain

    # gRPC только через CDN
    if cdn and grpc_service and "grpc" not in disabled:
        proxies.append({
            "name": users.get_config_name("gRPC", label),
            "type": "vless",
            "server": connect_host,
            "port": 443,
            "uuid": uuid_val,
            "udp": True,
            "tls": True,
            "servername": domain,
            "client-fingerprint": "chrome",
            "network": "grpc",
            "encryption": enc,
            "grpc-opts": {
                "grpc-service-name": grpc_service,
                "ping-interval": 15,
            },
        })

    # XHTTP direct (можно скрыть при включённом CDN)
    if xhttp_path and "xhttp" not in disabled and xhttp_direct_enabled():
        proxies.append({
            "name": users.get_config_name("XHTTP", label),
            "type": "vless",
            "server": server_ip,
            "port": 443,
            "uuid": uuid_val,
            "udp": True,
            "tls": True,
            "servername": domain,
            "client-fingerprint": "chrome",
            "network": "xhttp",
            "encryption": enc,
            "alpn": ["h2"],
            "xhttp-opts": {
                "path": xhttp_path,
                "mode": xhttp_mode or "auto",
                "host": domain,
                "no-grpc-header": True,
                "x-padding-bytes": "100-1000",
                "reuse-settings": {
                    "max-concurrency": "16-32",
                    "c-max-reuse-times": 0,
                    "h-max-request-times": "600-900",
                    "h-max-reusable-secs": "1800-3000",
                    "h-keep-alive-period": 15,
                },
            },
        })

    # XHTTP через CDN
    if cdn and xhttp_path and "xhttp" not in disabled:
        proxies.append({
            "name": users.get_config_name("XHTTP-CDN", label),
            "type": "vless",
            "server": connect_host,
            "port": 443,
            "uuid": uuid_val,
            "udp": True,
            "tls": True,
            "servername": domain,
            "client-fingerprint": "chrome",
            "network": "xhttp",
            "encryption": enc,
            "alpn": ["h2"],
            "xhttp-opts": {
                "path": xhttp_path,
                "mode": xhttp_cdn_mode or "auto",
                "host": domain,
                "no-grpc-header": False,
                "x-padding-bytes": "100-1000",
                "reuse-settings": {
                    "max-concurrency": "16-32",
                    "c-max-reuse-times": 0,
                    "h-max-request-times": "600-900",
                    "h-max-reusable-secs": "1800-3000",
                    "h-keep-alive-period": 15,
                },
            },
        })

    # WS только через CDN
    if cdn and ws_path and "ws" not in disabled:
        proxies.append({
            "name": users.get_config_name("WS", label),
            "type": "vless",
            "server": connect_host,
            "port": 443,
            "uuid": uuid_val,
            "udp": True,
            "tls": True,
            "servername": domain,
            "client-fingerprint": "chrome",
            "network": "ws",
            "encryption": enc,
            "ws-opts": {
                "path": ws_path,
                "headers": {"Host": domain},
            },
        })

    if pub_key and short_id and "reality" not in disabled:
        dest_host = reality_dest.split(":", 1)[0]
        if reality_mode == "xhttp":
            proxies.append({
                "name": users.get_config_name("Reality", label),
                "type": "vless",
                "server": server_ip,
                "port": int(reality_port_str),
                "uuid": uuid_val,
                "udp": True,
                "tls": True,
                "servername": dest_host,
                "client-fingerprint": "chrome",
                "reality-opts": {
                    "public-key": pub_key,
                    "short-id": short_id,
                    "support-x25519mlkem768": True,
                },
                "network": "xhttp",
                "encryption": "",
                "alpn": ["h2"],
                "xhttp-opts": {
                    "path": xhttp_path_reality or "/r",
                    "mode": _reality_xhttp_mode(xhttp_extra_mode),
                    "host": dest_host,
                    "no-grpc-header": True,
                    "x-padding-bytes": "100-1000",
                    "reuse-settings": {
                        "max-concurrency": "16-32",
                            "c-max-reuse-times": 0,
                        "h-max-request-times": "600-900",
                        "h-max-reusable-secs": "1800-3000",
                        "h-keep-alive-period": 15,
                    },
                },
            })
        else:
            proxies.append({
                "name": users.get_config_name("Reality", label),
                "type": "vless",
                "server": server_ip,
                "port": int(reality_port_str),
                "uuid": uuid_val,
                "udp": True,
                "flow": "xtls-rprx-vision",
                "encryption": "",
                "tls": True,
                "servername": dest_host,
                "client-fingerprint": "chrome",
                "reality-opts": {
                    "public-key": pub_key,
                    "short-id": short_id,
                    "support-x25519mlkem768": True,
                },
                "network": "tcp",
            })

    return proxies


def _yaml_str(val) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, list):
        return "[" + ", ".join(_yaml_str(v) for v in val) + "]"
    if isinstance(val, dict):
        lines = []
        for k, v in val.items():
            if isinstance(v, dict):
                lines.append(f"    {k}:")
                for kk, vv in v.items():
                    lines.append(f"      {kk}: {_yaml_str(vv)}")
            elif isinstance(v, list):
                lines.append(f"    {k}: {_yaml_str(v)}")
            else:
                lines.append(f"    {k}: {_yaml_str(v)}")
        return "\n".join(lines)
    s = str(val)
    reserved = {"y", "n", "yes", "no", "true", "false", "on", "off", "null", "~"}
    needs_quotes = (
        not s
        or " " in s
        or ":" in s
        or "#" in s
        or s.lower() in reserved
        or s[0] in "-?:,[]{}#&*!|>'\"%@`"
    )
    if needs_quotes:
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return s


def generate_mihomo_yaml(proxies: list[dict]) -> str:
    if not proxies:
        return "proxies: []\n"
    lines = ["proxies:"]
    for p in proxies:
        lines.append(f"  - name: {_yaml_str(p['name'])}")
        lines.append(f"    type: {p['type']}")
        lines.append(f"    server: {p['server']}")
        lines.append(f"    port: {p['port']}")
        lines.append(f"    uuid: {p['uuid']}")
        lines.append(f"    udp: {str(p.get('udp', True)).lower()}")
        if "flow" in p:
            lines.append(f"    flow: {p['flow']}")
        if "encryption" in p:
            lines.append(f'    encryption: "{p["encryption"]}"')
        lines.append(f"    tls: {str(p.get('tls', True)).lower()}")
        lines.append(f"    servername: {p['servername']}")
        lines.append(f"    client-fingerprint: {p.get('client-fingerprint', 'chrome')}")
        def _emit(key, value, indent):
            if isinstance(value, dict):
                lines.append(" " * indent + f"{key}:")
                for k, v in value.items():
                    _emit(k, v, indent + 2)
            else:
                lines.append(" " * indent + f"{key}: {_yaml_str(value)}")

        if "reality-opts" in p:
            lines.append("    reality-opts:")
            for k, v in p["reality-opts"].items():
                _emit(k, v, 6)
        if "network" in p:
            lines.append(f"    network: {p['network']}")
        if "alpn" in p:
            lines.append(f"    alpn: {_yaml_str(p['alpn'])}")
        if "grpc-opts" in p:
            lines.append("    grpc-opts:")
            for k, v in p["grpc-opts"].items():
                _emit(k, v, 6)
        if "xhttp-opts" in p:
            lines.append("    xhttp-opts:")
            for k, v in p["xhttp-opts"].items():
                _emit(k, v, 6)
        if "ws-opts" in p:
            lines.append("    ws-opts:")
            for k, v in p["ws-opts"].items():
                _emit(k, v, 6)
        lines.append("")
    return "\n".join(lines)


def write_sub_yaml(output_dir: str, label: str, token: str, proxies: list[dict]) -> str:
    os.makedirs(output_dir, exist_ok=True)
    safe = safe_label(label)
    filename = f"{safe}_{token}.yaml"
    path = os.path.join(output_dir, filename)
    content = generate_mihomo_yaml(proxies)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, 0o644)
    return path


def build_user_html_page(
    template_path: str,
    output_path: str,
    uuid_val: str,
    label: str,
    sub_url: str,
    lines: list[str],
    sub_yaml_url: str = "",
    page_title: str = "",
    cdn_ip: str = "",
    connect_host: str = "",
    domain: str = "",
    server_ip: str = "",
    flag_cached: str = "",
    has_dns: bool = False,
    dns_data: "dict | None" = None,
) -> str:
    import html as html_lib

    dns_data = dns_data or {}
    configs = []
    for line in lines:
        if not line.strip():
            continue
        if "security=reality" in line:
            cfg_type = "reality"
            proto_label = "Reality"
            m = re.search(r"@([^:]+)", line)
            host_disp = m.group(1) if m else (server_ip or "")
            cfg_cdn_ip = ""
        elif "type=grpc" in line:
            cfg_type = "grpc"
            proto_label = "gRPC + TLS"
            m = re.search(r"authority=([^&#]+)", line)
            host_disp = m.group(1) if m else (domain or "")
            cfg_cdn_ip = cdn_ip
        elif "type=xhttp" in line:
            cfg_type = "xhttp"
            proto_label = "XHTTP"
            m = re.search(r"host=([^&#]+)", line)
            host_disp = m.group(1) if m else (domain or "")
            sm = re.search(r"vless://[^@]+@([^:]+)", line)
            cfg_cdn_ip = cdn_ip if (sm and sm.group(1) == connect_host and cdn_ip) else ""
        elif "type=ws" in line:
            cfg_type = "ws"
            proto_label = "WS + TLS"
            m = re.search(r"host=([^&#]+)", line)
            host_disp = m.group(1) if m else (domain or "")
            sm = re.search(r"vless://[^@]+@([^:]+)", line)
            cfg_cdn_ip = cdn_ip if (sm and sm.group(1) == connect_host and cdn_ip) else ""
        else:
            cfg_type = "other"
            proto_label = "VLESS"
            host_disp = server_ip or ""
            cfg_cdn_ip = ""
        configs.append({
            "type": cfg_type,
            "proto_label": proto_label,
            "host": host_disp,
            "cdn_ip": cfg_cdn_ip,
            "url": line,
        })

    icons = {
        "grpc": '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        "reality": '<svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
        "xhttp": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
        "ws": '<svg viewBox="0 0 24 24"><path d="M4 12h16M4 6h16M4 18h16"/></svg>',
        "other": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>',
    }
    proto_tag_labels = {
        "grpc": "gRPC",
        "reality": "Reality",
        "xhttp": "XHTTP",
        "ws": "WS",
    }

    def render_card(cfg, idx):
        t = cfg["type"]
        icon = icons.get(t, icons["other"])
        url_safe = cfg["url"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        host_escaped = html_lib.escape(cfg["host"])
        if cfg["cdn_ip"]:
            host_html = f'{host_escaped}<span class="cfg-cdn-badge">CDN&nbsp;{html_lib.escape(cfg["cdn_ip"])}</span>'
        else:
            host_html = host_escaped
        return (
            f'<div class="cfg-card"><div class="cfg-icon {html_lib.escape(t)}">{icon}</div>'
            f'<div class="cfg-info"><div class="cfg-name">{html_lib.escape(cfg["proto_label"])}</div>'
            f'<div class="cfg-host">{host_html}</div></div>'
            f'<div class="cfg-btns"><div class="icon-btn" onclick="cp(\'cfg{idx}\',null)" title="Копировать">'
            f'<svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/>'
            f'<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></div>'
            f'<div class="icon-btn" onclick="tqr(\'qr{idx}\',\'cfg{idx}\',\'qrc{idx}\')" title="QR Code">'
            f'<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/>'
            f'<rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>'
            f'<rect x="14" y="14" width="3" height="3"/></svg></div></div></div>'
            f'<div id="cfg{idx}" style="display:none">{url_safe}</div>'
            f'<div class="qr-wrap" id="qr{idx}"><div class="qr-inner" id="qrc{idx}"></div></div>'
        )

    configs_html = "".join(render_card(c, i) for i, c in enumerate(configs))

    proto_tags = "".join(
        f'<span class="proto-tag">{proto_tag_labels.get(c["type"], "VLESS")}</span>'
        for c in configs if c["type"] in proto_tag_labels
    )
    if has_dns:
        proto_tags += '<span class="proto-tag">DNS</span>'

    all_configs_html = ""
    if len(configs) > 1:
        all_text = "\n".join(c["url"] for c in configs)
        all_safe = all_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        all_configs_html = (
            f'<div class="sec-lbl" style="margin-top:8px">Все конфиги</div>'
            f'<div class="all-box"><div class="url-text" id="cfgall">{all_safe}</div>'
            f'<div class="btn-row"><button class="btn-primary" onclick="cp(\'cfgall\',this)" '
            f'style="font-size:11px;padding:8px 14px">Копировать всё</button></div></div>'
        )

    with open(template_path, encoding="utf-8") as f:
        page = f.read()

    dns = dns_data
    dns_tab_btn = '<button class="tab" onclick="switchTab(\'dns\',this)">DNS Конфиги</button>' if has_dns else ""

    page_title = page_title or f"{flag_cached} {label} · {domain}"

    replacements = {
        "{{PAGE_TITLE}}": html_lib.escape(page_title),
        "{{USER_LABEL}}": html_lib.escape(label),
        "{{PROTO_TAGS}}": proto_tags,
        "{{SUB_URL}}": html_lib.escape(sub_url),
        "{{SUB_YAML_URL}}": html_lib.escape(sub_yaml_url),
        "{{CONFIGS_HTML}}": configs_html,
        "{{ALL_CONFIGS_HTML}}": all_configs_html,
        "{{DNS_TAB_BTN}}": dns_tab_btn,

    }
    for placeholder, value in replacements.items():
        page = page.replace(placeholder, value)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(page)
    os.chmod(output_path, 0o644)
    return output_path


def get_conf_or_fail(key: str) -> str:
    val = config.vwn_conf_get(key)
    if not val:
        raise RuntimeError(f"vwn.conf: {key} не задан")
    return val


def get_conf_or_none(key: str) -> "str | None":
    return config.vwn_conf_get(key)


def get_vless_encryption() -> str:
    return config.vwn_conf_get("VLESS_ENCRYPTION") or "none"


def get_disabled_protocols() -> set[str]:
    raw = config.vwn_conf_get("DISABLED_PROTOCOLS") or ""
    return {p.strip() for p in raw.split(",") if p.strip()}


def xhttp_direct_enabled() -> bool:
    """Публиковать ли direct-XHTTP в подписках (по умолчанию да)."""
    return (config.vwn_conf_get("XHTTP_DIRECT") or "on").lower() != "off"


def build_user_sub_file(
    uuid_val: str,
    label: str,
    token: str,
    domain: str,
    server_ip: str,
    output_dir: "str | None" = None,
    template_dir: "str | None" = None,
) -> None:
    """Сгенерировать .txt (base64) и .html для одного пользователя."""
    if output_dir is None:
        output_dir = SUB_DIR
    os.makedirs(output_dir, exist_ok=True)

    grpc_service = get_conf_or_none("GRPC_SERVICE") or ""
    grpc_mode = get_conf_or_none("GRPC_MODE") or "gun"
    xhttp_path = get_conf_or_none("XHTTP_PATH") or ""
    xhttp_mode = get_conf_or_none("XHTTP_MODE") or "auto"
    xhttp_cdn_mode = get_conf_or_none("XHTTP_CDN_MODE") or "auto"
    reality_port_str = get_conf_or_none("REALITY_PORT") or "443"
    reality_dest = get_conf_or_none("REALITY_DEST") or "microsoft.com:443"
    pub_key = get_conf_or_none("REALITY_PUBKEY") or ""
    short_id = get_conf_or_none("SHORT_ID") or ""

    connect_host = domain
    try:
        ch = Path(config.connect_host_file_path()).read_text().strip()
        if ch:
            connect_host = ch
    except (OSError, ValueError):
        pass
    cdn_ip = connect_host if connect_host != domain else ""

    lines: list[str] = []
    disabled = get_disabled_protocols()
    enc = get_vless_encryption()
    client_extra_direct = _xhttp_client_extra_json(cdn=False)
    client_extra_cdn = _xhttp_client_extra_json(cdn=True)

    # gRPC только через CDN
    if connect_host != domain and grpc_service and "grpc" not in disabled:
        name_grpc = users.get_config_name("gRPC", label)
        lines.append(generate_grpc_url(
            uuid_val, connect_host, 443, grpc_service, domain, name_grpc,
            mode=grpc_mode, vless_encryption=enc,
        ))

    # XHTTP direct (можно скрыть при включённом CDN)
    if xhttp_path and "xhttp" not in disabled and xhttp_direct_enabled():
        name_xhttp = users.get_config_name("XHTTP", label)
        lines.append(generate_xhttp_url(
            uuid_val, server_ip, 443, xhttp_path, domain, name_xhttp,
            mode=xhttp_mode, extra_json=client_extra_direct, vless_encryption=enc,
        ))

    # XHTTP через CDN
    if connect_host != domain and xhttp_path and "xhttp" not in disabled:
        name_xhttp_cdn = users.get_config_name("XHTTP-CDN", label)
        lines.append(generate_xhttp_url(
            uuid_val, connect_host, 443, xhttp_path, domain, name_xhttp_cdn,
            mode=xhttp_cdn_mode, extra_json=client_extra_cdn, vless_encryption=enc,
        ))

    # WS только через CDN
    ws_path_conf = get_conf_or_none("WS_PATH") or ""
    if connect_host != domain and ws_path_conf and "ws" not in disabled:
        name_ws = users.get_config_name("WS", label)
        lines.append(generate_ws_url(
            uuid_val, connect_host, 443, ws_path_conf, domain, name_ws,
            vless_encryption=enc,
        ))

    if pub_key and short_id and "reality" not in disabled:
        dest_host = reality_dest.split(":", 1)[0]
        name_reality = users.get_config_name("Reality", label)
        reality_mode = get_conf_or_none("REALITY_MODE") or "tcp"
        xhttp_path_reality = get_conf_or_none("REALITY_XHTTP_PATH") or ""
        xhttp_extra_mode = get_conf_or_none("REALITY_XHTTP_MODE") or "auto"
        lines.append(generate_reality_url(
            uuid_val, server_ip, int(reality_port_str),
            short_id, dest_host, pub_key, name_reality,
            mode=reality_mode, xhttp_path=xhttp_path_reality,
            xhttp_mode=xhttp_extra_mode, extra_json=client_extra_direct if reality_mode == "xhttp" else None,
            vless_encryption="none",
        ))

    write_sub_file(output_dir, label, token, lines)

    # YAML-подписка для mihomo (с ping-interval и т.д.)
    reality_mode = get_conf_or_none("REALITY_MODE") or "tcp"
    xhttp_path_reality = get_conf_or_none("REALITY_XHTTP_PATH") or ""
    xhttp_extra_mode = get_conf_or_none("REALITY_XHTTP_MODE") or "auto"
    ws_path_conf = get_conf_or_none("WS_PATH") or ""
    proxies = build_mihomo_proxies(
        uuid_val, label, domain, connect_host, server_ip,
        grpc_service, grpc_mode, xhttp_path, xhttp_mode,
        reality_port_str, reality_dest, pub_key, short_id,
        reality_mode, xhttp_path_reality, xhttp_extra_mode,
        disabled, ws_path=ws_path_conf, vless_encryption=get_vless_encryption(),
        xhttp_cdn_mode=xhttp_cdn_mode,
    )
    write_sub_yaml(output_dir, label, token, proxies)

    sub_url = f"https://{domain}/sub/{sub_filename(label, token)}"
    safe = safe_label(label)
    sub_yaml_url = f"https://{domain}/sub/{safe}_{token}.yaml"
    html_path = os.path.join(output_dir, f"{safe}_{token}.html")

    template_path = template_dir or os.path.join(
        os.path.dirname(__file__), "..", "data", "user_page.html"
    )
    build_user_html_page(
        template_path, html_path, uuid_val, label, sub_url, lines,
        sub_yaml_url=sub_yaml_url,
        domain=domain, server_ip=server_ip, cdn_ip=cdn_ip,
        connect_host=connect_host,
    )


def write_sub_map(conf_dir: str, country: str = "RU") -> str:
    """Написать sub_map.conf в nginx conf.d для map $uri $sub_label."""
    content = (
        "# Cloudflare real IP restore\n"
        "map $uri $sub_label {\n"
        f'    ~^/sub/(?<label>[A-Za-z0-9_-]+)_[A-Za-z0-9]+\\.txt$  "{country} VLESS | $label";\n'
        f'    ~^/sub/(?<label>[A-Za-z0-9_-]+)_[A-Za-z0-9]+\\.yaml$ "{country} VLESS | $label";\n'
        f'    default                                                "{country} VLESS";\n'
        "}\n"
    )
    os.makedirs(conf_dir, exist_ok=True)
    path = os.path.join(conf_dir, "sub_map.conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, 0o644)
    return path


def rebuild_all_sub_files(
    output_dir: str = SUB_DIR,
    template_dir: "str | None" = None,
    refresh_ip: bool = False,
) -> int:
    """Пересобрать подписки для всех пользователей из users.conf.

    При refresh_ip=True заново определяет внешний IP и флаг страны.
    Возвращает количество обработанных пользователей.
    """
    domain = get_conf_or_none("DOMAIN")
    server_ip = get_conf_or_none("SERVER_IP")
    if refresh_ip:
        try:
            from vwn.core import system
            current = system.get_server_ip()
            if current and current != "UNKNOWN" and current != server_ip:
                config.vwn_conf_set("SERVER_IP", current)
                server_ip = current
        except Exception:
            pass
        users.get_cached_flag(force_refresh=True)
    if not domain or not server_ip:
        print("Подписки не пересобраны: нет DOMAIN или SERVER_IP", file=sys.stderr)
        return 0

    users.init_users_file()
    if not os.path.isfile(users.USERS_FILE):
        print("Подписки не пересобраны: нет users.conf", file=sys.stderr)
        return 0

    write_sub_map(config.NGINX_CONF_DIR)
    count = 0
    for u in users.list_users():
        build_user_sub_file(u["uuid"], u["label"], u["token"],
                            domain, server_ip,
                            output_dir=output_dir, template_dir=template_dir)
        count += 1
    if count == 0:
        print("Подписки не пересобраны: нет пользователей", file=sys.stderr)
    return count


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "rebuild":
        rebuild_all_sub_files()
