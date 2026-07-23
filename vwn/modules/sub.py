"""Генерация VLESS-ссылок, файлов подписок и HTML-страниц пользователей.

Зависит от vwn.conf (DOMAIN, UUID, WS_PATH, XHTTP_PATH, REALITY_DEST,
REALITY_PORT, REALITY_PUBKEY, SHORT_ID, XHTTP_MODE) для построения URL.
"""

import base64
import os
import re
import secrets
import string
from pathlib import Path

from vwn.core import config, render
from vwn.modules import users

SUB_DIR = "/usr/local/etc/xray/sub"


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
    xhttp_extra: str = "",
) -> str:
    base = (
        f"vless://{uuid_val}@{server_ip}:{port}"
        f"?encryption=none&security=reality"
        f"&sni={dest_host}&fp=chrome&pbk={pub_key}&sid={short_id}"
    )
    if mode == "xhttp":
        path = xhttp_path or "/r"
        extra = f"&path={_urlencode(path)}&mode={xhttp_extra or 'auto'}&host={dest_host}"
        return f"{base}&type=xhttp{extra}#{_urlencode(name)}"
    return f"{base}&type=tcp&flow=xtls-rprx-vision#{_urlencode(name)}"


def generate_ws_url(
    uuid_val: str,
    connect_host: str,
    port: int,
    ws_path: str,
    domain: str,
    name: str,
) -> str:
    encoded_path = _urlencode(ws_path)
    return (
        f"vless://{uuid_val}@{connect_host}:{port}"
        f"?encryption=none&security=tls"
        f"&sni={domain}&fp=chrome&alpn=http%2F1.1"
        f"&type=ws&host={domain}&path={encoded_path}"
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
) -> str:
    encoded_path = _urlencode(xhttp_path)
    return (
        f"vless://{uuid_val}@{connect_host}:{port}"
        f"?security=tls&type=xhttp&path={encoded_path}"
        f"&mode={mode}&alpn=h2&host={domain}&sni={domain}"
        f"&fp=chrome"
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
        if f.startswith(safe + "_") and (f.endswith(".txt") or f.endswith(".html")):
            os.remove(os.path.join(output_dir, f))
    filename = sub_filename(label, token)
    path = os.path.join(output_dir, filename)
    raw = "\n".join(lines)
    b64 = base64.b64encode(raw.encode()).decode()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(b64)
    os.chmod(path, 0o644)
    return path


def build_user_html_page(
    template_path: str,
    output_path: str,
    uuid_val: str,
    label: str,
    sub_url: str,
    lines: list[str],
    page_title: str = "",
    cdn_ip: str = "",
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
        elif "type=ws" in line:
            cfg_type = "ws"
            proto_label = "WS + TLS"
            m = re.search(r"host=([^&]+)", line)
            host_disp = m.group(1) if m else (domain or "")
            cfg_cdn_ip = cdn_ip
        elif "type=xhttp" in line:
            cfg_type = "xhttp"
            proto_label = "XHTTP"
            m = re.search(r"host=([^&]+)", line)
            host_disp = m.group(1) if m else (domain or "")
            cfg_cdn_ip = cdn_ip
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
        "ws": '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        "reality": '<svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
        "xhttp": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
        "other": '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>',
    }
    proto_tag_labels = {
        "ws": "WebSocket",
        "reality": "Reality",
        "xhttp": "XHTTP",
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

    ws_path = get_conf_or_none("WS_PATH") or ""
    xhttp_path = get_conf_or_none("XHTTP_PATH") or ""
    xhttp_mode = get_conf_or_none("XHTTP_MODE") or "auto"
    reality_port_str = get_conf_or_none("REALITY_PORT") or "443"
    reality_dest = get_conf_or_none("REALITY_DEST") or "microsoft.com:443"
    pub_key = get_conf_or_none("REALITY_PUBKEY") or ""
    short_id = get_conf_or_none("SHORT_ID") or ""

    connect_host = domain
    try:
        ch = Path(config.CONNECT_HOST_FILE).read_text().strip()
        if ch:
            connect_host = ch
    except (OSError, ValueError):
        pass

    lines: list[str] = []

    if ws_path:
        name_ws = users.get_config_name("WS", label)
        lines.append(generate_ws_url(
            uuid_val, connect_host, 443, ws_path, domain, name_ws,
        ))

    if xhttp_path:
        name_xhttp = users.get_config_name("XHTTP", label)
        lines.append(generate_xhttp_url(
            uuid_val, connect_host, 443, xhttp_path, domain, name_xhttp,
            mode=xhttp_mode,
        ))

    if pub_key and short_id:
        dest_host = reality_dest.split(":", 1)[0]
        name_reality = users.get_config_name("Reality", label)
        reality_mode = get_conf_or_none("REALITY_MODE") or "tcp"
        xhttp_path_reality = get_conf_or_none("REALITY_XHTTP_PATH") or ""
        xhttp_extra_mode = get_conf_or_none("REALITY_XHTTP_MODE") or "auto"
        lines.append(generate_reality_url(
            uuid_val, server_ip, int(reality_port_str),
            short_id, dest_host, pub_key, name_reality,
            mode=reality_mode, xhttp_path=xhttp_path_reality,
            xhttp_extra=xhttp_extra_mode,
        ))

    write_sub_file(output_dir, label, token, lines)

    sub_url = f"https://{domain}/sub/{sub_filename(label, token)}"
    safe = safe_label(label)
    html_path = os.path.join(output_dir, f"{safe}_{token}.html")

    template_path = template_dir or os.path.join(
        os.path.dirname(__file__), "..", "data", "user_page.html"
    )
    build_user_html_page(
        template_path, html_path, uuid_val, label, sub_url, lines,
        domain=domain, server_ip=server_ip,
    )


def write_sub_map(conf_dir: str, country: str = "RU") -> str:
    """Написать sub_map.conf в nginx conf.d для map $uri $sub_label."""
    content = (
        "# Cloudflare real IP restore\n"
        "map $uri $sub_label {\n"
        f'    ~^/sub/(?<label>[A-Za-z0-9_-]+)_[A-Za-z0-9]+\\.txt$  "{country} VLESS | $label";\n'
        f'    default                                                "{country} VLESS";\n'
        "}\n"
    )
    path = os.path.join(conf_dir, "sub_map.conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, 0o644)
    return path


def rebuild_all_sub_files(
    output_dir: str = SUB_DIR,
    template_dir: "str | None" = None,
) -> int:
    """Пересобрать подписки для всех пользователей из users.conf.

    Возвращает количество обработанных пользователей.
    """
    domain = get_conf_or_none("DOMAIN")
    server_ip = get_conf_or_none("SERVER_IP")
    if not domain or not server_ip:
        return 0

    users.init_users_file()
    if not os.path.isfile(users.USERS_FILE):
        return 0

    write_sub_map(config.NGINX_CONF_DIR)
    count = 0
    for u in users.list_users():
        build_user_sub_file(u["uuid"], u["label"], u["token"],
                            domain, server_ip,
                            output_dir=output_dir, template_dir=template_dir)
        count += 1
    return count


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "rebuild":
        rebuild_all_sub_files()
