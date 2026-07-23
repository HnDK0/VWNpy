"""Многопользовательский менеджер: users.conf, apply, подписки, имена.

Формат users.conf: UUID|LABEL|TOKEN (построчно, без заголовков).
Sub URL: https://<domain>/sub/<label>_<token>.txt
"""

import json
import os
import re
import secrets
import string
import urllib.request
import uuid as uuid_mod

from vwn.core import config, shell

USERS_FILE = "/usr/local/etc/xray/users.conf"
SUB_DIR = "/usr/local/etc/xray/sub"

_VWN_FLAG_CACHE: str | None = None


# ── helpers ─────────────────────────────────────────────────────

def _read_lines(path: str) -> list[str]:
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f if l.strip()]


def _write_lines(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def safe_label(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "", label)


def sub_filename(label: str, token: str) -> str:
    return f"{safe_label(label)}_{token}.txt"


def generate_token(length: int = 32) -> str:
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


def users_count() -> int:
    return len(_read_lines(USERS_FILE))


def list_users() -> list[dict]:
    """Вернуть [{uuid, label, token}, ...] из users.conf."""
    result = []
    for line in _read_lines(USERS_FILE):
        parts = line.split("|", 2)
        if len(parts) >= 2:
            result.append({
                "uuid": parts[0],
                "label": parts[1],
                "token": parts[2] if len(parts) > 2 else "",
            })
    return result


def _uuid_by_line(line_no: int) -> str:
    lines = _read_lines(USERS_FILE)
    if 0 < line_no <= len(lines):
        return lines[line_no - 1].split("|", 1)[0]
    return ""


def _label_by_line(line_no: int) -> str:
    lines = _read_lines(USERS_FILE)
    if 0 < line_no <= len(lines):
        return lines[line_no - 1].split("|", 2)[1]
    return ""


def _token_by_line(line_no: int) -> str:
    lines = _read_lines(USERS_FILE)
    if 0 < line_no <= len(lines):
        parts = lines[line_no - 1].split("|", 2)
        return parts[2] if len(parts) > 2 else ""
    return ""


# ── флаги и имена конфигов ─────────────────────────────────────

def _country_code_to_flag(code: str) -> str:
    if len(code) == 2 and code.isalpha():
        return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code.upper())
    return "\U0001f310"


def get_country_flag(ip: str) -> str:
    try:
        url = f"https://ip-api.com/line/{ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=5) as resp:
            code = resp.read().decode().strip()
        return _country_code_to_flag(code)
    except Exception:
        return "\U0001f310"


def get_cached_flag() -> str:
    global _VWN_FLAG_CACHE
    if _VWN_FLAG_CACHE is None:
        ip = config.vwn_conf_get("SERVER_IP") or ""
        _VWN_FLAG_CACHE = get_country_flag(ip) if ip else "\U0001f310"
    return _VWN_FLAG_CACHE


def _read_json(path: str) -> dict | None:
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def get_active_modes_suffix() -> str:
    suffix = ""
    ws_cfg = _read_json(os.path.join(config.XRAY_DIR, "config.json"))
    if ws_cfg is None:
        return ""
    rules = ws_cfg.get("routing", {}).get("rules", [])

    def is_global(tag: str) -> bool:
        for r in rules:
            if r.get("outboundTag") == tag and not r.get("inboundTag") and r.get("port") == "0-65535":
                return True
        return False

    warp_g = is_global("warp")
    psiphon_g = is_global("psiphon")
    relay_g = is_global("relay")
    tor_g = is_global("tor")

    if not any([warp_g, psiphon_g, relay_g, tor_g]):
        return ""

    suffix = " \U0001f310"

    if warp_g:
        try:
            with urllib.request.urlopen(
                "https://ip-api.com/line/?fields=countryCode", timeout=5
            ) as resp:
                code = resp.read().decode().strip()
            suffix += " \u2601\ufe0f" + _country_code_to_flag(code) if len(code) == 2 and code.isalpha() else " \u2601\ufe0f"
        except Exception:
            suffix += " \u2601\ufe0f"

    if psiphon_g:
        ps_config = _read_json("/usr/local/etc/xray/psiphon_config.json")
        ps_country = (ps_config or {}).get("EgressRegion", "")
        if ps_country:
            suffix += " \U0001f531" + _country_code_to_flag(ps_country)
        else:
            suffix += " \U0001f531"

    if relay_g:
        relay_cfg_file = "/usr/local/etc/xray/relay.conf"
        relay_host = ""
        if os.path.isfile(relay_cfg_file):
            with open(relay_cfg_file) as f:
                for line in f:
                    if line.startswith("RELAY_HOST="):
                        relay_host = line.split("=", 1)[1].strip()
                        break
        if relay_host:
            try:
                url = f"https://ip-api.com/line/{relay_host}?fields=countryCode"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    code = resp.read().decode().strip()
                suffix += " \U0001f309" + _country_code_to_flag(code) if len(code) == 2 and code.isalpha() else " \U0001f309"
            except Exception:
                suffix += " \U0001f309"
        else:
            suffix += " \U0001f309"

    if tor_g:
        tor_cfg = "/etc/tor/torrc"
        tor_country = ""
        if os.path.isfile(tor_cfg):
            with open(tor_cfg) as f:
                m = re.search(r"ExitNodes\s+\{([A-Z]+)\}", f.read())
                if m:
                    tor_country = m.group(1)
        if tor_country:
            suffix += " \U0001f9c5" + _country_code_to_flag(tor_country)
        else:
            suffix += " \U0001f9c5"

    return suffix.strip()


def get_config_name(type_: str, label: str) -> str:
    flag = get_cached_flag()
    modes = get_active_modes_suffix()
    if type_ == "WS":
        return f"{flag} VL-WS | {label} {flag}{modes}"
    elif type_ == "Reality":
        r_mode = config.vwn_conf_get("REALITY_MODE") or "tcp"
        if r_mode == "xhttp":
            return f"{flag} VL-Reality-XHTTP | {label} {flag}{modes}"
        return f"{flag} VL-Reality | {label} {flag}{modes}"
    elif type_ == "XHTTP":
        return f"{flag} VL-XHTTP | {label} {flag}{modes}"
    return f"{flag} VL-{type_} | {label} {flag}{modes}"


# ── CRUD ────────────────────────────────────────────────────────

def init_users_file() -> None:
    if os.path.isfile(USERS_FILE):
        return
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    existing_uuid = config.vwn_conf_get("UUID") or ""
    if not existing_uuid:
        return
    token = generate_token()
    suffix = secrets.token_hex(3)
    label = f"default_{suffix}"
    _write_lines(USERS_FILE, [f"{existing_uuid}|{label}|{token}"])
    apply_users_to_configs()
    from vwn.modules.sub import build_user_sub_file
    domain = config.vwn_conf_get("DOMAIN") or ""
    server_ip = config.vwn_conf_get("SERVER_IP") or ""
    build_user_sub_file(existing_uuid, label, token, domain, server_ip)


def add_user(label: str | None = None) -> dict:
    init_users_file()
    if not label:
        label = f"user{users_count() + 1}"
    label = label.replace("|", "")
    uuid_val = str(uuid_mod.uuid4())
    token = generate_token()
    lines = _read_lines(USERS_FILE)
    lines.append(f"{uuid_val}|{label}|{token}")
    _write_lines(USERS_FILE, lines)
    apply_users_to_configs()
    from vwn.modules.sub import build_user_sub_file
    domain = config.vwn_conf_get("DOMAIN") or ""
    server_ip = config.vwn_conf_get("SERVER_IP") or ""
    build_user_sub_file(uuid_val, label, token, domain, server_ip)
    return {"uuid": uuid_val, "label": label, "token": token}


def remove_user(line_no: int) -> bool:
    lines = _read_lines(USERS_FILE)
    if line_no < 1 or line_no > len(lines):
        return False
    parts = lines[line_no - 1].split("|")
    label = parts[1] if len(parts) > 1 else ""
    safe = safe_label(label)
    if os.path.isdir(SUB_DIR):
        for f in os.listdir(SUB_DIR):
            if f.startswith(safe + "_") and (f.endswith(".txt") or f.endswith(".html")):
                os.remove(os.path.join(SUB_DIR, f))
    lines.pop(line_no - 1)
    _write_lines(USERS_FILE, lines)
    apply_users_to_configs()
    return True


def rename_user(line_no: int, new_label: str) -> bool:
    lines = _read_lines(USERS_FILE)
    if line_no < 1 or line_no > len(lines):
        return False
    parts = lines[line_no - 1].split("|")
    old_safe = safe_label(parts[1]) if len(parts) > 1 else ""
    if os.path.isdir(SUB_DIR):
        for f in os.listdir(SUB_DIR):
            if f.startswith(old_safe + "_") and (f.endswith(".txt") or f.endswith(".html")):
                os.remove(os.path.join(SUB_DIR, f))
    new_label = safe_label(new_label.replace("|", ""))
    if not new_label:
        return False
    parts[1] = new_label
    uuid_val = parts[0]
    token = parts[2] if len(parts) > 2 else ""
    lines[line_no - 1] = "|".join(parts)
    _write_lines(USERS_FILE, lines)
    apply_users_to_configs()
    from vwn.modules.sub import build_user_sub_file
    domain = config.vwn_conf_get("DOMAIN") or ""
    server_ip = config.vwn_conf_get("SERVER_IP") or ""
    build_user_sub_file(uuid_val, new_label, token, domain, server_ip)
    return True


def rekey_user(line_no: int) -> str | None:
    lines = _read_lines(USERS_FILE)
    if line_no < 1 or line_no > len(lines):
        return None
    new_uuid = str(uuid_mod.uuid4())
    parts = lines[line_no - 1].split("|")
    parts[0] = new_uuid
    label = parts[1] if len(parts) > 1 else ""
    token = parts[2] if len(parts) > 2 else ""
    lines[line_no - 1] = "|".join(parts)
    _write_lines(USERS_FILE, lines)
    apply_users_to_configs()
    from vwn.modules.sub import build_user_sub_file
    domain = config.vwn_conf_get("DOMAIN") or ""
    server_ip = config.vwn_conf_get("SERVER_IP") or ""
    build_user_sub_file(new_uuid, label, token, domain, server_ip)
    return new_uuid


def reissue_token(line_no: int) -> str | None:
    lines = _read_lines(USERS_FILE)
    if line_no < 1 or line_no > len(lines):
        return None
    parts = lines[line_no - 1].split("|")
    new_token = generate_token()
    if len(parts) < 3:
        parts.append(new_token)
    else:
        parts[2] = new_token
    lines[line_no - 1] = "|".join(parts)
    _write_lines(USERS_FILE, lines)
    from vwn.modules.sub import build_user_sub_file
    domain = config.vwn_conf_get("DOMAIN") or ""
    server_ip = config.vwn_conf_get("SERVER_IP") or ""
    build_user_sub_file(parts[0], parts[1], new_token, domain, server_ip)
    return new_token


# ── apply / rebuild ─────────────────────────────────────────────

def apply_users_to_configs() -> None:
    users_list = list_users()
    if not users_list:
        return
    clients_r = [{"id": u["uuid"], "flow": "xtls-rprx-vision", "email": u["label"]}
                 for u in users_list]
    clients_x = [{"id": u["uuid"], "email": u["label"]} for u in users_list]

    ws_path = os.path.join(config.XRAY_DIR, "config.json")
    ws_cfg = _read_json(ws_path)
    if ws_cfg:
        ws_cfg["inbounds"][0]["settings"]["clients"] = clients_x
        _write_json(ws_path, ws_cfg)

    xh_path = os.path.join(config.XRAY_DIR, "xhttp.json")
    xh_cfg = _read_json(xh_path)
    if xh_cfg:
        xh_cfg["inbounds"][0]["settings"]["clients"] = clients_x
        _write_json(xh_path, xh_cfg)

    reality_path = os.path.join(config.XRAY_DIR, "xray-reality.json")
    r_cfg = _read_json(reality_path)
    if r_cfg:
        r_cfg["inbounds"][0]["settings"]["clients"] = clients_r
        _write_json(reality_path, r_cfg)

    shell.run(["systemctl", "daemon-reload"], check=False)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        shell.run(["systemctl", "restart", svc], check=False)


def _write_json(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def get_sub_url(label: str, token: str) -> str | None:
    domain = config.vwn_conf_get("DOMAIN")
    if not domain:
        return None
    return f"https://{domain}/sub/{sub_filename(label, token)}"
