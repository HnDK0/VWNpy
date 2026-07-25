"""Общая логика туннелей исходящего трафика (warp/psiphon/tor/relay).

ИСПРАВЛЕНИЕ бага 1.3: вместо копипасты определения режима в каждом
модуле — одна функция get_tunnel_mode(), переиспользуемая всеми.
"""

import json

from vwn.core import shell
from vwn.core.color import C

_TUNNEL_TAGS = {"warp", "psiphon", "tor", "relay"}


def _is_any_tunnel_tag(tag: str) -> bool:
    return tag in _TUNNEL_TAGS or tag.startswith("warp-")


def insert_before_catchall(rules: list, rule: dict) -> None:
    """Вставить routing rule перед catch-all (port 0-65535 → не-tunnel outbound).

    Xray: first-match. Catch-all должен быть последним.
    DNS, ads, private, bittorrent — ДО туннеля.
    Туннельный rule — перед catch-all, после всего остального.
    """
    for i, r in enumerate(rules):
        if r.get("port") == "0-65535" and not _is_any_tunnel_tag(r.get("outboundTag", "")):
            rules.insert(i, rule)
            return
    rules.append(rule)


def _match_tunnel_tag(outbound_tag: str, tag: str) -> bool:
    if tag == "warp":
        return outbound_tag.startswith("warp-") or outbound_tag == "warp"
    return outbound_tag == tag


def get_tunnel_mode(cfg: dict, tag: str) -> str:
    """Определить режим туннеля по конфигу Xray (dict).

    Global — правило с port="0-65535"; Split — правило с доменами;
    иначе OFF.
    """
    rules = (cfg.get("routing", {}) or {}).get("rules", []) or []
    for rule in rules:
        if not _match_tunnel_tag(rule.get("outboundTag", ""), tag):
            continue
        if rule.get("inboundTag"):
            continue
        if rule.get("port") == "0-65535":
            return "Global"
        if len(rule.get("domain", []) or []) > 0:
            return "Split"
        return "OFF"
    return "OFF"


def get_tunnel_mode_from_file(path: str, tag: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return "OFF"
    return get_tunnel_mode(cfg, tag)


def render_tunnel_status(name: str, mode: str, active: bool, country: str = "", method: str = "") -> str:
    if not active:
        state = C["red"] + "OFF" + C["reset"]
    elif mode == "Global":
        state = C["green"] + "ACTIVE | Global" + C["reset"]
    elif mode == "Split":
        state = C["green"] + "ACTIVE | Split" + C["reset"]
    else:
        state = C["yellow"] + "ACTIVE | OFF" + C["reset"]
    if method:
        state = state.replace("ACTIVE", f"ACTIVE | {method}", 1)
    if country:
        state += f" ({country})"
    return f"{name:10} : {state}"


def service_active(service: str) -> bool:
    return shell.service_active(service)
