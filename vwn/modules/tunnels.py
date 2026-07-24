"""Общая логика туннелей исходящего трафика (warp/psiphon/tor/relay).

ИСПРАВЛЕНИЕ бага 1.3: вместо копипасты определения режима в каждом
модуле — одна функция get_tunnel_mode(), переиспользуемая всеми.
"""

import json

from vwn.core import shell
from vwn.core.color import C


def get_tunnel_mode(cfg: dict, tag: str) -> str:
    """Определить режим туннеля по конфигу Xray (dict).

    Global — правило с port="0-65535"; Split — правило с доменами;
    иначе OFF.
    """
    rules = (cfg.get("routing", {}) or {}).get("rules", []) or []
    for rule in rules:
        if rule.get("outboundTag") != tag:
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


def render_tunnel_status(name: str, mode: str, active: bool) -> str:
    """Единый формат строки статуса туннеля для меню/диагностики."""
    if not active:
        state = C["red"] + "OFF" + C["reset"]
    elif mode == "Global":
        state = C["green"] + "ACTIVE | Global" + C["reset"]
    elif mode == "Split":
        state = C["green"] + "ACTIVE | Split" + C["reset"]
    else:
        state = C["yellow"] + "ACTIVE | OFF" + C["reset"]
    return f"{name:10} : {state}"


def service_active(service: str) -> bool:
    return shell.service_active(service)
