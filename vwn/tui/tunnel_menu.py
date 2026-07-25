"""Подменю туннелей (WARP, Psiphon, Tor, Relay)."""

import collections.abc
import json
import os

from vwn.core import config, shell
from vwn.core.color import console
from vwn.modules.tunnels import _is_any_tunnel_tag, insert_before_catchall
from vwn.tui.helpers import pick_country, restart_xray_services, run_cmd, run_task, wait_key


def _switch_tunnel_mode(tag: str, mode: str) -> str:
    if not os.path.isfile(os.path.join(config.XRAY_DIR, "config.json")):
        return tag
    from vwn.modules._outbound import _paths
    from vwn.modules.tunnels import _match_tunnel_tag
    actual_tag = _resolve_actual_tag(tag)
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = json.load(f)
        rules = cfg.setdefault("routing", {}).setdefault("rules", [])
        rules = [r for r in rules if not (_match_tunnel_tag(r.get("outboundTag", ""), tag) and "inboundTag" not in r)]
        if mode == "Global":
            rules = [r for r in rules
                     if not (_is_any_tunnel_tag(r.get("outboundTag", ""))
                             and r.get("port") == "0-65535")]
            insert_before_catchall(rules, {"type": "field", "port": "0-65535", "outboundTag": actual_tag})
        elif mode == "Split":
            from vwn.modules._domains import list_domains
            domains = list_domains(actual_tag)
            if not domains:
                domains = ["whoer.net"]
            domains_json = [f"domain:{d}" for d in domains]
            insert_before_catchall(rules, {"type": "field", "domain": domains_json, "outboundTag": actual_tag})
        cfg["routing"]["rules"] = rules
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    from vwn.core import config as _cfg
    conf_key = f"{tag.upper()}_TUNNEL_MODE"
    if mode != "OFF":
        _cfg.vwn_conf_set(conf_key, mode)
    else:
        _cfg.vwn_conf_del(conf_key)
    return actual_tag


def _resolve_actual_tag(tag: str) -> str:
    """Определить реальный outbound tag для туннеля.

    Для warp: читаем WARP_METHOD из vwn.conf и резолвим через _tag_for_method().
    Для остальных: tag используется напрямую.
    """
    if tag == "warp":
        from vwn.modules.warp import _tag_for_method
        method = config.vwn_conf_get("WARP_METHOD") or ""
        if method:
            return _tag_for_method(method)
    return tag


def manage_tunnel(name: str, svc: str, tag: str, has_install: bool = False,
                  has_configure: bool = False,
                  extra: dict[str, collections.abc.Callable[[], None]] | None = None) -> None:
    from vwn.modules.tunnels import get_tunnel_mode_from_file, render_tunnel_status
    while True:
        config_path = os.path.join(config.XRAY_DIR, "config.json")
        mode = get_tunnel_mode_from_file(config_path, tag)
        active = shell.service_active(svc) if svc else False
        country = ""
        method = ""
        if tag == "warp":
            from vwn.modules.warp import status as warp_st
            ws = warp_st()
            active = bool(ws["method"])
            method = ws.get("method", "")
        elif tag == "psiphon":
            from vwn.modules.psiphon import status as ps_st
            ps = ps_st()
            active = ps["active"]
            country = ps.get("country", "")
        elif tag == "tor":
            from vwn.modules.tor import status as tor_st
            ts = tor_st()
            active = ts["active"]
            country = ts.get("country", "")
        console.print(f"\n[bold]{name}[/]")
        console.print(f"  Статус: {render_tunnel_status(name, mode, active, country, method)}")
        idx = 1
        if has_install:
            console.print(f"  {idx}. Установить")
            idx += 1
            console.print(f"  {idx}. Удалить")
            idx += 1
        if has_configure:
            console.print(f"  {idx}. Настроить")
            idx += 1
        console.print(f"  {idx}. Глобальный режим"); idx += 1
        console.print(f"  {idx}. Раздельный режим"); idx += 1
        console.print(f"  {idx}. Выключить"); idx += 1
        extra_start = idx
        if extra:
            for label in extra:
                console.print(f"  {idx}. {label}")
                idx += 1
        if svc:
            console.print(f"  {idx}. Перезапустить"); idx += 1
            console.print(f"  {idx}. Показать логи"); idx += 1
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif has_install and val == "1":
            if tag == "warp":
                console.print("  Выберите метод:")
                console.print("    1. native (wgcf→WireGuard, ~0 MB)")
                console.print("    2. amnezia (AmneziaWG, ~20 MB)")
                console.print("    3. warp-svc (legacy, ~200 MB)")
                m = input("> ").strip()
                method = {"1": "native", "2": "amnezia", "3": "warp-svc"}.get(m, "native")
                from vwn.modules.warp import install as warp_install
                run_task("Установка WARP", lambda: warp_install(method))
            elif tag == "psiphon":
                from vwn.modules.psiphon import COUNTRIES as PS_COUNTRIES
                country = pick_country(PS_COUNTRIES)
                console.print("  Режим туннеля:")
                console.print("    1. Plain  — прямое подключение к Psiphon")
                console.print("    2. Warp   — Psiphon поверх WARP")
                tm = input("> ").strip()
                tmode = "warp" if tm == "2" else "plain"
                from vwn.modules.psiphon import install as ps_install
                run_task("Установка Psiphon",
                          lambda: ps_install(country, tmode))
            elif tag == "tor":
                from vwn.modules.tor import COUNTRIES as TOR_COUNTRIES
                country = pick_country(TOR_COUNTRIES)
                from vwn.modules.tor import install as tor_install
                run_task("Установка Tor",
                          lambda: tor_install(country))
            wait_key()
        elif has_install and val == "2":
            if tag == "warp":
                from vwn.modules.warp import remove as warp_remove
                run_task("Удаление WARP", warp_remove)
            elif tag == "psiphon":
                from vwn.modules.psiphon import remove as ps_remove
                run_task("Удаление Psiphon", ps_remove)
            elif tag == "tor":
                from vwn.modules.tor import remove as tor_remove
                run_task("Удаление Tor", tor_remove)
            wait_key()
        elif has_configure and val == "1":
            console.print("  URL релея (vless:// vmess:// trojan:// socks5://):")
            url = input("> ").strip()
            if url:
                from vwn.modules.relay import configure as relay_cfg
                run_task("Настройка релея", lambda: relay_cfg(url))
            wait_key()
        else:
            offset = 1
            if has_install:
                offset += 2
            if has_configure:
                offset += 1
            if val == str(offset):
                _switch_tunnel_mode(tag, "Global")
                restart_xray_services()
                wait_key()
            elif val == str(offset + 1):
                _switch_tunnel_mode(tag, "Split")
                restart_xray_services()
                wait_key()
            elif val == str(offset + 2):
                _switch_tunnel_mode(tag, "OFF")
                restart_xray_services()
                wait_key()
            elif extra and val.isdigit() and extra_start <= int(val) < extra_start + len(extra):
                label = list(extra.keys())[int(val) - extra_start]
                extra[label]()
                wait_key()
            elif svc and val == str(offset + 3 + (len(extra) if extra else 0)):
                run_cmd(f"systemctl restart {svc}")
                wait_key()
            elif svc and val == str(offset + 4 + (len(extra) if extra else 0)):
                if svc == "psiphon.service":
                    log = "/var/log/psiphon/psiphon.log"
                    if os.path.isfile(log):
                        run_cmd(f"tail -n 50 {log}")
                    else:
                        run_cmd(f"journalctl -u {svc} -n 50 --no-pager")
                else:
                    run_cmd(f"journalctl -u {svc} -n 50 --no-pager")
                wait_key()
