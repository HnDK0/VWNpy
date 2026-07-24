"""Дашборд VWN — Rich Panel со статусами протоколов, CDN, туннелей, безопасности."""

import datetime

from rich.panel import Panel

from vwn.core import config
from vwn.core.color import console
from vwn.tui.helpers import cert_days, onoff, service_status, sub_status


def dashboard() -> None:
    from vwn.modules.cdn import status as _cdn_status
    from vwn.modules.warp import status as _warp_status
    from vwn.modules.psiphon import status as _ps_status
    from vwn.modules.tor import status as _tor_status
    from vwn.modules.relay import status as _relay_status
    from vwn.modules.security import (bbr_status, fail2ban_status,
                                       webjail_status, ipv6_status,
                                       cpu_guard_status)

    now = datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
    lines: list[str] = []

    svcs = [service_status(s) for s in
            ("xray-reality.service", "xray-ws.service",
             "xray-xhttp.service", "nginx.service")]
    lines.append(f"[bold]Протоколы:[/]    {'  '.join(svcs)}")

    cdn = _cdn_status()
    dmode = cdn["mode"]
    cdn_info = f"[bright_green]{dmode}[/]"
    if cdn["ip"]:
        cdn_info += f" | [cyan]{cdn['ip']}[/]"
        if cdn["ping_ms"]:
            cdn_info += f" ({cdn['ping_ms']}ms)"
    elif cdn.get("watcher"):
        cdn_info += " [yellow]сканирование...[/]"
    else:
        cdn_info += " [red]нет IP[/]"
    if cdn.get("watcher"):
        cdn_info += " [bright_black]w[/]"
    if cdn.get("found_count", 0):
        cdn_info += f" [{cdn['found_count']} найдено]"
    domain = config.vwn_conf_get("DOMAIN") or "?"
    server_ip = config.vwn_conf_get("SERVER_IP") or "?"
    ssl = cert_days()
    subs = sub_status()
    lines.append(f"[bold]CDN:[/] {cdn_info}    [bold]SSL:[/] {ssl}    [bold]Подписки:[/] {subs}")
    lines.append(f"[bold]Домен:[/] [cyan]{domain}[/] ([blue]{server_ip}[/])")

    warp = _warp_status()
    ws = onoff(warp["active"])
    if warp["active"] and warp["method"]:
        ws += f" | {warp['method']}"
    ps = _ps_status()
    ts = _tor_status()
    rs = _relay_status()
    ps_s = onoff(ps["active"])
    ts_s = onoff(ts["active"])
    rs_s = onoff(rs.get("configured", False))
    lines.append(f"[bold]Туннели:[/]     WARP: {ws}    Psiphon: {ps_s}    Tor: {ts_s}    Relay: {rs_s}")

    bbr = bbr_status()
    f2b = fail2ban_status()
    wj = webjail_status()
    ipv6 = ipv6_status()
    cpu = cpu_guard_status()
    bbr_s = onoff(bbr["enabled"]) + f"({bbr['algo']})"
    f2b_s = onoff(f2b["active"])
    if f2b["active"] and f2b["jailed"]:
        f2b_s += f"({f2b['jailed']})"
    wj_s = onoff(wj["enabled"])
    if wj["enabled"] and wj["banned"]:
        wj_s += f"({wj['banned']})"
    ipv6_s = "[red]OFF[/]" if ipv6["disabled"] else "[bright_green]ON[/]"
    cpu_s = onoff(cpu)
    lines.append(f"[bold]Безопасность:[/] BBR: {bbr_s}  F2B: {f2b_s}  WebJail: {wj_s}  IPv6: {ipv6_s}  CPU: {cpu_s}")

    panel_text = "\n".join(lines)
    console.print(Panel(panel_text, title=f"[bold yellow]VWN Панель  {now}[/]",
                        border_style="blue"))
