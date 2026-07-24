import collections.abc
import datetime
import os
import subprocess
import sys
import time

from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

from vwn.core import config, shell
from vwn.core.color import console


def _b(success: bool, text: str = "") -> str:
    """Статус-бейдж."""
    mark = "[bright_green]✓[/]" if success else "[red]✗[/]"
    return f"{mark} {text}"


def _service_status(svc: str) -> str:
    active = shell.service_active(svc)
    return _b(active, svc.replace(".service", ""))


def _cert_days() -> str:
    cert = os.path.join(config.CERT_DIR, "cert.pem")
    if not os.path.exists(cert):
        return "[red]MISSING[/]"
    try:
        r = subprocess.run(["openssl", "x509", "-in", cert, "-noout",
                            "-enddate"], capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return "[red]ERR[/]"
        end_date = r.stdout.strip().replace("notAfter=", "")
        expire = datetime.datetime.strptime(end_date, "%b %d %H:%M:%S %Y %Z")
        days = (expire - datetime.datetime.now()).days
        if days <= 0:
            return f"[red]EXPIRED ({-days}d ago)[/]"
        if days < 15:
            return f"[red]{days}d[/]"
        return f"[bright_green]OK ({days}d)[/]"
    except Exception:
        return "[yellow]?[/]"


def _sub_status() -> str:
    sub_dir = "/usr/local/etc/xray/sub"
    if not os.path.isdir(sub_dir):
        return "[red]НЕТ ПОДП[/]"
    txts = [f for f in os.listdir(sub_dir) if f.endswith(".txt")]
    return f"[bright_green]{len(txts)} подп[/]" if txts else "[yellow]0 подп[/]"


def _onoff(active: bool) -> str:
    return "[bright_green]ON[/]" if active else "[red]OFF[/]"

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

    # Протоколы — одной строкой
    svcs = [_service_status(s) for s in
            ("xray-reality.service", "xray-ws.service",
             "xray-xhttp.service", "nginx.service")]
    lines.append(f"[bold]Протоколы:[/]    {'  '.join(svcs)}")

    # CDN
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
    ssl = _cert_days()
    subs = _sub_status()
    lines.append(f"[bold]CDN:[/] {cdn_info}    [bold]SSL:[/] {ssl}    [bold]Подписки:[/] {subs}")
    lines.append(f"[bold]Домен:[/] [cyan]{domain}[/] ([blue]{server_ip}[/])")

    # Туннели
    warp = _warp_status()
    ws = _onoff(warp["active"])
    if warp["active"] and warp["method"]:
        ws += f" | {warp['method']}"
    ps = _ps_status()
    ts = _tor_status()
    rs = _relay_status()
    ps_s = _onoff(ps["active"])
    ts_s = _onoff(ts["active"])
    rs_s = _onoff(rs.get("configured", False))
    lines.append(f"[bold]Туннели:[/]     WARP: {ws}    Psiphon: {ps_s}    Tor: {ts_s}    Relay: {rs_s}")

    # Безопасность
    bbr = bbr_status()
    f2b = fail2ban_status()
    wj = webjail_status()
    ipv6 = ipv6_status()
    cpu = cpu_guard_status()
    bbr_s = _onoff(bbr["enabled"]) + f"({bbr['algo']})"
    f2b_s = _onoff(f2b["active"])
    if f2b["active"] and f2b["jailed"]:
        f2b_s += f"({f2b['jailed']})"
    wj_s = _onoff(wj["enabled"])
    if wj["enabled"] and wj["banned"]:
        wj_s += f"({wj['banned']})"
    ipv6_s = "[red]OFF[/]" if ipv6["disabled"] else "[bright_green]ON[/]"
    cpu_s = _onoff(cpu)
    lines.append(f"[bold]Безопасность:[/] BBR: {bbr_s}  F2B: {f2b_s}  WebJail: {wj_s}  IPv6: {ipv6_s}  CPU: {cpu_s}")

    panel_text = "\n".join(lines)
    console.print(Panel(panel_text, title=f"[bold yellow]VWN Панель  {now}[/]",
                        border_style="blue"))


def ask_list(title: str, choices: list[str]) -> str:
    """Simplified questionary-style prompt for terminal."""
    console.print(f"\n[bold]{title}[/]")
    for i, c in enumerate(choices):
        console.print(f"  {i}. {c}")
    while True:
        try:
            val = input("> ").strip()
            idx = int(val)
            if 0 <= idx < len(choices):
                return choices[idx]
        except (ValueError, IndexError):
            pass
        console.print("[red]Invalid choice[/]")


def wait_key() -> None:
    input("\nНажмите Enter для продолжения...")


def manage_users() -> None:
    from vwn.modules import users as usr
    from vwn.modules.sub import rebuild_all_sub_files, build_user_sub_file
    usr.init_users_file()
    while True:
        users_list = usr.list_users()
        console.print(f"\n[bold]Пользователи[/]  ({len(users_list)})")
        if users_list:
            for i, u in enumerate(users_list, 1):
                uuid_short = u["uuid"][:8]
                tok_short = u["token"][:8] if u["token"] else "?"
                console.print(f"  {i:2d}. {usr.get_cached_flag()} {u['label']:20s}  {uuid_short}...  tok={tok_short}")
        console.print("")
        console.print("  1. Добавить пользователя")
        console.print("  2. Удалить пользователя")
        console.print("  3. Переименовать")
        console.print("  4. Сменить UUID (rekey)")
        console.print("  5. Сменить токен подписки")
        console.print("  6. QR + URL подписки")
        console.print("  7. Пересобрать все подписки")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            label = input("  Имя пользователя (пусто=авто): ").strip() or None
            r = _run_task("Добавление", lambda: usr.add_user(label))
            if r:
                console.print(f"  [bright_green]{r['label']} — {r['uuid']}[/]")
        elif val == "2":
            if len(users_list) <= 1:
                console.print("  [red]Нельзя удалить последнего пользователя[/]")
                wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]")
                wait_key(); continue
            u = users_list[n - 1]
            if input(f"  Удалить '{u['label']}'? (y/N): ").strip().lower() != "y":
                continue
            _run_task("Удаление", lambda: usr.remove_user(n))
        elif val == "3":
            if not users_list:
                console.print("  [yellow]Нет пользователей[/]"); wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]"); wait_key(); continue
            new_label = input(f"  Новое имя [{users_list[n-1]['label']}]: ").strip()
            if new_label:
                _run_task("Переименование", lambda: usr.rename_user(n, new_label))
        elif val == "4":
            if not users_list:
                console.print("  [yellow]Нет пользователей[/]"); wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]"); wait_key(); continue
            if input(f"  Сменить UUID для '{users_list[n-1]['label']}'? (y/N): ").strip().lower() == "y":
                new_uuid = usr.rekey_user(n)
                if new_uuid:
                    console.print(f"  [bright_green]Новый UUID: {new_uuid}[/]")
        elif val == "5":
            if not users_list:
                console.print("  [yellow]Нет пользователей[/]"); wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]"); wait_key(); continue
            new_token = usr.reissue_token(n)
            if new_token:
                console.print(f"  [bright_green]Новый токен: {new_token}[/]")
        elif val == "6":
            if not users_list:
                console.print("  [yellow]Нет пользователей[/]"); wait_key(); continue
            try:
                n = int(input("  Номер: ").strip())
            except ValueError:
                wait_key(); continue
            if n < 1 or n > len(users_list):
                console.print("  [red]Неверный номер[/]"); wait_key(); continue
            u = users_list[n - 1]
            dom = config.vwn_conf_get("DOMAIN") or "?"
            server_ip = config.vwn_conf_get("SERVER_IP") or "?"
            build_user_sub_file(u["uuid"], u["label"], u["token"], dom, server_ip)
            sub_url = usr.get_sub_url(u["label"], u["token"]) or f"https://{dom}/sub/{usr.sub_filename(u['label'], u['token'])}"
            safe = usr.safe_label(u["label"])
            html_url = f"https://{dom}/sub/{safe}_{u['token']}.html"
            console.print(f"\n  {usr.get_cached_flag()} [bold]{u['label']}[/]")
            console.print(f"  UUID: {u['uuid']}")
            console.print(f"  Sub URL: [bright_green]{sub_url}[/]")
            console.print(f"  HTML:    [bright_green]{html_url}[/]")
            r = shell.run(["qrencode", "-t", "ANSIUTF8"], input=sub_url,
                          capture=True, check=False)
            if r.stdout:
                console.print(r.stdout)
        elif val == "7":
            _run_task("Пересборка подписок", rebuild_all_sub_files)
        wait_key()


def manage_reality() -> None:
    from vwn.modules.xray import (read_reality_info, update_reality_port,
                                    update_reality_dest, set_reality_mode,
                                    remove_reality, update_uuid_all)
    while True:
        info = read_reality_info()
        if info:
            m = info["mode"].upper()
            xh = f", path={info.get('xhttp_path','')}, mode={info.get('xhttp_mode','')}" if info["mode"] == "xhttp" else ""
            console.print(f"\n[bold]Reality[/]")
            console.print(f"  Порт: {info['port']}, Dest: {info['dest']}")
            console.print(f"  Режим: {m}{xh}")
            console.print(f"  UUID: {info['uuid'][:8]}... PubKey: {info['pub_key'][:16]}...")
        else:
            console.print("\n[bold]Reality[/]  [red]НЕ УСТАНОВЛЕН[/]")
        console.print("  1. Показать информацию")
        console.print("  2. Показать QR")
        console.print("  3. Сменить порт")
        console.print("  4. Сменить dest (fallback)")
        console.print("  5. Сменить транспорт (TCP/XHTTP)")
        console.print("  6. Сменить UUID")
        console.print("  7. Перезапустить")
        console.print("  8. Показать логи")
        console.print("  9. Удалить")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            if info:
                console.print(f"UUID:       {info['uuid']}")
                console.print(f"Порт:       {info['port']}")
                console.print(f"Назначение: {info['dest']}")
                console.print(f"Сервер:     {info['server_name']}")
                console.print(f"Пуб.ключ:   {info['pub_key']}")
                console.print(f"Коротк.ID:  {info['short_id']}")
                console.print(f"Режим:      {info['mode'].upper()}")
                if info["mode"] == "xhttp":
                    console.print(f"XHTTP путь: {info.get('xhttp_path','')}")
                    console.print(f"XHTTP режим: {info.get('xhttp_mode','')}")
            else:
                console.print("[yellow]Reality не установлен[/]")
        elif val == "2":
            _run_cmd("vwn qr --type reality")
        elif val == "3":
            if not info:
                console.print("[red]Не установлен[/]"); wait_key(); continue
            try:
                p = int(input(f"  Порт [{info['port']}]: ").strip())
                if 1024 <= p <= 65535:
                    _run_task("Смена порта", lambda: update_reality_port(p))
                else:
                    console.print("[red]Порт должен быть 1024-65535[/]")
            except (ValueError, EOFError):
                pass
        elif val == "4":
            if not info:
                console.print("[red]Не установлен[/]"); wait_key(); continue
            dest = input(f"  Dest [{info['dest']}]: ").strip()
            if dest and ":" in dest:
                _run_task("Смена dest", lambda: update_reality_dest(dest))
            else:
                console.print("[red]Формат: host:port[/]")
        elif val == "5":
            if not info:
                console.print("[red]Не установлен[/]"); wait_key(); continue
            mode = ask_list("Режим транспорта", ["TCP (vision)", "XHTTP"])
            if mode == "TCP (vision)":
                set_reality_mode("tcp")
                console.print("[bright_green]→ TCP (xtls-rprx-vision)[/]")
            elif mode == "XHTTP":
                xm = ask_list("XHTTP mode", ["auto", "stream-one", "stream-up",
                                             "packet-one", "packet-up", "none"])
                set_reality_mode("xhttp", xhttp_mode=xm)
                console.print(f"[bright_green]→ XHTTP (mode={xm})[/]")
        elif val == "6":
            from vwn.modules import users as _usr
            _usr.init_users_file()
            _ul = _usr.list_users()
            if not _ul:
                console.print("  [yellow]Нет пользователей[/]")
            elif len(_ul) == 1:
                _nu = _usr.rekey_user(1)
                if _nu:
                    console.print(f"  [bright_green]Новый UUID: {_nu}[/]")
            else:
                try:
                    _n = int(input(f"  Номер пользователя (1-{len(_ul)}): ").strip())
                except ValueError:
                    break
                if 1 <= _n <= len(_ul):
                    _nu = _usr.rekey_user(_n)
                    if _nu:
                        console.print(f"  [bright_green]Новый UUID для {_ul[_n-1]['label']}: {_nu}[/]")
        elif val == "7":
            _run_cmd("systemctl restart xray-reality")
        elif val == "8":
            _run_cmd("journalctl -u xray-reality -n 50 --no-pager")
        elif val == "9":
            if input("Удалить Reality? (y/N): ").strip().lower() == "y":
                _run_task("Удаление Reality", remove_reality)
        wait_key()


def manage_ws_xhttp() -> None:
    from vwn.modules.xray import (read_ws_xhttp_info, update_ws_path,
                                   update_xhttp_path, update_domain,
                                   update_stub_url, update_uuid_all,
                                   set_xhttp_mode, renew_ssl,
                                   remove_ws, remove_xhttp, check_cert)
    while True:
        ws = shell.service_active("xray-ws.service")
        xh = shell.service_active("xray-xhttp.service")
        info = read_ws_xhttp_info()
        console.print(f"\n[bold]WS / XHTTP[/]")
        console.print(f"  WS:     {'[bright_green]РАБОТАЕТ[/]' if ws else '[red]ОСТАНОВЛЕН[/]'}")
        console.print(f"  XHTTP:  {'[bright_green]РАБОТАЕТ[/]' if xh else '[red]ОСТАНОВЛЕН[/]'}")
        console.print(f"  Домен:    {info['domain']}")
        console.print(f"  URL загл.: {info['stub_url']}")
        console.print(f"  WS path:  {info['ws_path']}")
        console.print(f"  XHTTP:    {info['xhttp_path']} (mode: {info['xhttp_mode']})")
        console.print(f"  UUID:     {info['uuid'][:12]}...")
        console.print("  1. Показать информацию (полная)")
        console.print("  2. Показать QR (WS)")
        console.print("  3. Показать QR (XHTTP)")
        console.print("  4. Сменить путь WS")
        console.print("  5. Сменить путь XHTTP")
        console.print("  6. Сменить режим XHTTP (mode)")
        console.print("  7. Сменить домен")
        console.print("  8. Сменить URL заглушки (stub)")
        console.print("  9. Сменить UUID (все протоколы)")
        console.print(" 10. Обновить SSL сертификат")
        console.print(" 11. Перезапустить сервисы")
        console.print(" 12. Логи WS")
        console.print(" 13. Логи XHTTP")
        console.print(" 14. Удалить WS")
        console.print(" 15. Удалить XHTTP")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            _run_cmd("vwn status")
        elif val == "2":
            _run_cmd("vwn qr --type ws")
        elif val == "3":
            _run_cmd("vwn qr --type xhttp")
        elif val == "4":
            cur = info["ws_path"]
            p = input(f"  Новый WS path [{cur}]: ").strip()
            if p:
                _run_task("Смена WS path", lambda: update_ws_path(p))
        elif val == "5":
            cur = info["xhttp_path"]
            p = input(f"  Новый XHTTP path [{cur}]: ").strip()
            if p:
                _run_task("Смена XHTTP path", lambda: update_xhttp_path(p))
        elif val == "6":
            mode = ask_list("XHTTP mode", ["auto", "stream-one", "stream-up",
                                           "packet-one", "packet-up", "none"])
            _run_task("Смена XHTTP mode", lambda: set_xhttp_mode(mode))
        elif val == "7":
            cur = info["domain"]
            d = input(f"  Новый домен [{cur}]: ").strip()
            if d:
                _run_task("Смена домена", lambda: update_domain(d))
                if input("  Перевыпустить SSL для нового домена? (y/N): ").strip().lower() == "y":
                    cert_info = check_cert(d)
                    console.print("  Метод SSL:")
                    console.print("    1. Самоподписанный (self-signed)")
                    console.print("    2. ACME standalone (порт 80)")
                    console.print("    3. ACME Cloudflare DNS")
                    m = input("> ").strip()
                    if m == "1":
                        _run_task("SSL самоподписанный", lambda: renew_ssl(d, "self"))
                    elif m == "2":
                        _run_task("SSL ACME standalone", lambda: renew_ssl(d, "standalone"))
                    elif m == "3":
                        ce = input("  CF Email: ").strip()
                        ck = input("  CF Key: ").strip()
                        if ce and ck:
                            _run_task("SSL ACME CF", lambda: renew_ssl(d, "cf", ce, ck))
        elif val == "8":
            cur = info["stub_url"]
            u = input(f"  Новый stub URL [{cur}]: ").strip()
            if u:
                _run_task("Смена stub URL", lambda: update_stub_url(u))
        elif val == "9":
            from vwn.modules import users as _usr
            _usr.init_users_file()
            _ul = _usr.list_users()
            if not _ul:
                console.print("  [yellow]Нет пользователей[/]")
            elif len(_ul) == 1:
                if input("  Сменить UUID? (y/N): ").strip().lower() == "y":
                    _nu = _usr.rekey_user(1)
                    if _nu:
                        console.print(f"  [bright_green]Новый UUID: {_nu}[/]")
            else:
                try:
                    _n = int(input(f"  Номер пользователя (1-{len(_ul)}): ").strip())
                except ValueError:
                    break
                if 1 <= _n <= len(_ul):
                    if input(f"  Сменить UUID для {_ul[_n-1]['label']}? (y/N): ").strip().lower() == "y":
                        _nu = _usr.rekey_user(_n)
                        if _nu:
                            console.print(f"  [bright_green]Новый UUID для {_ul[_n-1]['label']}: {_nu}[/]")
        elif val == "10":
            domain = info["domain"] or config.vwn_conf_get("DOMAIN") or ""
            if not domain:
                console.print("[red]Домен не задан[/]"); wait_key(); continue
            cert_info = check_cert(domain)
            if cert_info["valid"]:
                cd = cert_info["domain"]
                dl = cert_info["days_left"]
                exp = cert_info["expires"]
                console.print(f"  Текущий сертификат: {cd}, истекает: {exp}")
                if dl > 15 and cd == domain:
                    console.print(f"  [bright_green]Дней осталось: {dl}, всё ок[/]")
                    if input("  Перевыпустить? (y/N): ").strip().lower() != "y":
                        wait_key(); continue
                else:
                    console.print(f"  [yellow]Дней: {dl}, требуется перевыпуск[/]")
            else:
                reason = cert_info.get("reason", "")
                console.print(f"  [yellow]Сертификат: {reason}[/]")
            console.print("  Метод SSL:")
            console.print("    1. Самоподписанный (self-signed)")
            console.print("    2. ACME standalone (порт 80)")
            console.print("    3. ACME Cloudflare DNS")
            m = input("> ").strip()
            if m == "1":
                _run_task("SSL самоподписанный", lambda: renew_ssl(domain, "self"))
            elif m == "2":
                _run_task("SSL ACME standalone", lambda: renew_ssl(domain, "standalone"))
            elif m == "3":
                ce = input("  CF Email: ").strip()
                ck = input("  CF Key: ").strip()
                if ce and ck:
                    _run_task("SSL ACME CF", lambda: renew_ssl(domain, "cf", ce, ck))
        elif val == "11":
            _run_cmd("systemctl restart xray-ws xray-xhttp")
        elif val == "12":
            _run_cmd("journalctl -u xray-ws -n 50 --no-pager")
        elif val == "13":
            _run_cmd("journalctl -u xray-xhttp -n 50 --no-pager")
        elif val == "14":
            if input("Удалить WS? (y/N): ").strip().lower() == "y":
                _run_task("Удаление WS", remove_ws)
        elif val == "15":
            if input("Удалить XHTTP? (y/N): ").strip().lower() == "y":
                _run_task("Удаление XHTTP", remove_xhttp)
        wait_key()


def manage_tunnel(name: str, svc: str, tag: str, has_install: bool = False,
                  has_configure: bool = False,
                  extra: dict[str, collections.abc.Callable[[], None]] | None = None) -> None:
    """extra: {label: handler_callable} — добавляется после Выключить"""
    from vwn.modules.tunnels import get_tunnel_mode_from_file, render_tunnel_status
    while True:
        config_path = os.path.join(config.XRAY_DIR, "config.json")
        mode = get_tunnel_mode_from_file(config_path, tag)
        active = shell.service_active(svc) if svc else False
        if tag == "warp":
            from vwn.modules.warp import status as warp_st
            ws = warp_st()
            active = bool(ws["method"])
        elif tag == "psiphon":
            from vwn.modules.psiphon import status as ps_st
            ps = ps_st()
            active = ps["active"]
        elif tag == "tor":
            from vwn.modules.tor import status as tor_st
            ts = tor_st()
            active = ts["active"]
        console.print(f"\n[bold]{name}[/]")
        console.print(f"  Статус: {render_tunnel_status(name, mode, active)}")
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
                _run_task("Установка WARP", lambda: warp_install(method))
            elif tag == "psiphon":
                from vwn.modules.psiphon import COUNTRIES as PS_COUNTRIES
                for i, (code, name) in enumerate(PS_COUNTRIES, 1):
                    console.print(f"    {i:>2}. {code} — {name}")
                console.print("  Номер страны (пусто=авто):")
                cn = input("> ").strip()
                country = ""
                if cn.isdigit() and 1 <= int(cn) <= len(PS_COUNTRIES):
                    country = PS_COUNTRIES[int(cn) - 1][0]
                elif cn:
                    country = cn.upper()[:2]
                console.print("  Режим туннеля:")
                console.print("    1. Plain  — прямое подключение к Psiphon")
                console.print("    2. Warp   — Psiphon поверх WARP")
                tm = input("> ").strip()
                tmode = "warp" if tm == "2" else "plain"
                from vwn.modules.psiphon import install as ps_install
                _run_task("Установка Psiphon",
                          lambda: ps_install(country, tmode))
            elif tag == "tor":
                from vwn.modules.tor import COUNTRIES as TOR_COUNTRIES
                for i, (code, name) in enumerate(TOR_COUNTRIES, 1):
                    console.print(f"    {i:>2}. {code} — {name}")
                console.print("  Номер страны (пусто=авто):")
                cn = input("> ").strip()
                country = ""
                if cn.isdigit() and 1 <= int(cn) <= len(TOR_COUNTRIES):
                    country = TOR_COUNTRIES[int(cn) - 1][0]
                elif cn:
                    country = cn.upper()[:2]
                from vwn.modules.tor import install as tor_install
                _run_task("Установка Tor",
                          lambda: tor_install(country))
            wait_key()
        elif has_install and val == "2":
            if tag == "warp":
                from vwn.modules.warp import remove as warp_remove
                _run_task("Удаление WARP", warp_remove)
            elif tag == "psiphon":
                from vwn.modules.psiphon import remove as ps_remove
                _run_task("Удаление Psiphon", ps_remove)
            elif tag == "tor":
                from vwn.modules.tor import remove as tor_remove
                _run_task("Удаление Tor", tor_remove)
            wait_key()
        elif has_configure and val == "1":
            console.print("  URL релея (vless:// vmess:// trojan:// socks5://):")
            url = input("> ").strip()
            if url:
                from vwn.modules.relay import configure as relay_cfg
                _run_task("Настройка релея", lambda: relay_cfg(url))
            wait_key()
        else:
            offset = 1
            if has_install:
                offset += 2
            if has_configure:
                offset += 1
            if val == str(offset):
                _switch_tunnel_mode(tag, "Global")
                _run_cmd("systemctl restart xray-ws xray-xhttp")
                wait_key()
            elif val == str(offset + 1):
                _switch_tunnel_mode(tag, "Split")
                _run_cmd("systemctl restart xray-ws xray-xhttp")
                wait_key()
            elif val == str(offset + 2):
                _switch_tunnel_mode(tag, "OFF")
                _run_cmd("systemctl restart xray-ws xray-xhttp")
                wait_key()
            elif extra and val.isdigit() and extra_start <= int(val) < extra_start + len(extra):
                label = list(extra.keys())[int(val) - extra_start]
                extra[label]()
                wait_key()
            elif svc and val == str(offset + 3):
                _run_cmd(f"systemctl restart {svc}")
                wait_key()
            elif svc and val == str(offset + 4):
                _run_cmd(f"journalctl -u {svc} -n 50 --no-pager")
                wait_key()


_TUNNEL_TAGS = {"warp", "psiphon", "tor", "relay"}


def _is_any_tunnel_tag(tag: str) -> bool:
    if tag in _TUNNEL_TAGS:
        return True
    return tag.startswith("warp-")


def _switch_tunnel_mode(tag: str, mode: str) -> str:
    """Переключить режим туннеля. Возвращает реальный outboundTag."""
    if not os.path.isfile(os.path.join(config.XRAY_DIR, "config.json")):
        return tag
    import json
    from vwn.modules._outbound import _paths
    from vwn.modules.tunnels import _match_tunnel_tag
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = json.load(f)
        rules = cfg.setdefault("routing", {}).setdefault("rules", [])
        # Resolve actual outbound tag for warp
        actual_tag = tag
        if tag == "warp":
            for o in cfg.get("outbounds", []):
                if _match_tunnel_tag(o.get("tag", ""), "warp"):
                    actual_tag = o["tag"]
                    break
        rules = [r for r in rules if not _match_tunnel_tag(r.get("outboundTag", ""), tag)]
        if mode == "Global":
            rules = [r for r in rules
                     if not (_is_any_tunnel_tag(r.get("outboundTag", ""))
                             and r.get("port") == "0-65535")]
            rules.insert(0, {"type": "field", "port": "0-65535", "outboundTag": actual_tag})
        elif mode == "Split":
            from vwn.modules._domains import list_domains
            domains = list_domains(actual_tag)
            if not domains:
                domains = ["whoer.net"]
            domains_json = [f"domain:{d}" for d in domains]
            rules.insert(0, {"type": "field", "domain": domains_json, "outboundTag": actual_tag})
        cfg["routing"]["rules"] = rules
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    if tag == "warp" and mode != "OFF":
        from vwn.core import config as _cfg
        _cfg.vwn_conf_set("WARP_TUNNEL_MODE", mode)
    elif tag == "warp" and mode == "OFF":
        from vwn.core import config as _cfg
        _cfg.vwn_conf_del("WARP_TUNNEL_MODE")
    return actual_tag


def _run_task(title: str, fn):
    try:
        return fn()
    except Exception as e:
        console.print(f"[red]{title}: ошибка — {e}[/]")
    return None


def _run_cmd(cmd: str) -> None:
    console.print(f"\n[dim]> {cmd}[/]")
    r = shell.run(cmd, capture=True, check=False)
    if r.stdout:
        console.print(r.stdout[:2000])
    if r.stderr:
        console.print(f"[red]{r.stderr[:500]}[/]")


def show_logs() -> None:
    services = [
        ("Xray ошибка", "journalctl -u xray-reality -n 50 --no-pager"),
        ("Xray доступ", "cat /var/log/xray/error.log 2>/dev/null | tail -50"),
        ("Nginx ошибка", "journalctl -u nginx -n 50 --no-pager"),
        ("Nginx доступ", "tail -50 /var/log/nginx/access.log 2>/dev/null"),
    ]
    for i, (name, cmd) in enumerate(services):
        console.print(f"  {i}. {name}")
    try:
        idx = int(input("Выберите лог (0-3): ").strip())
        if 0 <= idx < len(services):
            _run_cmd(services[idx][1])
    except ValueError:
        pass
    wait_key()


def manage_privacy() -> None:
    from vwn.modules.privacy import status, enable, disable, shred
    while True:
        s = status()
        console.print(f"\n[bold]Приватность[/]")
        console.print(f"  Режим: {'[bright_green]ВКЛ[/]' if s['enabled'] else '[red]ВЫКЛ[/]'} (компонентов: {s['score']}/4)")
        console.print("  1. Включить (откл. логи, tmpfs, shred)")
        console.print("  2. Выключить (восстановить логи)")
        console.print("  3. Уничтожить логи сейчас")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            _run_task("Включение приватности", enable)
        elif val == "2":
            _run_task("Выключение приватности", disable)
        elif val == "3":
            _run_task("Уничтожение логов", shred)
        wait_key()


def manage_logs() -> None:
    from vwn.modules.logs import (clear, setup_logrotate, logrotate_status,
                                   setup_ssl_cron, remove_ssl_cron, ssl_cron_status,
                                   setup_clear_cron, remove_clear_cron, clear_cron_status)
    while True:
        lr = "активна" if logrotate_status() else "неактивна"
        sc = "активна" if ssl_cron_status() else "неактивна"
        cc = "активна" if clear_cron_status() else "неактивна"
        console.print(f"\n[bold]Логи[/]")
        console.print(f"  Логротация: {lr}")
        console.print(f"  Автообновление SSL: {sc}")
        console.print(f"  Автоочистка: {cc}")
        console.print("  1. Очистить все логи сейчас")
        console.print("  2. Настроить logrotate")
        console.print("  3. Настроить автообновление SSL (acme.sh)")
        console.print("  4. Удалить автообновление SSL")
        console.print("  5. Настроить автоочистку (еженедельно)")
        console.print("  6. Удалить автоочистку")
        console.print("  7. Просмотр логов")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            r = _run_task("Очистка логов", clear)
            if r:
                console.print(f"  Освобождено: {r['freed_kb']} КБ")
        elif val == "2":
            _run_task("Настройка logrotate", setup_logrotate)
        elif val == "3":
            _run_task("Настройка автообновления SSL", setup_ssl_cron)
        elif val == "4":
            _run_task("Удаление автообновления SSL", remove_ssl_cron)
        elif val == "5":
            _run_task("Настройка автоочистки", setup_clear_cron)
        elif val == "6":
            _run_task("Удаление автоочистки", remove_clear_cron)
        elif val == "7":
            show_logs()
        wait_key()


def _cdn_menu_scanner_settings() -> None:
    from vwn.modules.cdn import scan
    keys = [("CDN_AUTOSCAN_COUNT", "Выборка (кол-во IP)"),
            ("CDN_SCAN_PARALLEL", "Воркеры"),
            ("CDN_SCAN_TIMEOUT", "Таймаут (сек)")]
    vals = [config.vwn_conf_get(k) or d for (k, _), d in zip(keys, ["200", "40", "3"])]
    while True:
        console.print("\n[bold]Настройки сканера[/]")
        for i, ((k, label), v) in enumerate(zip(keys, vals), 1):
            console.print(f"  {i}. {label}: {v}")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        if val.isdigit() and 1 <= int(val) <= len(keys):
            i = int(val) - 1
            new_v = input(f"  {keys[i][1]} [{vals[i]}]: ").strip()
            if new_v:
                config.vwn_conf_set(keys[i][0], new_v)
                vals[i] = new_v
                console.print(f"  [bright_green]Сохранено[/]")


def _cdn_menu_edit_ips() -> None:
    from vwn.modules.cdn import IPS_FILE
    import subprocess, shutil, tempfile, os
    if not os.path.isfile(IPS_FILE):
        console.print("  [yellow]Файл не найден[/]"); return
    editor = os.environ.get("EDITOR") or "nano"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write(open(IPS_FILE).read())
        tmp_path = tmp.name
    console.print(f"  Открываю {editor}...")
    subprocess.run([editor, tmp_path])
    shutil.move(tmp_path, IPS_FILE)


def manage_cdn() -> None:
    from vwn.modules.cdn import (status, set_mode, scan, scan_status, scan_stop,
                                  find_best, apply_ip, check_ip, ping,
                                  blacklist_add, blacklist_list, blacklist_clear,
                                  domains_list, domains_add, domains_remove,
                                  init_sources, install_watcher, remove_watcher)
    init_sources()
    while True:
        s = status()
        mode_str = s["mode"]
        ip_str = s["ip"] or "нет"
        ping_str = f" ({s['ping_ms']}ms)" if s["ping_ms"] else ""
        w_str = "[bright_green]вкл[/]" if s["watcher"] else "[red]выкл[/]"
        cnt = int(config.vwn_conf_get("CDN_AUTOSCAN_COUNT") or "200")
        wk = int(config.vwn_conf_get("CDN_SCAN_PARALLEL") or "40")
        to = int(config.vwn_conf_get("CDN_SCAN_TIMEOUT") or "3")
        console.print(f"\n[bold]CDN[/]")
        console.print(f"  Режим: {mode_str}  |  Активный IP: {ip_str}{ping_str}")
        console.print(f"  Вотчер: {w_str}  |  Кэш: {s['found_count']} IP  |  Скан: {cnt}×{wk}w/{to}s")
        console.print("  1. Выключить (основной домен)")
        console.print("  2. Ручной (фикс. IP/домен)")
        console.print("  3. Авто — резолв доменов")
        console.print("  4. Авто — сканер (кэш)")
        console.print("  5. Сканировать новые IP")
        console.print("  6. Выбрать лучший из кэша")
        console.print("  7. Добавить домен в список")
        console.print("  8. Удалить домен из списка")
        console.print("  9. Заблокировать текущий IP")
        console.print(" 10. Показать/очистить чёрный список")
        console.print(" 11. Установить/удалить вотчер")
        console.print(" 12. Проверить IP")
        console.print(" 13. Настройки сканера")
        console.print(" 14. Редактировать список IP (cdn_ips.txt)")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            _run_task("CDN выкл", lambda: set_mode("off"))
        elif val == "2":
            ip = input("  IP или домен: ").strip()
            if ip:
                _run_task("Применить ручной", lambda: (set_mode("manual"), apply_ip(ip)))
        elif val == "3":
            _run_task("Авто-резолв", lambda: set_mode("auto_resolve"))
        elif val == "4":
            _run_task("Авто-сканер", lambda: set_mode("auto_scan"))
        elif val == "5":
            _run_task("Сканирование", lambda: scan(foreground=True))
        elif val == "6":
            ip = find_best(config.vwn_conf_get("CDN_MODE", ""))
            if ip:
                _run_task("Применить лучший", lambda: apply_ip(ip))
            else:
                console.print("  [yellow]Нет кандидатов[/]")
        elif val == "7":
            d = input("  Домен: ").strip()
            if d:
                _run_task("Добавление домена", lambda: domains_add(d))
        elif val == "8":
            doms = domains_list()
            if not doms:
                console.print("  [yellow]Нет доменов[/]"); wait_key(); continue
            for i, d in enumerate(doms, 1):
                console.print(f"  {i}. {d}")
            n = input("  Номер: ").strip()
            if n.isdigit() and 1 <= int(n) <= len(doms):
                _run_task("Удаление домена", lambda: domains_remove(int(n) - 1))
        elif val == "9":
            ip = s["ip"]
            if ip:
                _run_task("Чёрный список", lambda: blacklist_add(ip))
                _run_task("Поиск следующего", lambda: apply_ip(find_best(
                    config.vwn_conf_get("CDN_MODE", ""), ip) or ""))
        elif val == "10":
            bl = blacklist_list()
            if bl:
                for ip in bl:
                    console.print(f"  {ip}")
                if input("  Очистить чёрный список? (y/N): ").strip().lower() == "y":
                    blacklist_clear()
                    console.print("  [bright_green]Очищен[/]")
            else:
                console.print("  [yellow]Пусто[/]")
        elif val == "11":
            if s["watcher"]:
                _run_task("Удаление вотчера", remove_watcher)
            else:
                _run_task("Установка вотчера", install_watcher)
        elif val == "12":
            ip = input("  IP для проверки: ").strip()
            if ip:
                ms = ping(ip)
                console.print(f"  {'[bright_green]ДОСТУПЕН' if ms < 9999 else '[red]ОШИБКА'} ({ms}ms)" if ms < 9999 else "  [red]Недоступен[/]")
        elif val == "13":
            _cdn_menu_scanner_settings()
        elif val == "14":
            _cdn_menu_edit_ips()
        wait_key()


def security_menu() -> None:
    from vwn.modules.security import (bbr_status, bbr_enable, bbr_disable,
                                       fail2ban_install, fail2ban_remove,
                                       fail2ban_status, fail2ban_start,
                                       fail2ban_stop,
                                       ufw_status, ufw_allow, ufw_deny,
                                       change_ssh_port, ssh_disable_password_auth,
                                       ssh_password_auth_status,
                                       webjail_status, webjail_enable,
                                       webjail_disable,
                                       ipv6_status, ipv6_disable, ipv6_enable,
                                       cpu_guard_status, cpu_guard_enable,
                                       cpu_guard_disable)
    while True:
        console.print("\n[bold]Безопасность[/]")
        bbr = bbr_status()
        f2b = fail2ban_status()
        ufw = ufw_status()
        wj = webjail_status()
        ipv6 = ipv6_status()
        console.print(f"  BBR:      {'[bright_green]включён[/]' if bbr['enabled'] else '[yellow]выключен[/]'} ({bbr['algo']})")
        console.print(f"  Fail2Ban: {'[bright_green]активен[/]' if f2b['active'] else '[red]остановлен[/]'} ({f2b['jailed']} забанено)")
        console.print(f"  WebJail:  {'[bright_green]включён[/]' if wj['enabled'] else '[yellow]выключен[/]'} ({wj['banned']} забанено)")
        console.print(f"  UFW:      {'[bright_green]активен[/]' if ufw.get('active') else '[red]неактивен[/]'}")
        cg = cpu_guard_status()
        console.print(f"  IPv6:     {'[red]выкл[/]' if ipv6['disabled'] else '[bright_green]вкл[/]'}")
        sh = ssh_password_auth_status()
        console.print(f"  CPU Guard: {'[bright_green]вкл[/]' if cg else '[red]выкл[/]'}")
        console.print(f"  SSH порт: {_parse_ssh_port()}  Пароль: {'[red]ДА[/]' if sh['password_auth'] else '[green]НЕТ[/]'}  Root вход: {'[red]ДА (пароль)[/]' if sh['root_password_login'] else '[green]prohibit-password[/]'}")
        console.print("")
        console.print("  1. Включить BBR")
        console.print("  2. Выключить BBR (→ cubic)")
        console.print("  3. Установить и запустить Fail2Ban")
        console.print("  4. Остановить Fail2Ban")
        console.print("  5. Удалить Fail2Ban")
        console.print("  6. Статус UFW")
        console.print("  7. Разрешить порт UFW")
        console.print("  8. Заблокировать порт UFW")
        console.print("  9. Включить WebJail (nginx-probe)")
        console.print(" 10. Выключить WebJail")
        console.print(" 11. Выключить IPv6")
        console.print(" 12. Включить IPv6")
        console.print(" 13. Сменить SSH порт")
        console.print(" 14. Вкл/Выкл CPU Guard")
        console.print(" 15. SSH: отключить парольный вход (key-only)")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            _run_task("Включение BBR", bbr_enable)
        elif val == "2":
            _run_task("Выключение BBR", bbr_disable)
        elif val == "3":
            _run_task("Установка Fail2Ban", fail2ban_install)
        elif val == "4":
            _run_task("Остановка Fail2Ban", fail2ban_stop)
        elif val == "5":
            _run_task("Удаление Fail2Ban", fail2ban_remove)
        elif val == "6":
            _run_task("Статус UFW", lambda: _show_ufw(ufw))
        elif val == "7":
            p = _ask_port()
            if p:
                _run_task(f"Разрешить порт UFW {p}", lambda: ufw_allow(p, "tcp"))
        elif val == "8":
            p = _ask_port()
            if p:
                _run_task(f"Заблокировать порт UFW {p}", lambda: ufw_deny(p, "tcp"))
        elif val == "9":
            _run_task("Включение WebJail", webjail_enable)
        elif val == "10":
            _run_task("Выключение WebJail", webjail_disable)
        elif val == "11":
            _run_task("Выключение IPv6", ipv6_disable)
        elif val == "12":
            _run_task("Включение IPv6", ipv6_enable)
        elif val == "13":
            p = _ask_port("Новый SSH порт")
            if p:
                _run_task(f"Смена SSH порта на {p}", lambda: change_ssh_port(p))
        elif val == "14":
            if cpu_guard_status():
                _run_task("Выключение CPU Guard", cpu_guard_disable)
            else:
                _run_task("Включение CPU Guard", cpu_guard_enable)
        elif val == "15":
            _run_task("SSH hardening (key-only)", ssh_disable_password_auth)
        wait_key()


def _parse_ssh_port() -> int:
    import re
    path = "/etc/ssh/sshd_config"
    try:
        with open(path) as f:
            for line in f:
                m = re.match(r"^\s*Port\s+(\d+)\s*$", line)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 22


def _ask_port(prompt: str = "Порт") -> "int | None":
    try:
        return int(input(f"  {prompt}: ").strip())
    except (ValueError, EOFError):
        return None


def _show_ufw(ufw: dict) -> None:
    if not ufw.get("installed"):
        console.print("  UFW не установлен")
        return
    console.print(f"  Активен: {ufw['active']}")
    for r in ufw.get("rules", []):
        console.print(f"    {r}")


def manage_backup() -> None:
    backup_dir = "/root/vwn_backups"
    backup_paths = [
        "/usr/local/etc/xray",
        "/etc/nginx/conf.d",
        "/etc/nginx/cert",
        "/etc/cron.d/acme-renew",
        "/etc/cron.d/clear-logs",
        "/etc/fail2ban/jail.local",
        "/etc/fail2ban/filter.d/nginx-probe.conf",
        "/etc/systemd/system/xray-*.service",
        "/root/.cloudflare_api",
    ]
    while True:
        bps = [p for p in backup_paths if os.path.exists(p)]
        count = 0
        if os.path.isdir(backup_dir):
            count = len([f for f in os.listdir(backup_dir) if f.endswith(".tar.gz")])
        console.print(f"\n[bold]Бэкап / Восстановление[/]")
        console.print(f"  Директория: {backup_dir}")
        console.print(f"  Бэкапов:    {count}  |  Компонентов: {len(bps)}")
        console.print("  1. Создать бэкап")
        console.print("  2. Список бэкапов")
        console.print("  3. Восстановить")
        console.print("  4. Удалить бэкап")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            ts = time.strftime("%Y%m%d_%H%M%S")
            os.makedirs(backup_dir, exist_ok=True)
            if not bps:
                console.print("[yellow]Нечего бэкапить[/]")
                wait_key(); continue
            r = subprocess.run(["tar", "-czf", f"{backup_dir}/vwn_{ts}.tar.gz"] + bps,
                               capture_output=True, text=True)
            if r.returncode == 0:
                size = os.path.getsize(f"{backup_dir}/vwn_{ts}.tar.gz")
                console.print(f"[bright_green]Бэкап: vwn_{ts}.tar.gz ({size//1024} KB)[/]")
            else:
                console.print(f"[red]Ошибка: {r.stderr[:200]}[/]")
            wait_key()
        elif val == "2":
            if not os.path.isdir(backup_dir):
                console.print("[yellow]Нет бэкапов[/]"); wait_key(); continue
            files = sorted([f for f in os.listdir(backup_dir) if f.endswith(".tar.gz")], reverse=True)
            if not files:
                console.print("[yellow]Нет бэкапов[/]"); wait_key(); continue
            for i, f in enumerate(files, 1):
                sz = os.path.getsize(os.path.join(backup_dir, f)) // 1024
                console.print(f"  {i}. {f}  ({sz} KB)")
            wait_key()
        elif val == "3":
            if not os.path.isdir(backup_dir):
                console.print("[yellow]Нет бэкапов[/]"); wait_key(); continue
            files = sorted([f for f in os.listdir(backup_dir) if f.endswith(".tar.gz")], reverse=True)
            if not files:
                console.print("[yellow]Нет бэкапов[/]"); wait_key(); continue
            for i, f in enumerate(files, 1):
                sz = os.path.getsize(os.path.join(backup_dir, f)) // 1024
                console.print(f"  {i}. {f}  ({sz} KB)")
            try:
                n = int(input("  Номер: ").strip())
                if n < 1 or n > len(files):
                    raise ValueError
            except ValueError:
                console.print("[red]Неверный номер[/]"); wait_key(); continue
            fname = files[n - 1]
            if input(f"  Восстановить {fname}? (y/N): ").strip().lower() != "y":
                continue
            for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
                subprocess.run(["systemctl", "stop", svc], capture_output=True)
            r = subprocess.run(["tar", "-xzf", os.path.join(backup_dir, fname), "-C", "/"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
                for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
                    subprocess.run(["systemctl", "restart", svc], capture_output=True)
                console.print("[bright_green]Восстановлено[/]")
            else:
                console.print(f"[red]Ошибка: {r.stderr[:200]}[/]")
            wait_key()
        elif val == "4":
            if not os.path.isdir(backup_dir):
                console.print("[yellow]Нет бэкапов[/]"); wait_key(); continue
            files = sorted([f for f in os.listdir(backup_dir) if f.endswith(".tar.gz")], reverse=True)
            if not files:
                console.print("[yellow]Нет бэкапов[/]"); wait_key(); continue
            for i, f in enumerate(files, 1):
                sz = os.path.getsize(os.path.join(backup_dir, f)) // 1024
                console.print(f"  {i}. {f}  ({sz} KB)")
            try:
                n = int(input("  Номер: ").strip())
                if n < 1 or n > len(files):
                    raise ValueError
            except ValueError:
                console.print("[red]Неверный номер[/]"); wait_key(); continue
            fname = files[n - 1]
            if input(f"  Удалить {fname}? (y/N): ").strip().lower() == "y":
                os.remove(os.path.join(backup_dir, fname))
                console.print("[bright_green]Удалён[/]")
            wait_key()


def full_remove() -> None:
    console.print("[red]ВНИМАНИЕ: Это удалит ВСЕ компоненты VWN![/]")
    confirm = input('Введите "yes" для подтверждения: ').strip()
    if confirm != "yes":
        return
    remove_cert = input("  Оставить SSL сертификат? (Y/n): ").strip().lower() == "n"
    for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
        subprocess.run(["systemctl", "stop", svc], capture_output=True)
        subprocess.run(["systemctl", "disable", svc], capture_output=True)
    paths = ["/usr/local/etc/xray", "/etc/nginx/conf.d/xray.conf",
             "/etc/nginx/conf.d/sub_map.conf", "/etc/systemd/system/xray-*.service"]
    if remove_cert:
        paths.append("/etc/nginx/cert")
    subprocess.run(["rm", "-rf"] + paths, capture_output=True)
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    console.print("[bright_green]VWNpy удалён" + (" (сертификат сохранён)[/]" if not remove_cert else "[/]"))


def _rebuild_configs() -> None:
    """Пересобрать все конфиги (новые ключи Reality)."""
    from vwn.core import config as vc
    domain = vc.vwn_conf_get("DOMAIN")
    stub = vc.vwn_conf_get("STUB_URL")
    reality_dest = vc.vwn_conf_get("REALITY_DEST")
    if not all([domain, stub, reality_dest]):
        console.print("[red]Конфиг неполный — сначала выполните vwn install[/]")
        return
    from vwn.modules.xray import provision_configs
    provision_configs(domain, stub, reality_dest)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    _run_cmd("systemctl daemon-reload")
    for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
        _run_cmd(f"systemctl restart {svc}")
    console.print("[bright_green]Конфиги пересобраны (новые ключи Reality)[/]")


def _update_xray() -> None:
    from vwn.core.system import install_xray
    _run_task("Обновление Xray-core", install_xray)


def _update_vwn() -> None:
    import glob, os, shutil, subprocess, sys, tempfile, zipfile
    from urllib.request import urlretrieve

    REPO = "https://github.com/HnDK0/VWNpy"
    tmpdir = tempfile.mkdtemp()
    try:
        urlretrieve(f"{REPO}/releases/latest/download/vwnpy-wheel.zip",
                    os.path.join(tmpdir, "wheel.zip"))
        wheel_dir = os.path.join(tmpdir, "wheel")
        with zipfile.ZipFile(os.path.join(tmpdir, "wheel.zip")) as zf:
            zf.extractall(wheel_dir)
        whls = glob.glob(os.path.join(wheel_dir, "*.whl"))
        if not whls:
            console.print("[red]wheel не найден в архиве[/]")
            return
        _run_task("pip install --force-reinstall",
                  lambda: subprocess.run(
                      [sys.executable, "-m", "pip", "install",
                       "--force-reinstall", whls[0]],
                      check=True))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def run_menu() -> None:
    while True:
        console.clear()
        dashboard()
        console.print("\n[bold]Главное меню[/]")
        items = [
            "Управление пользователями",
            "Reality",
            "WS / XHTTP",
            "WARP",
            "Psiphon",
            "Tor",
            "Relay",
            "Диагностика (полная)",
            "Безопасность",
            "Приватность",
            "Логи",
            "CDN",
            "Бэкап / Восстановление",
            "Пересобрать все конфиги",
            "Обновить VWNpy",
            "Обновить Xray-core",
            "Перезапустить все сервисы",
            "Полное удаление",
            "Выход",
        ]
        for i, item in enumerate(items):
            console.print(f"  {i+1}. {item}")
        try:
            choice = int(input("> ").strip())
        except (ValueError, EOFError):
            continue
        if choice == 1:
            manage_users()
        elif choice == 2:
            manage_reality()
        elif choice == 3:
            manage_ws_xhttp()
        elif choice == 4:
            def _warp_check_ip():
                from vwn.modules.warp import check_ip as _ci
                r = _ci()
                console.print(f"  Прямой IP: {r['direct'] or 'N/A'}")
                console.print(f"  WARP IP:   {r['warp'] or 'N/A'}")
                console.print(f"  Выход geo: {r['country'] or 'N/A'}")
                if not r["warp"] and r.get("error"):
                    console.print(f"  [red]Ошибка: {r['error']}[/]")

            def _warp_add_domain():
                console.print("  Домен для добавления:")
                d = input("> ").strip()
                if d:
                    from vwn.modules.warp import add_domain as _ad
                    _ad(d)
                    console.print(f"  [bright_green]Добавлен: {d}[/]")

            def _warp_del_domain():
                from vwn.modules.warp import list_domains as _ld, remove_domain as _rd
                doms = _ld()
                if not doms:
                    console.print("  [yellow]Нет доменов[/]"); return
                for i, d in enumerate(doms, 1):
                    console.print(f"  {i}. {d}")
                n = input("> ").strip()
                if n.isdigit() and 1 <= int(n) <= len(doms):
                    _rd(int(n) - 1)
                    console.print("  [bright_green]Удалён[/]")

            def _warp_change_method():
                from vwn.modules.warp import status as _st, remove as _rm, install as _ins
                cur = _st()
                console.print(f"  Текущий метод: {cur['method'] or 'не установлен'}")
                console.print("  Новый метод:")
                console.print("    1. native (wgcf→WireGuard, ~0 MB)")
                console.print("    2. amnezia (AmneziaWG, ~20 MB)")
                console.print("    3. warp-svc (legacy, ~200 MB)")
                m = input("> ").strip()
                method = {"1": "native", "2": "amnezia", "3": "warp-svc"}.get(m)
                if not method:
                    console.print("  [red]Неверный выбор[/]"); return
                if cur["method"]:
                    _run_task("Удаление текущего WARP", _rm)
                _run_task("Установка WARP", lambda: _ins(method))

            def _warp_logs():
                from vwn.core import config as _cfg
                method = _cfg.vwn_conf_get("WARP_METHOD") or ""
                if method == "amnezia":
                    _run_cmd("journalctl -u amnezia-warp -n 50 --no-pager")
                elif method == "warp-svc":
                    _run_cmd("journalctl -u warp-svc -n 50 --no-pager")
                else:
                    _run_cmd("journalctl -u xray-reality -n 50 --no-pager")

            manage_tunnel("WARP", "", "warp", has_install=True,
                          extra={
                              "Сменить метод": _warp_change_method,
                              "Добавить домен": _warp_add_domain,
                              "Удалить домен": _warp_del_domain,
                              "Проверить IP через WARP": _warp_check_ip,
                              "Показать логи": _warp_logs,
                          })
        elif choice == 5:
            def _ps_add_domain():
                console.print("  Домен для добавления:")
                d = input("> ").strip()
                if d:
                    from vwn.modules.psiphon import add_domain as _ad
                    _ad(d)
                    console.print(f"  [bright_green]Добавлен: {d}[/]")
            def _ps_del_domain():
                from vwn.modules.psiphon import list_domains as _ld, remove_domain as _rd
                doms = _ld()
                if not doms:
                    console.print("  [yellow]Нет доменов[/]"); return
                for i, d in enumerate(doms, 1):
                    console.print(f"  {i}. {d}")
                n = input("> ").strip()
                if n.isdigit() and 1 <= int(n) <= len(doms):
                    _rd(int(n) - 1)
                    console.print("  [bright_green]Удалён[/]")
            def _ps_change_country():
                from vwn.modules.psiphon import COUNTRIES as PS_COUNTRIES
                for i, (code, name) in enumerate(PS_COUNTRIES, 1):
                    console.print(f"    {i:>2}. {code} — {name}")
                console.print("  Номер страны (пусто=авто):")
                cn = input("> ").strip()
                c = ""
                if cn.isdigit() and 1 <= int(cn) <= len(PS_COUNTRIES):
                    c = PS_COUNTRIES[int(cn) - 1][0]
                elif cn:
                    c = cn.upper()[:2]
                from vwn.modules.psiphon import _write_config as _wc
                _wc(c, "")
                from vwn.modules.psiphon import MODE_FILE
                mode = open(MODE_FILE).read().strip() if os.path.isfile(MODE_FILE) else "plain"
                upstream = "socks5://127.0.0.1:40000" if mode == "warp" else ""
                _wc(c, upstream)
                from vwn.core import shell as _sh
                _sh.run(["systemctl", "restart", "psiphon"], check=False)
                console.print(f"  [bright_green]Страна: {c or 'авто'}[/]")
            def _ps_check_ip():
                import subprocess
                r = subprocess.run(["curl", "-sS", "--max-time", "15",
                                    "--socks5-hostname", "127.0.0.1:40002",
                                    "https://api.ipify.org"],
                                   capture_output=True, text=True, timeout=20)
                ip = r.stdout.strip() if r.returncode == 0 else "N/A"
                console.print(f"  Psiphon IP: {ip}")
            manage_tunnel("Psiphon", "psiphon.service", "psiphon", has_install=True,
                          extra={
                              "Сменить страну": _ps_change_country,
                              "Добавить домен": _ps_add_domain,
                              "Удалить домен": _ps_del_domain,
                              "Проверить IP через Psiphon": _ps_check_ip,
                          })
        elif choice == 6:
            def _tor_add_domain():
                from vwn.modules.tor import add_domain as _ad, list_domains as _ld
                console.print("  Домен для добавления:")
                d = input("> ").strip()
                if d:
                    _ad(d)
                    console.print(f"  [bright_green]Добавлен: {d}[/]")
            def _tor_del_domain():
                from vwn.modules.tor import remove_domain as _rd, list_domains as _ld
                doms = _ld()
                if not doms:
                    console.print("  [yellow]Нет доменов[/]")
                    return
                for i, d in enumerate(doms, 1):
                    console.print(f"  {i}. {d}")
                console.print("  Номер для удаления:")
                n = input("> ").strip()
                if n.isdigit() and 1 <= int(n) <= len(doms):
                    _rd(int(n) - 1)
                    console.print("  [bright_green]Удалён[/]")
            def _tor_change_country():
                from vwn.modules.tor import COUNTRIES as TOR_COUNTRIES, change_country as _cc
                for i, (code, name) in enumerate(TOR_COUNTRIES, 1):
                    console.print(f"    {i:>2}. {code} — {name}")
                console.print("  Номер страны (пусто=авто):")
                cn = input("> ").strip()
                c = ""
                if cn.isdigit() and 1 <= int(cn) <= len(TOR_COUNTRIES):
                    c = TOR_COUNTRIES[int(cn) - 1][0]
                elif cn:
                    c = cn.upper()[:2]
                _cc(c)
                console.print(f"  [bright_green]Страна: {c or 'авто'}[/]")
            def _tor_check_ip():
                from vwn.modules.tor import check_ip as _ci
                r = _ci()
                console.print(f"  Прямой IP: {r['direct']}")
                console.print(f"  Tor IP:    {r['tor'] or 'N/A'}")
                console.print(f"  Выход geo: {r['country'] or 'N/A'}")
            def _tor_renew():
                from vwn.modules.tor import renew_circuit as _rc
                _rc()
                console.print("  [bright_green]Цепь обновлена[/]")
            def _tor_bridges():
                from vwn.modules.tor import add_bridges as _ab, remove_bridges as _rb, status as _ts
                console.print("  1. Добавить мосты")
                console.print("  2. Удалить мосты")
                console.print("  0. Назад")
                bv = input("> ").strip()
                if bv == "1":
                    console.print("  Тип моста:")
                    console.print("    1. obfs4 (рекомендуется)")
                    console.print("    2. snowflake (WebRTC)")
                    console.print("    3. meek_lite (Azure CDN)")
                    console.print("    4. Ручной ввод")
                    bt = input("> ").strip()
                    btype_map = {"1": "obfs4", "2": "snowflake", "3": "meek_lite", "4": ""}
                    btype = btype_map.get(bt, "")
                    console.print("  Вставьте строки мостов (по одной, пустая = готово):")
                    lines = []
                    while True:
                        l = input("> ").strip()
                        if not l:
                            break
                        lines.append(l)
                    if lines:
                        _ab(btype, lines)
                        console.print("  [bright_green]Мосты добавлены, tor перезапущен[/]")
                elif bv == "2":
                    _rb()
                    console.print("  [bright_green]Мосты удалены, tor перезапущен[/]")
            def _tor_upgrade():
                from vwn.modules.tor import upgrade as _up
                _up()
                console.print("  [bright_green]Tor обновлён[/]")
            manage_tunnel("Tor", "tor.service", "tor", has_install=True,
                          extra={
                              "Сменить страну": _tor_change_country,
                              "Добавить домен": _tor_add_domain,
                              "Удалить домен": _tor_del_domain,
                              "Проверить IP через Tor": _tor_check_ip,
                              "Обновить цепь (новый IP)": _tor_renew,
                              "Управление мостами": _tor_bridges,
                              "Обновить Tor": _tor_upgrade,
                          })
        elif choice == 7:
            def _rl_add_domain():
                console.print("  Домен для добавления:")
                d = input("> ").strip()
                if d:
                    from vwn.modules.relay import add_domain as _ad
                    _ad(d)
                    console.print(f"  [bright_green]Добавлен: {d}[/]")
            def _rl_del_domain():
                from vwn.modules.relay import list_domains as _ld, remove_domain as _rd
                doms = _ld()
                if not doms:
                    console.print("  [yellow]Нет доменов[/]"); return
                for i, d in enumerate(doms, 1):
                    console.print(f"  {i}. {d}")
                n = input("> ").strip()
                if n.isdigit() and 1 <= int(n) <= len(doms):
                    _rd(int(n) - 1)
                    console.print("  [bright_green]Удалён[/]")
            def _rl_check_ip():
                import subprocess
                from vwn.modules.relay import status as _st
                s = _st()
                if not s.get("configured"):
                    console.print("  [yellow]Relay не настроен[/]"); return
                proto = s.get("protocol", "")
                host = s.get("host", "")
                port = s.get("port", 0)
                if proto in ("socks", "socks5"):
                    r = subprocess.run(["curl", "-sS", "--max-time", "15",
                                        "--socks5-hostname", f"{host}:{port}",
                                        "https://api.ipify.org"],
                                       capture_output=True, text=True, timeout=20)
                    ip = r.stdout.strip() if r.returncode == 0 else "N/A"
                    console.print(f"  Relay IP: {ip}")
                else:
                    console.print(f"  [yellow]Проверка IP для {proto} не реализована[/]")
            manage_tunnel("Relay", "", "relay", has_configure=True,
                          extra={
                              "Добавить домен": _rl_add_domain,
                              "Удалить домен": _rl_del_domain,
                              "Проверить IP через Relay": _rl_check_ip,
                          })
        elif choice == 8:
            from vwn.modules.diag import run_full_diag
            run_full_diag()
            wait_key()
        elif choice == 9:
            security_menu()
        elif choice == 10:
            manage_privacy()
        elif choice == 11:
            manage_logs()
        elif choice == 12:
            manage_cdn()
        elif choice == 13:
            manage_backup()
        elif choice == 14:
            _rebuild_configs()
        elif choice == 15:
            _update_vwn()
        elif choice == 16:
            _update_xray()
        elif choice == 17:
            for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
                _run_cmd(f"systemctl restart {svc}")
            wait_key()
        elif choice == 18:
            full_remove()
        elif choice == 19:
            break
