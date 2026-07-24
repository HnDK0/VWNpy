"""Подменю Reality и WS/XHTTP."""

from vwn.core import config, shell
from vwn.core.color import console
from vwn.tui.helpers import ask_list, restart_xray_services, run_cmd, run_task, wait_key


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
            run_cmd("vwn qr --type reality")
        elif val == "3":
            if not info:
                console.print("[red]Не установлен[/]"); wait_key(); continue
            try:
                p = int(input(f"  Порт [{info['port']}]: ").strip())
                if 1024 <= p <= 65535:
                    run_task("Смена порта", lambda: update_reality_port(p))
                else:
                    console.print("[red]Порт должен быть 1024-65535[/]")
            except (ValueError, EOFError):
                pass
        elif val == "4":
            if not info:
                console.print("[red]Не установлен[/]"); wait_key(); continue
            dest = input(f"  Dest [{info['dest']}]: ").strip()
            if dest and ":" in dest:
                run_task("Смена dest", lambda: update_reality_dest(dest))
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
            run_cmd("systemctl restart xray-reality")
        elif val == "8":
            run_cmd("journalctl -u xray-reality -n 50 --no-pager")
        elif val == "9":
            if input("Удалить Reality? (y/N): ").strip().lower() == "y":
                run_task("Удаление Reality", remove_reality)
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
            run_cmd("vwn status")
        elif val == "2":
            run_cmd("vwn qr --type ws")
        elif val == "3":
            run_cmd("vwn qr --type xhttp")
        elif val == "4":
            cur = info["ws_path"]
            p = input(f"  Новый WS path [{cur}]: ").strip()
            if p:
                run_task("Смена WS path", lambda: update_ws_path(p))
        elif val == "5":
            cur = info["xhttp_path"]
            p = input(f"  Новый XHTTP path [{cur}]: ").strip()
            if p:
                run_task("Смена XHTTP path", lambda: update_xhttp_path(p))
        elif val == "6":
            mode = ask_list("XHTTP mode", ["auto", "stream-one", "stream-up",
                                           "packet-one", "packet-up", "none"])
            run_task("Смена XHTTP mode", lambda: set_xhttp_mode(mode))
        elif val == "7":
            cur = info["domain"]
            d = input(f"  Новый домен [{cur}]: ").strip()
            if d:
                run_task("Смена домена", lambda: update_domain(d))
                if input("  Перевыпустить SSL для нового домена? (y/N): ").strip().lower() == "y":
                    cert_info = check_cert(d)
                    console.print("  Метод SSL:")
                    console.print("    1. Самоподписанный (self-signed)")
                    console.print("    2. ACME standalone (порт 80)")
                    console.print("    3. ACME Cloudflare DNS")
                    m = input("> ").strip()
                    if m == "1":
                        run_task("SSL самоподписанный", lambda: renew_ssl(d, "self"))
                    elif m == "2":
                        run_task("SSL ACME standalone", lambda: renew_ssl(d, "standalone"))
                    elif m == "3":
                        ce = input("  CF Email: ").strip()
                        ck = input("  CF Key: ").strip()
                        if ce and ck:
                            run_task("SSL ACME CF", lambda: renew_ssl(d, "cf", ce, ck))
        elif val == "8":
            cur = info["stub_url"]
            u = input(f"  Новый stub URL [{cur}]: ").strip()
            if u:
                run_task("Смена stub URL", lambda: update_stub_url(u))
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
                run_task("SSL самоподписанный", lambda: renew_ssl(domain, "self"))
            elif m == "2":
                run_task("SSL ACME standalone", lambda: renew_ssl(domain, "standalone"))
            elif m == "3":
                ce = input("  CF Email: ").strip()
                ck = input("  CF Key: ").strip()
                if ce and ck:
                    run_task("SSL ACME CF", lambda: renew_ssl(domain, "cf", ce, ck))
        elif val == "11":
            restart_xray_services()
        elif val == "12":
            run_cmd("journalctl -u xray-ws -n 50 --no-pager")
        elif val == "13":
            run_cmd("journalctl -u xray-xhttp -n 50 --no-pager")
        elif val == "14":
            if input("Удалить WS? (y/N): ").strip().lower() == "y":
                run_task("Удаление WS", remove_ws)
        elif val == "15":
            if input("Удалить XHTTP? (y/N): ").strip().lower() == "y":
                run_task("Удаление XHTTP", remove_xhttp)
        wait_key()
