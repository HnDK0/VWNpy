"""Подменю Reality и gRPC/XHTTP."""

from vwn.core import config, shell
from vwn.core.color import console
from vwn.tui.helpers import ask_list, restart_xray_services, run_cmd, run_task, wait_key


def manage_reality() -> None:
    from vwn.modules.xray import (read_reality_info,
                                    set_reality_mode, update_domain,
                                    disable_reality, enable_reality)
    from vwn.modules.sub import get_disabled_protocols
    while True:
        info = read_reality_info()
        disabled = "reality" in get_disabled_protocols()
        if info and not disabled:
            m = info["mode"].upper()
            xh = f", path={info.get('xhttp_path','')}, mode={info.get('xhttp_mode','')}" if info["mode"] == "xhttp" else ""
            console.print(f"\n[bold]Reality[/]")
            console.print(f"  Порт: {info['port']}, SNI (домен): {info['sni']}")
            console.print(f"  Режим: {m}{xh}")
            console.print(f"  UUID: {info['uuid'][:8]}... PubKey: {info['pub_key'][:16]}...")
        elif disabled:
            console.print("\n[bold]Reality[/]  [yellow]ОТКЛЮЧЁН[/]")
        else:
            console.print("\n[bold]Reality[/]  [red]НЕ УСТАНОВЛЕН[/]")
        console.print("  1. Показать информацию")
        console.print("  2. Показать QR")
        console.print("  3. Сменить домен (SNI=домен)")
        console.print("  4. Сменить транспорт (TCP/XHTTP)")
        console.print("  5. Сменить UUID")
        console.print("  6. Перезапустить")
        console.print("  7. Показать логи")
        if disabled:
            console.print("  8. Включить")
        else:
            console.print("  8. Отключить")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            if info and not disabled:
                console.print(f"UUID:       {info['uuid']}")
                console.print(f"Порт:       {info['port']}")
                console.print(f"SNI:        {info['sni']}")
                console.print(f"Пуб.ключ:   {info['pub_key']}")
                console.print(f"Коротк.ID:  {info['short_id']}")
                console.print(f"Режим:      {info['mode'].upper()}")
                if info["mode"] == "xhttp":
                    console.print(f"XHTTP путь: {info.get('xhttp_path','')}")
                    console.print(f"XHTTP режим: {info.get('xhttp_mode','')}")
            else:
                console.print("[yellow]Reality не доступен[/]")
        elif val == "2":
            run_cmd("vwn qr --type reality")
        elif val == "3":
            if not info or disabled:
                console.print("[red]Не установлен[/]"); wait_key(); continue
            domain = input(f"  Новый домен (SNI) [{info['sni']}]: ").strip()
            if domain:
                run_task("Смена домена", lambda: update_domain(domain))
        elif val == "4":
            if not info or disabled:
                console.print("[red]Не установлен[/]"); wait_key(); continue
            mode = ask_list("Режим транспорта", ["TCP (vision)", "XHTTP"])
            if mode == "TCP (vision)":
                set_reality_mode("tcp")
                from vwn.modules.sub import rebuild_all_sub_files
                rebuild_all_sub_files()
                console.print("[bright_green]→ TCP (xtls-rprx-vision)[/]")
            elif mode == "XHTTP":
                xm = ask_list("XHTTP mode", ["auto", "stream-one", "stream-up",
                                             "packet-up", "none"])
                set_reality_mode("xhttp", xhttp_mode=xm)
                from vwn.modules.sub import rebuild_all_sub_files
                rebuild_all_sub_files()
                console.print(f"[bright_green]→ XHTTP (mode={xm})[/]")
        elif val == "5":
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
        elif val == "6":
            run_cmd("systemctl restart xray-reality")
        elif val == "7":
            run_cmd("journalctl -u xray-reality -n 50 --no-pager")
        elif val == "8":
            if disabled:
                run_task("Включение Reality", enable_reality)
            else:
                if input("Отключить Reality? (y/N): ").strip().lower() == "y":
                    run_task("Отключение Reality", disable_reality)
        wait_key()


def manage_grpc_xhttp() -> None:
    from vwn.modules.xray import (read_grpc_xhttp_info, update_grpc_service,
                                   update_xhttp_path,
                                   update_domain, update_stub_url, update_uuid_all,
                                   set_xhttp_mode, set_xhttp_cdn_mode, set_grpc_mode, renew_ssl,
                                   disable_grpc, enable_grpc, disable_xhttp, enable_xhttp,
                                   disable_ws, enable_ws, update_ws_path,
                                   read_vless_encryption, enable_vless_encryption,
                                   disable_vless_encryption, check_cert)
    from vwn.modules.sub import get_disabled_protocols
    while True:
        disabled = get_disabled_protocols()
        grpc_disabled = "grpc" in disabled
        xh_disabled = "xhttp" in disabled
        ws_disabled = "ws" in disabled
        grpc = shell.service_active("xray-grpc.service") and not grpc_disabled
        xh = shell.service_active("xray-xhttp.service") and not xh_disabled
        ws = shell.service_active("xray-ws.service") and not ws_disabled
        info = read_grpc_xhttp_info()
        ve = read_vless_encryption()
        console.print(f"\n[bold]gRPC / XHTTP / WS[/]")
        if grpc_disabled:
            console.print(f"  gRPC:   [yellow]ОТКЛЮЧЁН[/]")
        else:
            console.print(f"  gRPC:   {'[bright_green]РАБОТАЕТ[/]' if grpc else '[red]ОСТАНОВЛЕН[/]'}")
        if xh_disabled:
            console.print(f"  XHTTP:  [yellow]ОТКЛЮЧЁН[/]")
        else:
            console.print(f"  XHTTP:  {'[bright_green]РАБОТАЕТ[/]' if xh else '[red]ОСТАНОВЛЕН[/]'}")
        if ws_disabled:
            console.print(f"  WS:     [yellow]ОТКЛЮЧЁН[/]")
        else:
            console.print(f"  WS:     {'[bright_green]РАБОТАЕТ[/]' if ws else '[red]ОСТАНОВЛЕН[/]'}")
        console.print(f"  Домен:    {info['domain']}")
        console.print(f"  URL загл.: {info['stub_url']}")
        console.print(f"  gRPC:     {info['grpc_service']} (mode: {info['grpc_mode']})")
        console.print(f"  XHTTP:    {info['xhttp_path']} (mode: {info['xhttp_mode']})")
        console.print(f"  XHTTP CDN: {info.get('xhttp_cdn_mode', 'auto')}")
        console.print(f"  WS:       {info.get('ws_path', '')}")
        console.print(f"  VE:       {'on' if ve['enabled'] else 'off'}")
        console.print(f"  UUID:     {info['uuid'][:12]}...")
        console.print("  1. Показать информацию (полная)")
        console.print("  2. Показать QR (gRPC)")
        console.print("  3. Показать QR (XHTTP)")
        console.print("  4. Показать QR (XHTTP CDN)")
        console.print("  5. Показать QR (WS)")
        console.print("  6. Сменить serviceName gRPC")
        console.print("  7. Сменить путь XHTTP")
        console.print("  8. Сменить режим XHTTP (mode)")
        console.print("  9. Сменить режим XHTTP CDN (mode)")
        console.print(" 10. Сменить путь WS")
        console.print(" 11. Сменить домен")
        console.print(" 12. Сменить URL заглушки (stub)")
        console.print(" 13. Сменить UUID (все протоколы)")
        console.print(" 14. Обновить SSL сертификат")
        console.print(" 15. Перезапустить сервисы")
        console.print(" 16. Логи gRPC")
        console.print(" 17. Логи XHTTP")
        console.print(" 18. Логи WS")
        if grpc_disabled:
            console.print(" 19. Включить gRPC")
        else:
            console.print(" 19. Отключить gRPC")
        if xh_disabled:
            console.print(" 20. Включить XHTTP")
        else:
            console.print(" 20. Отключить XHTTP")
        if ws_disabled:
            console.print(" 21. Включить WS")
        else:
            console.print(" 21. Отключить WS")
        console.print(" 22. Сменить режим gRPC (gun / multi)")
        if ve["enabled"]:
            console.print(" 23. Отключить VLESS Encryption")
        else:
            console.print(" 23. Включить VLESS Encryption")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            run_cmd("vwn status")
        elif val == "2":
            run_cmd("vwn qr --type grpc")
        elif val == "3":
            run_cmd("vwn qr --type xhttp")
        elif val == "4":
            run_cmd("vwn qr --type xhttp-cdn")
        elif val == "5":
            run_cmd("vwn qr --type ws")
        elif val == "6":
            cur = info["grpc_service"]
            p = input(f"  Новый serviceName gRPC [{cur}]: ").strip()
            if p:
                run_task("Смена serviceName gRPC", lambda: update_grpc_service(p))
        elif val == "7":
            cur = info["xhttp_path"]
            p = input(f"  Новый XHTTP path [{cur}]: ").strip()
            if p:
                run_task("Смена XHTTP path", lambda: update_xhttp_path(p))
        elif val == "8":
            mode = ask_list("XHTTP mode", ["auto", "stream-one", "stream-up",
                                           "packet-up", "none"])
            run_task("Смена XHTTP mode", lambda: set_xhttp_mode(mode))
        elif val == "9":
            mode = ask_list("XHTTP CDN mode", ["auto", "stream-one", "stream-up",
                                               "packet-up", "none"])
            run_task("Смена XHTTP CDN mode", lambda: set_xhttp_cdn_mode(mode))
        elif val == "10":
            cur = info.get("ws_path", "")
            p = input(f"  Новый WS path [{cur}]: ").strip()
            if p:
                run_task("Смена WS path", lambda: update_ws_path(p))
        elif val == "11":
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
        elif val == "12":
            cur = info["stub_url"]
            u = input(f"  Новый stub URL [{cur}]: ").strip()
            if u:
                run_task("Смена stub URL", lambda: update_stub_url(u))
        elif val == "13":
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
        elif val == "14":
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
        elif val == "15":
            restart_xray_services()
        elif val == "16":
            run_cmd("journalctl -u xray-grpc -n 50 --no-pager")
        elif val == "17":
            run_cmd("journalctl -u xray-xhttp -n 50 --no-pager")
        elif val == "18":
            run_cmd("journalctl -u xray-ws -n 50 --no-pager")
        elif val == "19":
            if grpc_disabled:
                run_task("Включение gRPC", enable_grpc)
            else:
                if input("Отключить gRPC? (y/N): ").strip().lower() == "y":
                    run_task("Отключение gRPC", disable_grpc)
        elif val == "20":
            if xh_disabled:
                run_task("Включение XHTTP", enable_xhttp)
            else:
                if input("Отключить XHTTP? (y/N): ").strip().lower() == "y":
                    run_task("Отключение XHTTP", disable_xhttp)
        elif val == "21":
            if ws_disabled:
                run_task("Включение WS", enable_ws)
            else:
                if input("Отключить WS? (y/N): ").strip().lower() == "y":
                    run_task("Отключение WS", disable_ws)
        elif val == "22":
            mode = ask_list("gRPC mode", ["gun", "multi"])
            run_task("Смена gRPC mode", lambda: set_grpc_mode(mode))
        elif val == "23":
            if ve["enabled"]:
                if input("Отключить VLESS Encryption? (y/N): ").strip().lower() == "y":
                    run_task("Отключение VLESS Encryption", disable_vless_encryption)
            else:
                run_task("Включение VLESS Encryption", lambda: enable_vless_encryption(force_new_keys=True))
        wait_key()
