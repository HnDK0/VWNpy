"""Подменю CDN."""

from vwn.core import config
from vwn.core.color import console
from vwn.tui.helpers import edit_list_in_editor, run_task, wait_key


def _cdn_menu_scanner_settings() -> None:
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
        console.print("  9. Редактировать список доменов")
        console.print(" 10. Заблокировать текущий IP")
        console.print(" 11. Показать/очистить чёрный список")
        console.print(" 12. Установить/удалить вотчер")
        console.print(" 13. Проверить IP")
        console.print(" 14. Настройки сканера")
        console.print(" 15. Редактировать список IP (cdn_ips.txt)")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "1":
            run_task("CDN выкл", lambda: set_mode("off"))
        elif val == "2":
            ip = input("  IP или домен: ").strip()
            if ip:
                run_task("Применить ручной", lambda: (set_mode("manual"), apply_ip(ip)))
        elif val == "3":
            run_task("Авто-резолв", lambda: set_mode("auto_resolve"))
        elif val == "4":
            run_task("Авто-сканер", lambda: set_mode("auto_scan"))
        elif val == "5":
            run_task("Сканирование", lambda: scan(foreground=True))
        elif val == "6":
            ip = find_best(config.vwn_conf_get("CDN_MODE", ""))
            if ip:
                run_task("Применить лучший", lambda: apply_ip(ip))
            else:
                console.print("  [yellow]Нет кандидатов[/]")
        elif val == "7":
            d = input("  Домен: ").strip()
            if d:
                run_task("Добавление домена", lambda: domains_add(d))
        elif val == "8":
            doms = domains_list()
            if not doms:
                console.print("  [yellow]Нет доменов[/]"); wait_key(); continue
            for i, d in enumerate(doms, 1):
                console.print(f"  {i}. {d}")
            n = input("  Номер: ").strip()
            if n.isdigit() and 1 <= int(n) <= len(doms):
                run_task("Удаление домена", lambda: domains_remove(int(n) - 1))
        elif val == "9":
            from vwn.modules.cdn import DOMAINS_FILE
            edit_list_in_editor(DOMAINS_FILE)
        elif val == "10":
            ip = s["ip"]
            if ip:
                run_task("Чёрный список", lambda: blacklist_add(ip))
                best = find_best(config.vwn_conf_get("CDN_MODE", ""), ip)
                if best:
                    run_task("Применение нового IP", lambda: apply_ip(best))
                else:
                    console.print("  [yellow]Нет доступных IP для замены[/]")
        elif val == "11":
            bl = blacklist_list()
            if bl:
                for ip in bl:
                    console.print(f"  {ip}")
                if input("  Очистить чёрный список? (y/N): ").strip().lower() == "y":
                    blacklist_clear()
                    console.print("  [bright_green]Очищен[/]")
            else:
                console.print("  [yellow]Пусто[/]")
        elif val == "12":
            if s["watcher"]:
                run_task("Удаление вотчера", remove_watcher)
            else:
                run_task("Установка вотчера", install_watcher)
        elif val == "13":
            ip = input("  IP для проверки: ").strip()
            if ip:
                ms = ping(ip)
                console.print(f"  {'[bright_green]ДОСТУПЕН' if ms < 9999 else '[red]ОШИБКА'} ({ms}ms)" if ms < 9999 else "  [red]Недоступен[/]")
        elif val == "14":
            _cdn_menu_scanner_settings()
        elif val == "15":
            from vwn.modules.cdn import IPS_FILE
            edit_list_in_editor(IPS_FILE)
        wait_key()
