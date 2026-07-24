"""Подменю логов."""

from vwn.core.color import console
from vwn.tui.helpers import run_cmd, run_task, wait_key


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
            run_cmd(services[idx][1])
    except ValueError:
        pass
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
            r = run_task("Очистка логов", clear)
            if r:
                console.print(f"  Освобождено: {r['freed_kb']} КБ")
        elif val == "2":
            run_task("Настройка logrotate", setup_logrotate)
        elif val == "3":
            run_task("Настройка автообновления SSL", setup_ssl_cron)
        elif val == "4":
            run_task("Удаление автообновления SSL", remove_ssl_cron)
        elif val == "5":
            run_task("Настройка автоочистки", setup_clear_cron)
        elif val == "6":
            run_task("Удаление автоочистки", remove_clear_cron)
        elif val == "7":
            show_logs()
        wait_key()
