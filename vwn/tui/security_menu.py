"""Подменю безопасности."""

from vwn.core.color import console
from vwn.tui.helpers import ask_port, parse_ssh_port, run_task, show_ufw_status, wait_key


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
        console.print(f"  SSH порт: {parse_ssh_port()}  Пароль: {'[red]ДА[/]' if sh['password_auth'] else '[green]НЕТ[/]'}  Root вход: {'[red]ДА (пароль)[/]' if sh['root_password_login'] else '[green]prohibit-password[/]'}")
        console.print("")
        console.print("  1. Включить BBR")
        console.print("  2. Выключить BBR (→ cubic)")
        console.print("  3. Установить и запустить Fail2Ban")
        console.print("  4. Остановить Fail2Ban")
        console.print("  5. Удалить Fail2Ban")
        console.print("  6. Открытые порты UFW")
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
            run_task("Включение BBR", bbr_enable)
        elif val == "2":
            run_task("Выключение BBR", bbr_disable)
        elif val == "3":
            run_task("Установка Fail2Ban", fail2ban_install)
        elif val == "4":
            run_task("Остановка Fail2Ban", fail2ban_stop)
        elif val == "5":
            run_task("Удаление Fail2Ban", fail2ban_remove)
        elif val == "6":
            run_task("Статус UFW", lambda: show_ufw_status(ufw))
        elif val == "7":
            p = ask_port()
            if p:
                run_task(f"Разрешить порт UFW {p}", lambda: ufw_allow(p, "tcp"))
        elif val == "8":
            p = ask_port()
            if p:
                run_task(f"Заблокировать порт UFW {p}", lambda: ufw_deny(p, "tcp"))
        elif val == "9":
            run_task("Включение WebJail", webjail_enable)
        elif val == "10":
            run_task("Выключение WebJail", webjail_disable)
        elif val == "11":
            run_task("Выключение IPv6", ipv6_disable)
        elif val == "12":
            run_task("Включение IPv6", ipv6_enable)
        elif val == "13":
            p = ask_port("Новый SSH порт")
            if p:
                run_task(f"Смена SSH порта на {p}", lambda: change_ssh_port(p))
        elif val == "14":
            if cpu_guard_status():
                run_task("Выключение CPU Guard", cpu_guard_disable)
            else:
                run_task("Включение CPU Guard", cpu_guard_enable)
        elif val == "15":
            run_task("SSH hardening (key-only)", ssh_disable_password_auth)
        wait_key()
