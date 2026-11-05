"""Подменю безопасности."""

from vwn.core.color import console
from vwn.tui.helpers import ask_port, parse_ssh_port, run_task, show_ufw_status, wait_key


def _dns_menu() -> None:
    """Подменю выбора DNS-провайдера."""
    from vwn.core.system import dns_status, dns_set, _DNS_PRESETS, setup_system_dns
    from vwn.core import config, shell
    from vwn.core.color import console

    def _apply() -> None:
        """Применить DNS: обновить системный resolv.conf и перезапустить Xray."""
        setup_system_dns()
        # сбросить кэш резолвера (systemd-resolved)
        shell.run(["resolvectl", "flush-caches"], check=False)
        shell.run(["systemd-resolve", "--flush-caches"], check=False)
        from vwn.cores import registry
        shell.run(["systemctl", "restart"] + list(registry.get_core().services), check=False)

    while True:
        st = dns_status()
        current = st["preset"] or "auto"
        console.print("\n[bold]Настройка DNS[/]")
        console.print(f"  Текущий: {current}")
        if st["v4"][0]:
            console.print(f"  IPv4: {st['v4'][0]}, {st['v4'][1]}")
        if st["v6"][0]:
            console.print(f"  IPv6: {st['v6'][0]}, {st['v6'][1]}")
        console.print("")
        console.print("  1. Cloudflare (1.1.1.1 / 2606:4700:4700::1111)")
        console.print("  2. Google (8.8.8.8 / 2001:4860:4860::8888)")
        console.print("  3. Quad9 (9.9.9.9 / 2620:fe::fe)")
        console.print("  4. AdGuard (94.140.14.14 / 2a10:50c0::ad1)")
        console.print("  5. OpenDNS (208.67.222.222 / 2620:119:35::35)")
        console.print("  6. Кастомный ввод")
        console.print("  7. Сбросить на автовыбор")
        console.print("  0. Назад")
        val = input("> ").strip()
        if val == "0":
            break
        elif val == "7":
            dns_set("")
            _apply()
            console.print("  [bright_green]DNS сброшен на автовыбор и применён.[/]")
            break
        elif val in ("1", "2", "3", "4", "5"):
            preset_keys = {"1": "cloudflare", "2": "google", "3": "quad9", "4": "adguard", "5": "opendns"}
            key = preset_keys[val]
            p = _DNS_PRESETS[key]
            dns_set(key, p["v4"][0], p["v4"][1], p["v6"][0], p["v6"][1])
            _apply()
            console.print(f"  [bright_green]DNS установлен: {p['name']} и применён.[/]")
            break
        elif val == "6":
            console.print("  IPv4 primary (например 1.1.1.1):")
            v4p = input("  > ").strip()
            console.print("  IPv4 fallback (например 1.0.0.1):")
            v4f = input("  > ").strip()
            console.print("  IPv6 primary (пусто если нет):")
            v6p = input("  > ").strip()
            console.print("  IPv6 fallback (пусто если нет):")
            v6f = input("  > ").strip()
            if v4p:
                dns_set("custom", v4p, v4f or v4p, v6p, v6f)
                _apply()
                console.print("  [bright_green]DNS установлен и применён.[/]")
                break
            else:
                console.print("  [red]IPv4 primary обязателен[/]")


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
    from vwn.core.system import dns_status, dns_set, _DNS_PRESETS  # ADD THIS LINE
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
        dns = dns_status()
        dns_preset = dns["preset"]
        dns_v4 = dns["v4"][0] if dns["v4"][0] else "авто"
        dns_v6 = dns["v6"][0] if dns["v6"][0] else "нет"
        preset_name = _DNS_PRESETS.get(dns_preset, {}).get("name", dns_preset) if dns_preset else "авто"
        console.print(f"  DNS:      {preset_name}  IPv4: {dns_v4}  IPv6: {dns_v6}")
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
        console.print(" 16. Настроить DNS")
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
        elif val == "16":
            _dns_menu()
        wait_key()
