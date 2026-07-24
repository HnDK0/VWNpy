"""Подменю бэкапов."""

import os
import subprocess
import time

from vwn.core.color import console
from vwn.tui.helpers import wait_key


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
                subprocess.run(["systemctl", "stop", svc])
            r = subprocess.run(["tar", "-xzf", os.path.join(backup_dir, fname), "-C", "/"],
                               capture_output=True, text=True)
            if r.returncode == 0:
                subprocess.run(["systemctl", "daemon-reload"])
                for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
                    subprocess.run(["systemctl", "restart", svc])
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
