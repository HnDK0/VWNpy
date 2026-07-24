import os
import subprocess
import sys

from vwn.core import config
from vwn.core.color import console
from vwn.tui.dashboard import dashboard
from vwn.tui.backup_menu import manage_backup
from vwn.tui.cdn_menu import manage_cdn
from vwn.tui.helpers import (add_domain_flow, pick_country, remove_domain_flow,
    run_cmd, run_task, wait_key)
from vwn.tui.logs_menu import manage_logs
from vwn.tui.privacy_menu import manage_privacy
from vwn.tui.protocols_menu import manage_reality, manage_ws_xhttp
from vwn.tui.security_menu import security_menu
from vwn.tui.tunnel_menu import manage_tunnel
from vwn.tui.users_menu import manage_users



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
    """Пересобрать все конфиги."""
    from vwn.modules.xray import rebuild_configs
    try:
        rebuild_configs()
    except RuntimeError as e:
        console.print(f"[red]{e}[/]")
        return
    run_cmd("systemctl daemon-reload")
    for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
        run_cmd(f"systemctl restart {svc}")
    console.print("[bright_green]Конфиги пересобраны из текущих параметров[/]")


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
        run_task("pip install --force-reinstall",
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
            def _warp_add_domain() -> None:
                from vwn.modules.warp import add_domain as _ad
                console.print("  Домен для добавления:")
                d = input("> ").strip()
                if d:
                    _ad(d)
                    console.print(f"  [bright_green]Добавлен: {d}[/]")

            def _warp_remove_domain() -> None:
                from vwn.modules.warp import list_domains as _ld, remove_domain as _rd
                doms = _ld()
                if not doms:
                    console.print("  [yellow]Нет доменов[/]")
                    return
                for i, d in enumerate(doms, 1):
                    console.print(f"  {i}. {d}")
                n = input("> ").strip()
                if n.isdigit() and 1 <= int(n) <= len(doms):
                    _rd(int(n) - 1)
                    console.print("  [bright_green]Удалён[/]")

            def _warp_check_ip() -> None:
                from vwn.modules.warp import check_ip as _ci
                r = _ci()
                console.print(f"  Прямой IP: {r['direct'] or 'N/A'}")
                console.print(f"  WARP IP:   {r['warp'] or 'N/A'}")
                console.print(f"  Выход geo: {r['country'] or 'N/A'}")
                if not r["warp"] and r.get("error"):
                    console.print(f"  [red]Ошибка: {r['error']}[/]")

            def _warp_change_method() -> None:
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
                    run_task("Удаление текущего WARP", _rm)
                run_task("Установка WARP", lambda: _ins(method))

            def _warp_logs() -> None:
                from vwn.core import config as _cfg
                method = _cfg.vwn_conf_get("WARP_METHOD") or ""
                if method == "amnezia":
                    run_cmd("journalctl -u amnezia-warp -n 50 --no-pager")
                elif method == "warp-svc":
                    run_cmd("journalctl -u warp-svc -n 50 --no-pager")
                else:
                    run_cmd("journalctl -u xray-reality -n 50 --no-pager")

            manage_tunnel("WARP", "", "warp", has_install=True,
            extra={
                "Сменить метод": _warp_change_method,
                "Добавить домен": lambda: _warp_add_domain(),
                "Удалить домен": lambda: _warp_remove_domain(),
                              "Проверить IP через WARP": _warp_check_ip,
                              "Показать логи": _warp_logs,
                          })
        elif choice == 5:
            def _ps_change_country() -> None:
                from vwn.modules.psiphon import COUNTRIES as PS_COUNTRIES, MODE_FILE, _write_config as _wc
                c = pick_country(PS_COUNTRIES)
                mode = open(MODE_FILE).read().strip() if os.path.isfile(MODE_FILE) else "plain"
                upstream = "socks5://127.0.0.1:40000" if mode == "warp" else ""
                _wc(c, upstream)
                from vwn.core import shell as _sh
                _sh.run(["systemctl", "restart", "psiphon"], check=False)
                console.print(f"  [bright_green]Страна: {c or 'авто'}[/]")
            def _ps_check_ip() -> None:
                import subprocess
                from vwn.core.system import get_server_ip
                server_ip = get_server_ip()
                console.print(f"  Сервер IP: {server_ip or 'N/A'}")
                r = subprocess.run(["curl", "-sS", "--max-time", "15",
                                    "--socks5-hostname", "127.0.0.1:40002",
                                    "https://api.ipify.org"],
                                   capture_output=True, text=True, timeout=20)
                ip = r.stdout.strip() if r.returncode == 0 else "N/A"
                console.print(f"  Psiphon IP: {ip}")
                if r.returncode != 0:
                    err = r.stderr.strip()[:200] if r.stderr.strip() else f"curl exit {r.returncode}"
                    console.print(f"  [red]Ошибка: {err}[/]")
                if r.returncode == 0 and ip:
                    try:
                        r2 = subprocess.run(["mmdblookup", "--file", "/usr/local/share/GeoLite2-Country.mmdb",
                                             "--ip", ip],
                                            capture_output=True, text=True, check=False)
                    except FileNotFoundError:
                        return
                    m = __import__("re").search(r'"iso_code":\s+"([A-Z]{2})"', r2.stdout or "")
                    country = m.group(1) if m else "N/A"
                    console.print(f"  Выход geo: {country}")
            manage_tunnel("Psiphon", "psiphon.service", "psiphon", has_install=True,
                          extra={
                              "Сменить страну": _ps_change_country,
                              "Добавить домен": lambda: add_domain_flow("psiphon"),
                              "Удалить домен": lambda: remove_domain_flow("psiphon"),
                              "Проверить IP через Psiphon": _ps_check_ip,
                          })
        elif choice == 6:
            def _tor_change_country() -> None:
                from vwn.modules.tor import COUNTRIES as TOR_COUNTRIES, change_country as _cc
                c = pick_country(TOR_COUNTRIES)
                _cc(c)
                console.print(f"  [bright_green]Страна: {c or 'авто'}[/]")
            def _tor_check_ip() -> None:
                from vwn.modules.tor import check_ip as _ci
                r = _ci()
                console.print(f"  Прямой IP: {r['direct']}")
                console.print(f"  Tor IP:    {r['tor'] or 'N/A'}")
                if r.get("error"):
                    console.print(f"  [red]Ошибка: {r['error']}[/]")
                console.print(f"  Выход geo: {r['country'] or 'N/A'}")
            def _tor_renew() -> None:
                from vwn.modules.tor import renew_circuit as _rc
                _rc()
                console.print("  [bright_green]Цепь обновлена[/]")
            def _tor_bridges() -> None:
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
            def _tor_upgrade() -> None:
                from vwn.modules.tor import upgrade as _up
                _up()
                console.print("  [bright_green]Tor обновлён[/]")
            manage_tunnel("Tor", "tor.service", "tor", has_install=True,
                          extra={
                              "Сменить страну": _tor_change_country,
                              "Добавить домен": lambda: add_domain_flow("tor"),
                              "Удалить домен": lambda: remove_domain_flow("tor"),
                              "Проверить IP через Tor": _tor_check_ip,
                              "Обновить цепь (новый IP)": _tor_renew,
                              "Управление мостами": _tor_bridges,
                              "Обновить Tor": _tor_upgrade,
                          })
        elif choice == 7:
            def _rl_check_ip() -> None:
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
                    if r.returncode != 0:
                        err = r.stderr.strip()[:200] if r.stderr.strip() else f"curl exit {r.returncode}"
                        console.print(f"  [red]Ошибка: {err}[/]")
                else:
                    from vwn.modules.relay import _build_outbound as _bo
                    ob = _bo(s)
                    tmp_cfg = {"log": {"loglevel": "none"},
                               "inbounds": [{"port": 19999, "listen": "127.0.0.1",
                                             "protocol": "socks",
                                             "settings": {"auth": "noauth", "udp": False}}],
                               "outbounds": [ob]}
                    p = os.path.join("/tmp", "relay_test.json")
                    import json
                    with open(p, "w") as f:
                        json.dump(tmp_cfg, f)
                    proc = None
                    import time
                    try:
                        proc = subprocess.Popen(["/usr/local/bin/xray", "run", "-config", p],
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        time.sleep(3)
                        r = subprocess.run(["curl", "-sS", "--max-time", "15",
                                            "--socks5-hostname", "127.0.0.1:19999",
                                            "https://api.ipify.org"],
                                           capture_output=True, text=True, timeout=20)
                    finally:
                        if proc:
                            proc.kill()
                        try:
                            os.remove(p)
                        except OSError:
                            pass
                    ip = r.stdout.strip() if r.returncode == 0 else "N/A"
                    console.print(f"  Relay IP: {ip}")
                    if r.returncode != 0:
                        err = r.stderr.strip()[:200] if r.stderr.strip() else f"curl exit {r.returncode}"
                        console.print(f"  [red]Ошибка: {err}[/]")
            manage_tunnel("Relay", "", "relay", has_configure=True,
                          extra={
                              "Добавить домен": lambda: add_domain_flow("relay"),
                              "Удалить домен": lambda: remove_domain_flow("relay"),
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
            from vwn.core.system import install_xray
            run_task("Обновление Xray-core", install_xray)
        elif choice == 17:
            for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
                run_cmd(f"systemctl restart {svc}")
            wait_key()
        elif choice == 18:
            full_remove()
        elif choice == 19:
            break
