"""CLI-диспетчер VWNpy (click)."""

import sys

import click

from vwn import __version__


@click.group()
@click.version_option(__version__, prog_name="vwn")
def cli() -> None:
    """VWNpy — управление Xray-стеком."""


@cli.command(context_settings={"ignore_unknown_options": True})
@click.argument("args", nargs=-1)
def install(args):
    """Установка VPN-стека (логика в vwn.install).

    Все аргументы после подкоманды (--auto --domain ... ) прокидываются
    в run_install как есть.
    """
    from vwn.install import run_install
    run_install(list(args))


@cli.command()
def status():
    """Полная диагностика стека."""
    from vwn.modules.diag import run_full_diag
    run_full_diag()


@cli.command()
def menu():
    """Интерактивное TUI-меню (Rich)."""
    from vwn.tui.menu import run_menu
    run_menu()


@cli.command()
@click.option("--type", default="reality", show_default=True,
              help="Тип конфига: reality, ws, xhttp")
def qr(type):
    """Показать QR-код первого конфига (Reality, WS или XHTTP)."""
    from vwn.core import config as vwn_cfg
    from vwn.modules import sub
    import subprocess, sys

    from vwn.modules.users import list_users, init_users_file, get_config_name
    init_users_file()
    users_list = list_users()
    first = users_list[0] if users_list else {}
    uuid = first.get("uuid") or vwn_cfg.vwn_conf_get("UUID")
    label = first.get("label") or vwn_cfg.vwn_conf_get("USER_LABEL") or "default"
    ip = vwn_cfg.vwn_conf_get("SERVER_IP")
    domain = vwn_cfg.vwn_conf_get("DOMAIN")
    pubkey = vwn_cfg.vwn_conf_get("REALITY_PUBKEY")
    short_id = vwn_cfg.vwn_conf_get("SHORT_ID")
    ws_path = vwn_cfg.vwn_conf_get("WS_PATH")
    xhttp_path = vwn_cfg.vwn_conf_get("XHTTP_PATH")
    xhttp_mode = vwn_cfg.vwn_conf_get("XHTTP_MODE") or "auto"

    if not all([uuid, ip, domain]):
        click.echo("Конфиг не полный (запустите vwn install)", err=True)
        return

    dest_host = (vwn_cfg.vwn_conf_get("REALITY_DEST") or "microsoft.com").split(":")[0]

    if type == "reality":
        reality_mode = vwn_cfg.vwn_conf_get("REALITY_MODE") or "tcp"
        xhttp_path_reality = vwn_cfg.vwn_conf_get("REALITY_XHTTP_PATH") or ""
        xhttp_extra_mode = vwn_cfg.vwn_conf_get("REALITY_XHTTP_MODE") or "auto"
        url = sub.generate_reality_url(uuid, ip, 443, short_id or "", dest_host, pubkey or "", get_config_name("Reality", label), mode=reality_mode, xhttp_path=xhttp_path_reality, xhttp_extra=xhttp_extra_mode)
    elif type == "ws":
        url = sub.generate_ws_url(uuid, domain, 443, ws_path or "/ws", domain, get_config_name("WS", label))
    elif type == "xhttp":
        url = sub.generate_xhttp_url(uuid, domain, 443, xhttp_path or "/xhttp", domain, get_config_name("XHTTP", label), mode=xhttp_mode)
    else:
        click.echo(f"Неизвестный тип: {type}", err=True)
        return

    r = subprocess.run(["qrencode", "-t", "ANSIUTF8"], input=url, capture_output=True, text=True)
    if r.returncode == 0 and r.stdout:
        click.echo(r.stdout)
    else:
        click.echo(url)


@cli.command()
@click.option("--domain", required=True, help="Домен сервера")
@click.option("--stub", default="https://httpbin.org/", show_default=True, help="URL заглушки")
@click.option("--reality-dest", default="microsoft.com:443", show_default=True)
@click.option("--xhttp-mode", default="auto", show_default=True)
def provision(domain, stub, reality_dest, xhttp_mode):
    """Сгенерировать все конфиги (Reality + WS + XHTTP + loopback-nginx)."""
    from vwn.modules.xray import provision_configs
    params = provision_configs(domain, stub, reality_dest, xhttp_mode=xhttp_mode)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    click.echo(f"Конфиги записаны. UUID={params['uuid']}")


@cli.group()
def sub():
    """Управление подписками."""


@sub.command(name="rebuild")
def sub_rebuild():
    """Пересобрать подписки из vwn.conf."""
    from vwn.modules.sub import rebuild_all_sub_files, SUB_DIR
    count = rebuild_all_sub_files()
    click.echo(f"Подписки пересобраны: {count} пользователей в {SUB_DIR}")


@cli.command()
def update():
    """Обновить VWNpy из GitHub Releases (скачать wheel)."""
    import glob, os, shutil, subprocess, sys, tempfile, zipfile
    from urllib.request import urlretrieve

    REPO = "https://github.com/HnDK0/VWNpy"
    tmpdir = tempfile.mkdtemp()
    try:
        click.echo("Скачивание обновления...")
        urlretrieve(f"{REPO}/releases/latest/download/vwnpy-wheel.zip",
                    os.path.join(tmpdir, "wheel.zip"))
        wheel_dir = os.path.join(tmpdir, "wheel")
        with zipfile.ZipFile(os.path.join(tmpdir, "wheel.zip")) as zf:
            zf.extractall(wheel_dir)
        whls = glob.glob(os.path.join(wheel_dir, "*.whl"))
        if not whls:
            click.echo("Ошибка: wheel не найден в архиве", err=True)
            return
        r = subprocess.run([sys.executable, "-m", "pip", "install",
                            "--force-reinstall", whls[0]],
                           capture_output=True, text=True)
        if r.returncode == 0:
            click.echo("Готово. vwnpy обновлена.")
        else:
            click.echo(f"pip install ошибка: {r.stderr.strip()}", err=True)
    except Exception as exc:
        click.echo(f"Ошибка обновления: {exc}", err=True)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@cli.command(name="update-xray")
def update_xray():
    """Обновить Xray-core до последней версии."""
    from vwn.core.system import install_xray
    click.echo("Обновление Xray-core...")
    install_xray()
    click.echo("Готово.")


@cli.command()
def backup():
    """Создать резервную копию конфигов."""
    import os, subprocess, time
    backup_dir = "/root/vwn_backups"
    paths = [
        "/usr/local/etc/xray", "/etc/nginx/conf.d", "/etc/nginx/cert",
        "/etc/cron.d/acme-renew", "/etc/cron.d/clear-logs",
        "/etc/fail2ban/jail.local", "/etc/fail2ban/filter.d/nginx-probe.conf",
        "/etc/systemd/system/xray-*.service", "/root/.cloudflare_api",
    ]
    exist = [p for p in paths if os.path.exists(p)]
    if not exist:
        click.echo("Нечего бэкапить."); return
    os.makedirs(backup_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    fname = f"vwn_{ts}.tar.gz"
    r = subprocess.run(["tar", "-czf", f"{backup_dir}/{fname}"] + exist,
                       capture_output=True, text=True)
    if r.returncode == 0:
        size = os.path.getsize(f"{backup_dir}/{fname}") // 1024
        click.echo(f"Бэкап: {backup_dir}/{fname} ({size} KB)")
    else:
        click.echo(f"Ошибка: {r.stderr[:200]}")


@cli.command()
@click.argument("file", required=False)
def restore(file):
    """Восстановить конфиги из бэкапа (последний или указанный)."""
    import os, subprocess
    backup_dir = "/root/vwn_backups"
    if not os.path.isdir(backup_dir):
        click.echo("Нет бэкапов.")
        return
    files = sorted([f for f in os.listdir(backup_dir) if f.endswith(".tar.gz")],
                   reverse=True)
    if not files:
        click.echo("Нет бэкапов.")
        return
    if file:
        fname = file if file.endswith(".tar.gz") else file + ".tar.gz"
        if fname not in files:
            click.echo(f"Файл {fname} не найден.")
            return
    else:
        fname = files[0]
        click.echo(f"Использую последний: {fname}")
    for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
        subprocess.run(["systemctl", "stop", svc], capture_output=True)
    r = subprocess.run(["tar", "-xzf", os.path.join(backup_dir, fname), "-C", "/"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        for svc in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
            subprocess.run(["systemctl", "restart", svc], capture_output=True)
        click.echo("Восстановлено.")
    else:
        click.echo(f"Ошибка: {r.stderr[:200]}")


@cli.command(name="open-80")
def open_80():
    """Открыть порт 80 в UFW (хук acme.sh)."""
    from vwn.core import shell
    if shell.run(["ufw", "status"], check=False).returncode == 0:
        shell.run(["ufw", "allow", "from", "any", "to", "any", "port", "80",
                   "proto", "tcp", "comment", "ACME temp"], check=False)


@cli.command(name="close-80")
def close_80():
    """Закрыть порт 80 в UFW (хук acme.sh)."""
    from vwn.core import shell
    out = shell.run(["ufw", "status", "numbered"], check=False, capture=True).stdout or ""
    for line in out.splitlines():
        if "ACME temp" in line:
            num = line.split("[")[1].split("]")[0]
            shell.run(["ufw", "--force", "delete", num], check=False)


if __name__ == "__main__":
    cli()
