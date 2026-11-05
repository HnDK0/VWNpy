"""CLI-диспетчер VWNpy (click)."""

import sys

import click

from vwn import __version__


@click.group()
@click.version_option(__version__, prog_name="vwn")
def cli() -> None:
    """VWNpy — управление Xray-стеком."""
    from vwn.cores import switch

    try:
        switch.recover_pending()
    except Exception as exc:
        click.echo(f"Восстановление после переключения ядра: {exc}", err=True)


@cli.group()
def core():
    """Управление ядром: xray или mihomo."""


@core.command("status")
def core_status():
    """Показать активное ядро, версию и ограничения."""
    from vwn.core import config
    from vwn.cores import registry

    backend = registry.get_core()
    from vwn.cores import versions
    version = config.vwn_conf_get(
        "MIHOMO_VERSION" if backend.name == "mihomo" else "XRAY_VERSION"
    ) or (versions.current_version() if backend.name == "mihomo" else "")
    click.echo(f"Ядро:       {backend.name}")
    click.echo(f"Версия:     {version or 'не пиннингована'}")
    click.echo(f"Бинарь:     {backend.bin} ({'есть' if backend.available() else 'нет'})")
    click.echo(f"Сервисы:    {', '.join(backend.services)}")
    click.echo(f"Возможности: {', '.join(sorted(backend.capabilities))}")
    if "bt-rule" not in backend.capabilities:
        click.echo("Ограничение: нет правила BitTorrent (риск для публичного сервера)")
    if "mptcp-in" not in backend.capabilities:
        click.echo("Ограничение: MPTCP inbound не поддерживается")
    click.echo("Доступные:  " + ", ".join(registry.CORE_NAMES))


@core.command("list")
def core_list():
    """Список ядер и статус установки."""
    from vwn.core import config
    from vwn.cores import registry

    current = config.core_name()
    for name, backend in registry.available_cores().items():
        mark = "*" if name == current else " "
        state = "установлено" if backend.available() else "не установлено"
        click.echo(f"{mark} {name:8} {state}")


@core.command("set")
@click.argument("name", type=click.Choice(["xray", "mihomo"]))
def core_set(name):
    """Переключить активное ядро (xray/mihomo) с откатом при ошибке."""
    from vwn.core import config
    from vwn.cores import registry

    if name == config.core_name():
        registry.get_core(name).rebuild(refresh_ip=True)
        click.echo(f"Ядро {name} уже активно; конфиги пересобраны.")
        return
    from vwn.cores import switch

    try:
        switch.switch_to(name)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Активное ядро: {name}.")



@core.command("rollback")
def core_rollback():
    """Откатить бинарь активного ядра на предыдущий."""
    import os
    import re
    import shutil
    import subprocess
    from vwn.core import config
    from vwn.cores import registry, versions

    backend = registry.get_core()
    if backend.name == "mihomo":
        version = versions.rollback_mihomo()
        click.echo(f"mihomo откатан на {version}")
    else:
        old = backend.bin + ".old"
        if not os.path.isfile(old):
            raise click.ClickException("xray.old не найден — откатывать нечего")
        shutil.copy2(old, backend.bin)
        os.chmod(backend.bin, 0o755)
        r = subprocess.run([backend.bin, "version"], capture_output=True, text=True)
        match = re.search(r"Xray\s+v?([0-9][^\s]*)", r.stdout + r.stderr)
        if match:
            config.vwn_conf_set("XRAY_VERSION", match.group(1))
        click.echo("Xray откатан на предыдущий бинарь")
    for svc in registry.active_services(backend):
        subprocess.run(["systemctl", "restart", svc], check=False)


@core.command("recover")
def core_recover():
    """Завершить прерванный switch ядра (используется guard-юнитом)."""
    from vwn.cores import switch

    switch.recover_pending()
    click.echo("Состояние ядра проверено.")


@core.command("update")
@click.option("--version", default=None, help="Версия для установки")
@click.option("--check", is_flag=True, help="Только проверить доступную версию")
def core_update(version, check):
    """Обновить/установить активное ядро."""
    from vwn.cores import registry

    backend = registry.get_core()
    if check:
        if backend.name == "mihomo":
            from vwn.cores import versions
            click.echo(f"Установлена: {versions.current_version()}")
            click.echo(f"Latest:      {versions.latest_version()}")
        else:
            from vwn.core import config
            click.echo(f"Установлена: {config.vwn_conf_get('XRAY_VERSION') or 'неизвестна'}")
        return
    backend.install(version)
    click.echo(f"Ядро {backend.name} установлено.")


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
@click.argument("out", required=False)
def report(out):
    """Собрать диагностику сервера в файл (секреты маскируются).

    Для разбора проблем gRPC/XHTTP: версии, ядро/BBR, сервисы, конфиги,
    проверки цепочки xray→nginx→443, DNS/исходящая сеть, логи.
    """
    import os
    import subprocess
    script = os.path.join(os.path.dirname(__file__), "data", "collect_report.sh")
    sys.exit(subprocess.call(["bash", script] + ([out] if out else [])))


@cli.command()
def menu():
    """Интерактивное TUI-меню (Rich)."""
    from vwn.tui.menu import run_menu
    try:
        run_menu()
    except (KeyboardInterrupt, EOFError):
        click.echo()


@cli.command(name="cdn-watch")
def cdn_watch():
    """Один проход CDN-вотчера (вызывается таймером vwn-cdn-watch)."""
    from vwn.modules.cdn import watch
    sys.exit(watch())


@cli.command()
@click.option("--type", default="reality", show_default=True,
              help="Тип конфига: reality, grpc, xhttp, ws")
def qr(type):
    """Показать QR-код первого конфига (Reality, gRPC или XHTTP)."""
    from vwn.core import config as vwn_cfg
    from vwn.modules import sub
    import subprocess

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
    grpc_service = vwn_cfg.vwn_conf_get("GRPC_SERVICE")
    grpc_mode = vwn_cfg.vwn_conf_get("GRPC_MODE") or "gun"
    xhttp_path = vwn_cfg.vwn_conf_get("XHTTP_PATH")
    xhttp_mode = vwn_cfg.vwn_conf_get("XHTTP_MODE") or "auto"
    xhttp_cdn_mode = vwn_cfg.vwn_conf_get("XHTTP_CDN_MODE") or "auto"
    from vwn.modules import xray as _xray
    _ve = _xray.read_vless_encryption()
    enc = _ve["encryption"] if _ve["enabled"] else "none"
    if not all([uuid, ip, domain]):
        click.echo("Конфиг не полный (запустите vwn install)", err=True)
        return

    dest_host = (vwn_cfg.vwn_conf_get("REALITY_DEST")
                 or vwn_cfg.vwn_conf_get("DOMAIN")
                 or "example.com").split(":")[0]

    if type == "reality":
        reality_mode = vwn_cfg.vwn_conf_get("REALITY_MODE") or "tcp"
        xhttp_path_reality = vwn_cfg.vwn_conf_get("REALITY_XHTTP_PATH") or ""
        xhttp_extra_mode = vwn_cfg.vwn_conf_get("REALITY_XHTTP_MODE") or "auto"
        url = sub.generate_reality_url(uuid, ip, 443, short_id or "", dest_host, pubkey or "", get_config_name("Reality", label), mode=reality_mode, xhttp_path=xhttp_path_reality, xhttp_mode=xhttp_extra_mode, extra_json=sub._xhttp_client_extra_json())
    elif type == "grpc":
        if not grpc_service:
            click.echo("gRPC не настроен (GRPC_SERVICE пуст) — выполните vwn rebuild", err=True)
            return
        from vwn.core import config as _c
        connect_host = domain
        try:
            ch = open(_c.connect_host_file_path()).read().strip()
            if ch:
                connect_host = ch
        except OSError:
            pass
        if connect_host == domain:
            click.echo("gRPC публикуется только через CDN (CDN не включён)", err=True)
            return
        url = sub.generate_grpc_url(uuid, connect_host, 443, grpc_service, domain, get_config_name("gRPC", label), mode=grpc_mode, vless_encryption=enc)
    elif type == "xhttp":
        if not sub.xhttp_direct_enabled():
            raise click.ClickException(
                "XHTTP direct скрыт (XHTTP_DIRECT=off) — используйте --type xhttp-cdn"
            )
        url = sub.generate_xhttp_url(uuid, ip, 443, xhttp_path or "/xhttp", domain, get_config_name("XHTTP", label), mode=xhttp_mode, extra_json=sub._xhttp_client_extra_json(cdn=False), vless_encryption=enc)
    elif type == "xhttp-cdn":
        from vwn.core import config as _c
        connect_host = domain
        try:
            ch = open(_c.connect_host_file_path()).read().strip()
            if ch:
                connect_host = ch
        except OSError:
            pass
        if connect_host == domain:
            click.echo("CDN не включён (connect_host == domain)", err=True)
            return
        url = sub.generate_xhttp_url(uuid, connect_host, 443, xhttp_path or "/xhttp", domain, get_config_name("XHTTP-CDN", label), mode=xhttp_cdn_mode or "auto", extra_json=sub._xhttp_client_extra_json(cdn=True), vless_encryption=enc)
    elif type == "ws":
        ws_path = vwn_cfg.vwn_conf_get("WS_PATH")
        if not ws_path:
            click.echo("WS не настроен (WS_PATH пуст) — выполните vwn rebuild", err=True)
            return
        from vwn.core import config as _c
        connect_host = domain
        try:
            ch = open(_c.connect_host_file_path()).read().strip()
            if ch:
                connect_host = ch
        except OSError:
            pass
        if connect_host == domain:
            click.echo("WS публикуется только через CDN (CDN не включён)", err=True)
            return
        url = sub.generate_ws_url(uuid, connect_host, 443, ws_path, domain, get_config_name("WS", label), vless_encryption=enc)
    else:
        click.echo(f"Неизвестный тип: {type}", err=True)
        return

    try:
        r = subprocess.run(["qrencode", "-t", "ANSIUTF8"], input=url,
                           capture_output=True, text=True)
    except OSError:
        r = None
    if r is not None and r.returncode == 0 and r.stdout:
        click.echo(r.stdout)
    else:
        click.echo(url)


@cli.command()
@click.option("--domain", required=True, help="Домен сервера")
@click.option("--stub", default="https://httpbin.org/", show_default=True, help="URL заглушки")
@click.option("--xhttp-mode", default="auto", show_default=True)
def provision(domain, stub, xhttp_mode):
    """Сгенерировать все конфиги (Reality + gRPC + XHTTP + loopback-nginx).

    SNI Reality всегда равен домену (self-steal); отдельный reality-dest
    больше не используется.
    """
    from vwn.core import config as vwn_cfg
    from vwn.install import InstallOptions, _provision_core
    _provision_core(InstallOptions(
        domain=domain, stub=stub, core=vwn_cfg.core_name(),
        xhttp_mode=xhttp_mode, preserve_existing=True,
    ))
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    click.echo("Конфиги записаны.")


@cli.command()
def rebuild():
    """Пересобрать конфиги из vwn.conf (UUID/ключи сохраняются).

    Для установок на WebSocket выполняет и переход на gRPC: удаляет xray-ws,
    заводит GRPC_SERVICE, обновляет nginx и подписки.
    """
    import subprocess
    from vwn.core import config
    from vwn.cores import registry
    from vwn.modules.xray import legacy_ws_present
    backend = registry.get_core()
    was_ws = legacy_ws_present() if backend.name == "xray" else False
    try:
        backend.rebuild(refresh_ip=True)
    except RuntimeError as exc:
        click.echo(f"Ошибка: {exc}", err=True)
        sys.exit(1)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    for svc in list(registry.active_services(backend)) + [config.NGINX_SERVICE]:
        subprocess.run(["systemctl", "restart", svc], check=False)
    click.echo("Конфиги пересобраны." + (" Переход WS → gRPC выполнен; "
               "новые ссылки — в подписках (старые WS-ссылки перестали работать)."
               if was_ws else ""))


@cli.group()
def sub():
    """Управление подписками."""


@sub.command(name="rebuild")
def sub_rebuild():
    """Пересобрать подписки из vwn.conf."""
    from vwn.modules.sub import rebuild_all_sub_files, SUB_DIR
    count = rebuild_all_sub_files(refresh_ip=True)
    click.echo(f"Подписки пересобраны: {count} пользователей в {SUB_DIR}")


@sub.command(name="xhttp-direct")
@click.argument("action", type=click.Choice(["on", "off"]))
def sub_xhttp_direct(action):
    """Публиковать ли direct-XHTTP (без CDN) в подписках."""
    from pathlib import Path
    from vwn.core import config as vwn_cfg
    from vwn.modules import sub as sub_mod

    if action == "off":
        domain = vwn_cfg.vwn_conf_get("DOMAIN") or ""
        connect_host = ""
        try:
            connect_host = Path(vwn_cfg.connect_host_file_path()).read_text().strip()
        except OSError:
            pass
        if not connect_host or connect_host == domain:
            raise click.ClickException(
                "CDN не включён: выключение direct-XHTTP оставит подписку без XHTTP"
            )
    vwn_cfg.vwn_conf_set("XHTTP_DIRECT", action)
    sub_mod.rebuild_all_sub_files()
    click.echo(f"XHTTP direct: {action}")


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
            # свежий процесс: этот ещё держит старые модули в памяти
            chk = subprocess.run(
                [sys.executable, "-c",
                 "from vwn.modules.xray import legacy_ws_present;"
                 "print(int(legacy_ws_present()))"],
                capture_output=True, text=True)
            if chk.stdout.strip() == "1":
                click.echo("Сервер ещё на WebSocket. Выполните «vwn rebuild» — "
                           "переход на gRPC (UUID и ключи сохранятся, ссылки в "
                           "подписках обновятся).")
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
    import subprocess
    from vwn.core import config
    for svc in config.XRAY_SERVICES:
        subprocess.run(["systemctl", "restart", svc], check=False)
    click.echo("Готово.")


@cli.command(name="update-mihomo")
@click.option("--version", default=None, help="Версия (по умолчанию latest)")
@click.option("--check", is_flag=True, help="Только показать версии")
def update_mihomo(version, check):
    """Обновить mihomo до последней версии."""
    from vwn.core import config as vwn_cfg
    from vwn.cores import registry, versions

    latest = versions.latest_version()
    target = version or latest
    if check:
        click.echo(f"Установлена: {versions.current_version()}")
        click.echo(f"Latest:      {latest}")
        return
    click.echo(f"Обновление mihomo: {versions.current_version()} → {target}")
    versions.install_mihomo(target)
    if vwn_cfg.core_name() == "mihomo":
        registry.get_core("mihomo").rebuild(refresh_ip=False)
    click.echo("Готово.")


@cli.command(name="vless-enc")
@click.argument("action", type=click.Choice(["on", "off"]))
def vless_enc(action):
    """Включить/выключить VLESS Encryption (mlkem768x25519plus)."""
    from vwn.modules.xray import enable_vless_encryption, disable_vless_encryption
    if action == "on":
        enable_vless_encryption()
    else:
        disable_vless_encryption()
    click.echo(f"VLESS Encryption: {action}")


@cli.command()
def backup():
    """Создать резервную копию конфигов."""
    import os, subprocess, time
    backup_dir = "/root/vwn_backups"
    paths = [
        "/usr/local/etc/xray", "/usr/local/etc/mihomo", "/etc/nginx/conf.d",
        "/etc/nginx/cert", "/etc/cron.d/acme-renew", "/etc/cron.d/clear-logs",
        "/etc/fail2ban/jail.local", "/etc/fail2ban/filter.d/nginx-probe.conf",
        "/etc/systemd/system/xray-*.service", "/etc/systemd/system/mihomo-*.service",
        "/usr/local/bin/xray", "/usr/local/bin/mihomo", "/usr/local/bin/mihomo.prev",
        "/root/.cloudflare_api",
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
    from vwn.core import config
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
    from vwn.cores import registry
    for svc in list(registry.get_core().services) + [config.NGINX_SERVICE]:
        subprocess.run(["systemctl", "stop", svc], capture_output=True)
    r = subprocess.run(["tar", "-xzf", os.path.join(backup_dir, fname), "-C", "/"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        warning = registry.sanitize()
        if warning:
            click.echo(warning)
        for svc in list(registry.get_core().services) + [config.NGINX_SERVICE]:
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


@cli.group(name="vless-enc")
def vless_enc():
    """Управление VLESS Encryption (mlkem768x25519plus)."""
    pass


@vless_enc.command(name="status")
def vless_enc_status():
    from vwn.modules import xray
    info = xray.read_vless_encryption()
    click.echo("VLESS Encryption: %s" % ("on" if info["enabled"] else "off"))
    click.echo("  XHTTP/gRPC/WS: %s" % ("on" if info["enabled"] else "off"))
    click.echo("  Reality:       none")
    if info["enabled"]:
        click.echo("  decryption: %s" % info["decryption"][:24] + "...")
        click.echo("  encryption: %s" % info["encryption"][:24] + "...")


@vless_enc.command(name="on")
@click.option("--force-new-keys", is_flag=True, default=False)
def vless_enc_on(force_new_keys):
    from vwn.modules import xray
    try:
        xray.enable_vless_encryption(force_new_keys=force_new_keys)
    except RuntimeError as exc:
        click.echo("Ошибка: %s" % exc, err=True)
        sys.exit(1)
    click.echo("VLESS Encryption включена.")


@vless_enc.command(name="off")
def vless_enc_off():
    from vwn.modules import xray
    xray.disable_vless_encryption()
    click.echo("VLESS Encryption выключена.")


if __name__ == "__main__":
    cli()
