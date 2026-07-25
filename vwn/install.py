"""Логика установщика VWNpy.

Чистая логика (парсинг/валидация опций) отделена от ОС-зависимого
исполнения, чтобы её можно было тестировать без сервера.
"""

from dataclasses import dataclass, field
from typing import List

from vwn.core import cert, config, shell, system
from vwn.core.color import C, console
from vwn.modules import sub, xray
from vwn.core.validate import validate_domain, validate_port, validate_url


@dataclass
class InstallOptions:
    """Опции автоустановки. Reality+WS+XHTTP ставятся всегда."""

    domain: str = ""
    stub: str = "https://httpbin.org/"
    lang: str = "ru"
    reality_dest: str = "microsoft.com:443"
    reality_port: int = 443
    cert_method: str = "standalone"
    cf_email: str = ""
    cf_key: str = ""
    ssh_port: int = 22
    bbr: bool = False
    fail2ban: bool = False
    no_warp: bool = False
    jail: bool = False
    ipv6: bool = False
    cpu_guard: bool = False
    psiphon: bool = False
    psiphon_country: str = ""
    psiphon_warp: bool = False

    unknown: List[str] = field(default_factory=list)


_VALUE_FLAGS = {
    "--domain": "domain", "--stub": "stub", "--lang": "lang",
    "--reality-dest": "reality_dest", "--reality-port": "reality_port",
    "--cert-method": "cert_method", "--cf-email": "cf_email", "--cf-key": "cf_key",
    "--ssh-port": "ssh_port", "--psiphon-country": "psiphon_country",
}

_BOOL_FLAGS = {
    "--bbr": "bbr", "--fail2ban": "fail2ban", "--no-warp": "no_warp",
    "--jail": "jail", "--ipv6": "ipv6", "--cpu-guard": "cpu_guard",
    "--psiphon": "psiphon", "--psiphon-warp": "psiphon_warp",
}


def parse_auto_args(argv: List[str]) -> InstallOptions:
    opts = InstallOptions()
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in _VALUE_FLAGS:
            key = _VALUE_FLAGS[a]
            if i + 1 >= len(argv):
                raise ValueError(f"{a} требует значение")
            val = argv[i + 1]
            i += 2
            if key in ("reality_port", "ssh_port"):
                setattr(opts, key, int(val))
            else:
                setattr(opts, key, val)
        elif a in _BOOL_FLAGS:
            setattr(opts, _BOOL_FLAGS[a], True)
            i += 1
        else:
            opts.unknown.append(a)
            i += 1
    return opts


def validate_auto_options(opts: InstallOptions) -> None:
    validate_domain(opts.domain)
    validate_url(opts.stub)

    if opts.cert_method not in ("cf", "standalone", "self"):
        raise ValueError("--cert-method: допустимо 'cf', 'standalone' или 'self'")
    if opts.cert_method == "cf":
        if not opts.cf_email:
            raise ValueError("--cf-email обязателен при --cert-method cf")
        if not opts.cf_key:
            raise ValueError("--cf-key обязателен при --cert-method cf")

    validate_port(opts.reality_port, 443, 65535)
    if opts.ssh_port:
        validate_port(opts.ssh_port, 1, 65535)

    if opts.psiphon_country:
        if not (len(opts.psiphon_country) == 2 and opts.psiphon_country.isalpha()):
            raise ValueError("--psiphon-country: 2-буквенный код (DE, NL, US...)")
        opts.psiphon_country = opts.psiphon_country.upper()

    if opts.psiphon_warp and opts.no_warp:
        raise ValueError("--psiphon-warp несовместим с --no-warp")


def _setup_ufw(ufw_allow) -> None:
    from vwn.modules.security import _parse_ssh_port
    ufw_allow(_parse_ssh_port(), "tcp", "SSH")
    ufw_allow(443, "tcp", "HTTPS/Reality")
    shell.run(["ufw", "--force", "enable"], check=False, timeout=30)


def _enable_start(service: str) -> None:
    shell.run(["systemctl", "daemon-reload"], check=False)
    shell.run(["systemctl", "enable", service], check=True)
    shell.run(["systemctl", "restart", service], check=True)


def run_install(argv: "list | None" = None) -> None:
    console.print(f"{C['cyan']}=== VWNpy: установка ==={C['reset']}")
    if not shell.is_root():
        shell.die("Запустите от имени root (sudo bash install.sh)")

    opts = parse_auto_args(argv or [])
    try:
        validate_auto_options(opts)
    except ValueError as exc:
        shell.die(str(exc))

    if not system.preflight():
        shell.die("Проверки окружения провалены.")

    shell.run_task("Системный DNS", system.setup_system_dns)
    shell.run_task("Swap при нехватке RAM", system.setup_swap)

    for pkg in ("curl", "jq", "socat", "qrencode", "python3", "unzip",
                "openssl", "e2fsprogs", "netcat-openbsd", "cron",
                "gnupg2", "lsb-release", "software-properties-common",
                "mmdb-bin"):
        shell.run_task(f"Установка {pkg}", lambda p=pkg: system.install_package(p))

    shell.run_task("Установка nginx 1.30+ (из исходников)",
                   system.install_nginx)

    shell.run_task("Установка Xray-core", system.install_xray)

    from vwn.modules.security import ufw_allow
    shell.run_task("UFW (брандмауэр): правила + включение",
                   lambda: _setup_ufw(ufw_allow))

    if not system.nginx_has_grpc_module():
        shell.die("nginx собран без http_grpc_module. "
                  "XHTTP-gRPC не заработает.")

    # ── Безопасность ──────────────────────────────────────────────────
    if opts.bbr:
        from vwn.modules.security import bbr_enable
        shell.run_task("BBR", bbr_enable)
    if opts.fail2ban:
        from vwn.modules.security import fail2ban_install
        shell.run_task("Fail2Ban", fail2ban_install)
    if opts.jail:
        from vwn.modules.security import webjail_enable
        shell.run_task("WebJail (nginx)", webjail_enable)
    if not opts.ipv6:
        from vwn.modules.security import ipv6_disable
        shell.run_task("Отключение IPv6", ipv6_disable)
    if opts.cpu_guard:
        from vwn.modules.security import cpu_guard_enable
        shell.run_task("CPU Guard", cpu_guard_enable)

    # ── Туннели ───────────────────────────────────────────────────────
    if opts.psiphon_warp:
        from vwn.modules.psiphon import install as install_psiphon
        shell.run_task("Psiphon + WARP", lambda: install_psiphon(opts.psiphon_country, tunnel_mode="warp"))
    elif opts.psiphon:
        from vwn.modules.psiphon import install as install_psiphon
        shell.run_task("Psiphon tunnel", lambda: install_psiphon(opts.psiphon_country))
    if opts.no_warp:
        from vwn.modules.warp import remove as remove_warp
        shell.run_task("Удаление WARP", remove_warp)

    # ── Конфиги + сертификат + юниты + старт ──────────────────────────
    shell.run_task(
        "Генерация конфигов (Reality/WS/XHTTP + loopback-nginx + unit-файлы)",
        lambda: xray.provision_configs(
            opts.domain, opts.stub, opts.reality_dest,
            reality_port=opts.reality_port,
        ),
    )

    shell.run_task(
        f"SSL-сертификат ({opts.cert_method})",
        lambda: cert.provision_cert(opts.domain, opts.cert_method,
                                    opts.cf_email, opts.cf_key),
    )

    # ── Подписки ──────────────────────────────────────────────────────
    server_ip = system.get_server_ip()
    config.vwn_conf_set("SERVER_IP", server_ip)

    from vwn.modules import users
    users.init_users_file()
    user_list = users.list_users()
    if not user_list:
        users.add_user("default")

    shell.run_task("Генерация подписок (sub_map + .txt + .html)",
                   sub.rebuild_all_sub_files)

    shell.run_task("Проверка и перезагрузка nginx", shell.nginx_reload)

    for svc in ("xray-reality", "xray-ws", "xray-xhttp", "nginx"):
        shell.run_task(f"Включение и старт {svc}",
                       lambda s=svc: _enable_start(s))

    # ── Пост-инсталл ──────────────────────────────────────────────
    user_list = users.list_users()
    if user_list:
        u = user_list[0]
        sub_url = f"https://{opts.domain}/sub/{u['label']}_{u['token']}.txt"
        html_url = f"https://{opts.domain}/sub/{u['label']}_{u['token']}.html"
        console.print(f"\n{C['green']}=== Установка завершена ==={C['reset']}")
        console.print(f"\n  Подписка: {C['cyan']}{sub_url}{C['reset']}")
        console.print(f"\n  {C['yellow']}Полезные команды:{C['reset']}")
        console.print(f"    vwn menu          TUI-меню (управление, QR-коды)")
        console.print(f"    vwn qr            QR-код первого конфига в терминале")
        console.print(f"    vwn status        Диагностика сервера")
        console.print(f"\n  Откройте в браузере для сканирования QR:")
        console.print(f"    {C['cyan']}{html_url}{C['reset']}\n")
