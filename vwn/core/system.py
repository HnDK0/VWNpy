"""Системные утилиты: ОС, пакеты, swap, DNS, сеть."""

import os
import platform
import re
import secrets
import zipfile
import shutil
import socket
import subprocess
import sys
import tempfile
import concurrent.futures
import urllib.request

from vwn.core import config, shell


def identify_os() -> str:
    """Вернуть пакетный менеджер: apt / dnf / yum."""
    for mgr in ("apt", "dnf", "yum"):
        if shutil.which(mgr):
            return mgr
    shell.die("Поддерживаются только системы с apt / dnf / yum")


# Единая конфигурация пакетного менеджера (ИСПРАВЛЕНИЕ багов 2.2/2.3:
# раньше удаление/переустановка хардкодили apt и ломались на RHEL).
_PM = {
    "apt": {
        "install": ["apt-get", "-y", "--no-install-recommends",
                    "-o", "Dpkg::Lock::Timeout=120", "install"],
        "remove": ["apt-get", "purge", "-y"],
        "update": ["apt-get", "update", "-o", "Acquire::http::Timeout=60"],
    },
    "dnf": {
        "install": ["dnf", "-y", "install", "--setopt=install_weak_deps=False"],
        "remove": ["dnf", "remove", "-y"],
        "update": ["dnf", "update"],
    },
    "yum": {
        "install": ["yum", "-y", "install", "--setopt=install_weak_deps=False"],
        "remove": ["yum", "remove", "-y"],
        "update": ["yum", "update"],
    },
}


def _pm() -> tuple:
    name = identify_os()
    return name, _PM[name]


def install_package(pkg: str) -> bool:
    name, pm = _pm()
    # Headless-серверы: не лезть в интерактивные debconf-диалоги (kernel upgrade и т.п.)
    env = {"DEBIAN_FRONTEND": "noninteractive"} if name == "apt" else None
    if name == "apt" and _apt_installed(pkg):
        print(f"  {pkg}... SKIP")
        return True
    print(f"  {pkg}... ", end="", flush=True)
    try:
        shell.run(pm["install"] + [pkg], env=env)
        print("OK")
        return True
    except Exception:
        print("RETRY")
        shell.run(pm["update"], check=False, env=env)
        shell.run(pm["install"] + [pkg], env=env)
        print("OK (retry)")
        return True


def _apt_installed(pkg: str) -> bool:
    r = shell.run(["dpkg", "-s", pkg], check=False)
    return r.returncode == 0 and "Status: install ok installed" in (r.stdout or "")


def nginx_has_grpc_module() -> bool:
    """XHTTP-gRPC требует http_grpc_module.

    В nginx 1.30+ grpc включён по умолчанию и не имеет --with- формы, поэтому
    в `nginx -V` его нет; модуль считаем отсутствующим, только если явно
    передан --without-http_grpc_module.
    """
    r = shell.run(["nginx", "-V"], check=False, capture=True)
    out = (r.stderr or "") + (r.stdout or "")  # nginx -V пишет в stderr
    return "--without-http_grpc_module" not in out


# nginx 1.30+ собираем из исходников nginx.org (как в старом коде), чтобы
# гарантированно иметь http_grpc_module, http_v2 и свежий стабильный релиз.
NGINX_TARGET_VER = "1.30.0"
NGINX_SRC_URL = f"https://nginx.org/download/nginx-{NGINX_TARGET_VER}.tar.gz"


def parse_nginx_version(text: str) -> "tuple[int, int, int] | None":
    """Вытянуть (major,minor,patch) из вывода `nginx -v` (пишет в stderr)."""
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def nginx_version() -> "tuple[int, int, int] | None":
    r = shell.run(["nginx", "-v"], check=False, capture=True)
    return parse_nginx_version((r.stderr or "") + (r.stdout or ""))


def version_ge(cur: "tuple[int, int, int] | None",
               target: "tuple[int, int, int]") -> bool:
    return cur is not None and cur >= target


def install_nginx() -> None:
    """Обеспечить nginx >= NGINX_TARGET_VER. Если уже стоит — пропускаем.

    Стратегия (по старому коду): системный nginx из дистро не используем,
    ставим стабильный 1.30+ сборкой из исходников nginx.org.
    """
    if version_ge(nginx_version(), _target_tuple()):
        print(f"info: nginx уже >= {NGINX_TARGET_VER}")
        if not _nginx_has_required_modules():
            print("info: в текущем nginx нет нужных модулей (ssl/v2/stream), пересобираем")
            _build_nginx_from_source()
    else:
        _build_nginx_from_source()
    # unit и главный конфиг пишем всегда (source-сборка кладёт свой дефолтный
    # nginx.conf без include conf.d и с лишним 80-м server-ом)
    _write_nginx_unit()
    _write_nginx_main_conf()
    os.makedirs(config.NGINX_CONF_DIR, exist_ok=True)
    shell.run(["systemctl", "daemon-reload"], check=False)


_NGINX_UNIT = """[Unit]
Description=nginx - high performance web server
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s quit
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


def _write_nginx_unit() -> None:
    """Source-сборка не кладёт systemd-юнит — создаём стандартный nginx.service."""
    path = "/etc/systemd/system/nginx.service"
    if os.path.isfile(path):
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_NGINX_UNIT)


def _write_nginx_main_conf() -> None:
    """Заменяем дефолтный nginx.conf от source-сборки на наш (с include conf.d)."""
    tpl = os.path.join(os.path.dirname(__file__), "..", "data", "nginx_main.conf")
    with open(tpl, "r", encoding="utf-8") as fh:
        content = fh.read()
    with open(config.NGINX_MAIN_CONF, "w", encoding="utf-8") as fh:
        fh.write(content)


def _target_tuple() -> "tuple[int, int, int]":
    a, b, c = NGINX_TARGET_VER.split(".")
    return int(a), int(b), int(c)


# Явно включаемые модули, без которых наш конфиг не поднимется. grpc в 1.30+
# включён по умолчанию и в `nginx -V` не фигурирует — его не проверяем.
_REQUIRED_MODULES = ("--with-http_ssl_module",
                     "--with-http_v2_module",
                     "--with-stream")


def _nginx_has_required_modules() -> bool:
    r = shell.run(["nginx", "-V"], check=False, capture=True)
    out = (r.stderr or "") + (r.stdout or "")
    return all(m in out for m in _REQUIRED_MODULES)


def _build_nginx_from_source() -> None:
    """Собрать nginx-${NGINX_TARGET_VER} из исходников (без shell=True).

    Набор модулей сокращён до реально нужных нашему конфигу (ssl/v2/realip/
    grpc/gzip_static/stub_status/stream). Флаги фильтруются по `./configure
    --help`: в 1.30+ часть модулей (grpc, возможно ssl/v2) включена по
    умолчанию и не имеет --with- формы — передавать их нельзя.
    """
    print(f"Сборка nginx {NGINX_TARGET_VER} из исходников...")
    install_package("build-essential")
    for dep in ("libpcre2-dev", "zlib1g-dev", "libssl-dev"):
        install_package(dep)

    build_dir = tempfile.mkdtemp(prefix="nginx-build-")
    tarball = os.path.join(build_dir, "nginx.tar.gz")
    try:
        shell.run(["curl", "-fsSL", NGINX_SRC_URL, "-o", tarball], check=True)
        import tarfile
        with tarfile.open(tarball) as tf:
            tf.extractall(build_dir)  # плоская структура: nginx-VER/*
        src_dir = os.path.join(build_dir, f"nginx-{NGINX_TARGET_VER}")

        # какие --with-* флаги валидны для этой версии (default-on модули —
        # только --without- форма, их пропускаем, они и так в сборке)
        help_out = subprocess.run(["./configure", "--help"], cwd=src_dir,
                                  capture_output=True, text=True).stdout
        valid = set(re.findall(r"--(?:with|without)-[A-Za-z0-9_=]+", help_out))
        keep = lambda flag: flag in valid

        base = [
            "--prefix=/etc/nginx", "--sbin-path=/usr/sbin/nginx",
            "--modules-path=/usr/lib/nginx/modules",
            "--conf-path=/etc/nginx/nginx.conf",
            "--error-log-path=/var/log/nginx/error.log",
            "--http-log-path=/var/log/nginx/access.log",
            "--pid-path=/run/nginx.pid", "--lock-path=/run/nginx.lock",
            "--http-client-body-temp-path=/var/cache/nginx/client_temp",
            "--http-proxy-temp-path=/var/cache/nginx/proxy_temp",
            "--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp",
            "--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp",
            "--http-scgi-temp-path=/var/cache/nginx/scgi_temp",
            "--user=www-data", "--group=www-data",
            "--with-compat", "--with-threads",
        ]
        # Только нужное; grpc в 1.30+ — по умолчанию (не имеет --with- формы)
        modules = [
            "--with-http_ssl_module", "--with-http_v2_module",
            "--with-http_realip_module", "--with-http_gzip_static_module",
            "--with-http_stub_status_module",
            "--with-stream", "--with-stream_ssl_module",
            "--with-stream_realip_module", "--with-stream_ssl_preread_module",
        ]
        configure_args = base + [m for m in modules if keep(m)]
        print("configure flags:", " ".join(configure_args))
        subprocess.run(["./configure", *configure_args], cwd=src_dir, check=True)
        subprocess.run(["make", "-j" + str(os.cpu_count() or 1)],
                       cwd=src_dir, check=True)
        subprocess.run(["make", "install"], cwd=src_dir, check=True)
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)

    for d in ("client_temp", "proxy_temp", "fastcgi_temp",
              "uwsgi_temp", "scgi_temp"):
        p = f"/var/cache/nginx/{d}"
        os.makedirs(p, exist_ok=True)
    shell.run(["chown", "-R", "www-data:www-data", "/var/cache/nginx"],
              check=False)

    if not version_ge(nginx_version(), _target_tuple()):
        shell.die(f"nginx не собрался в версию >= {NGINX_TARGET_VER}")


# ── Установка Xray-core (бинарь + geo-базы) ────────────────────────────────
def _xray_arch_tag(arch: str) -> str:
    return {
        "x86_64": "64", "aarch64": "arm64-v8a", "armv7l": "arm32-v7a",
    }.get(arch, "")


def _parse_xray_version(text: str) -> str:
    try: return __import__("json").loads(text).get("tag_name", "")
    except: return ""


def _create_xray_user() -> None:
    if shell.run(["id", "xray"], check=False).returncode == 0:
        return
    shell.run(["useradd", "-r", "-s", "/usr/sbin/nologin",
               "-d", config.XRAY_DIR, "xray"], check=False)


MMDB_FILE = "/usr/local/share/GeoLite2-Country.mmdb"

def _install_geo_databases() -> None:
    """Скачать geoip.dat/geosite.dat + GeoLite2-Country.mmdb."""
    os.makedirs("/usr/local/share/xray", exist_ok=True)
    base = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
    for dat in ("geoip.dat", "geosite.dat"):
        shell.run(["curl", "-fsSL", "--connect-timeout", "15", "--retry", "2",
                   f"{base}/{dat}", "-o", f"/usr/local/share/xray/{dat}"],
                  check=False)
    if not os.path.isfile(MMDB_FILE):
        os.makedirs(os.path.dirname(MMDB_FILE), exist_ok=True)
        shell.run(["curl", "-fsSL", "--connect-timeout", "15", "--retry", "2",
                   "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
                   "-o", MMDB_FILE], check=False)


def install_xray() -> None:
    """Поставить бинарь Xray-core + geo-базы (как fallback в оригинале)."""
    if not shutil.which("xray"):
        _create_xray_user()
        tag = _xray_arch_tag(platform.machine())
        if not tag:
            shell.die(f"Неподдерживаемая архитектура: {platform.machine()}")
        tmp = tempfile.mkdtemp(prefix="xray-")
        try:
            zip_url = (f"https://github.com/XTLS/Xray-core/releases/latest/"
                       f"download/Xray-linux-{tag}.zip")
            zip_path = os.path.join(tmp, "xray.zip")
            shell.run(["curl", "-fsSL", "--connect-timeout", "30", "--retry", "2",
                       zip_url, "-o", zip_path], check=True)
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(tmp)
            bin_src = os.path.join(tmp, "xray")
            if not (os.path.isfile(bin_src) and os.path.getsize(bin_src) > 0):
                shell.die("не удалось извлечь бинарь xray")
            os.makedirs(os.path.dirname(config.XRAY_BIN), exist_ok=True)
            shutil.copy(bin_src, config.XRAY_BIN)
            os.chmod(config.XRAY_BIN, 0o755)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if not shutil.which("xray"):
            shell.die("xray не установился")
    else:
        print("info: xray уже установлен, пропускаем бинарь")
    # geo-базы качаем всегда (idempotent; нужны для routing)
    _install_geo_databases()
    # лог-директория для xray (конфиги пишут в /var/log/xray/*.log)
    os.makedirs("/var/log/xray", exist_ok=True)
    for _f in ("reality-error.log", "error.log"):
        _p = os.path.join("/var/log/xray", _f)
        if not os.path.exists(_p):
            open(_p, "a").close()
    shell.run(["chown", "-R", "xray:xray", "/var/log/xray"], check=False)


def uninstall_package(pkg: str) -> None:
    """Единое удаление через PACKAGE_MANAGEMENT_REMOVE (без хардкода apt)."""
    _, pm = _pm()
    shell.run(pm["remove"] + [pkg], check=False)


def setup_swap() -> None:
    """Создать swap-файл, если его нет (размер зависит от RAM)."""
    swap_total = _mem_field("Swap")
    if swap_total and int(swap_total) > 256:
        print("info: swap уже есть, пропускаем")
        return
    ram = int(_mem_field("Mem") or 0)
    swap_mb = 1024 if ram <= 1024 else 2048 if ram <= 2048 else 1024
    print(f"Создаю swap {swap_mb} МБ...")
    swapfile = "/swapfile"
    if not (subprocess.run(["fallocate", "-l", f"{swap_mb}M", swapfile], check=False).returncode == 0 or
            subprocess.run(["dd", "if=/dev/zero", f"of={swapfile}", "bs=1M",
                            f"count={swap_mb}", "status=none"], check=False).returncode == 0):
        print("warn: не удалось создать swap")
        return
    os.chmod(swapfile, 0o600)
    shell.run(["mkswap", swapfile], check=False)
    shell.run(["swapon", swapfile], check=False)
    if not _file_contains("/etc/fstab", swapfile):
        with open("/etc/fstab", "a", encoding="utf-8") as fh:
            fh.write(f"{swapfile} none swap sw 0 0\n")
    shell.run(["sysctl", "-w", "vm.swappiness=10"], check=False)
    if not _file_contains("/etc/sysctl.conf", "vm.swappiness"):
        with open("/etc/sysctl.conf", "a", encoding="utf-8") as fh:
            fh.write("vm.swappiness=10\n")


def _mem_field(kind: str) -> "str | None":
    out = shell.run(["free", "-m"], check=False, capture=True).stdout or ""
    for line in out.splitlines():
        if line.startswith(kind + ":"):
            return line.split()[1]
    return None


def preflight() -> bool:
    """Базовые проверки окружения перед установкой."""
    identify_os()  # shell.die внутри, если менеджер пакетов неподдерживаемый
    import platform
    arch = platform.machine()
    if arch not in ("x86_64", "aarch64", "armv7l"):
        print(f"warn: непроверенная архитектура {arch}")
    if not shell.is_root():
        shell.die("Установка требует прав root (sudo)")
    return True


_DNS_CANDIDATES = [
    "1.1.1.1",        # Cloudflare — без логов
    "1.1.1.2",        # Cloudflare (malware block)
    "9.9.9.9",        # Quad9 — без логов, блокирует малварь
    "9.9.9.10",       # Quad9 (без блок-листа)
    "94.140.14.14",   # AdGuard DNS — без логов
    "76.76.2.2",      # Control D — без логов
    "76.76.19.19",    # Alternate DNS — без логов
]


def _test_dns_latency(dns: str, timeout: int = 3) -> float:
    """Измерить задержку до DNS-сервера (ms). 9999 если недоступен."""
    r = shell.run(["ping", "-c", "1", "-W", str(timeout), dns],
                  capture=True, check=False, timeout=timeout + 2)
    if r.returncode != 0:
        return 9999
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", r.stdout or "")
    return float(m.group(1)) if m else 9999


def _pick_best_dns() -> list[str]:
    """Протестировать всех кандидатов, вернуть [primary, fallback] по скорости."""
    results = [(dns, _test_dns_latency(dns)) for dns in _DNS_CANDIDATES]
    results.sort(key=lambda x: x[1])
    best = [dns for dns, ms in results if ms < 9999]
    if len(best) < 2:
        return ["1.1.1.1", "9.9.9.9"]
    return best[:2]


def setup_system_dns() -> None:
    """Настроить системный DNS (приватные, без логов), блокировать утечку через DNS хостера."""
    marker = "/usr/local/etc/xray/.dns_configured"
    if os.path.isfile(marker):
        return
    primary, fallback = _pick_best_dns()
    if shutil.which("systemd-resolve") or os.path.isfile("/run/systemd/resolve/stub-resolv.conf") \
            or shell.run(["systemctl", "is-active", "--quiet", "systemd-resolved"], check=False).returncode == 0:
        os.makedirs("/etc/systemd/resolved.conf.d", exist_ok=True)
        with open("/etc/systemd/resolved.conf.d/99-vwn-dns.conf", "w", encoding="utf-8") as fh:
            fh.write(
                "[Resolve]\n"
                f"DNS={primary}\n"
                f"FallbackDNS={fallback}\n"
                "Domains=~.\n"
                "DNSSEC=no\n"
                "Cache=yes\n"
                "DNSOverTLS=no\n"
            )
        shell.run(["systemctl", "restart", "systemd-resolved"], check=False)
    else:
        resolv = "/etc/resolv.conf"
        if os.path.islink(resolv):
            os.remove(resolv)
        with open(resolv, "w", encoding="utf-8") as fh:
            fh.write(
                "# VWN DNS: утечка через DNS хостера заблокирована\n"
                f"nameserver {primary}\n"
                f"nameserver {fallback}\n"
                "options edns0 trust-ad timeout:1 attempts:1\n"
            )
        os.chmod(resolv, 0o644)
        shell.run(["chattr", "+i", resolv], check=False)
    os.makedirs(os.path.dirname(marker), exist_ok=True)
    open(marker, "a").close()


def get_server_ip() -> str:
    """Определить внешний IPv4 (не приватный)."""
    urls = ["https://api.ipify.org", "https://ipv4.icanhazip.com",
            "https://checkip.amazonaws.com"]

    def fetch(u: str) -> "str | None":
        try:
            with urllib.request.urlopen(u, timeout=3) as r:
                return r.read().decode().strip()
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor() as ex:
        for ip in ex.map(fetch, urls):
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) \
                    and not re.match(r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)", ip):
                return ip
    # Фоллбэк: локальный маршрут
    try:
        return subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, check=False
        ).stdout.split("src")[-1].split()[0].strip() or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def find_free_port(start: int = 20000, end: int = 20999) -> int:
    """Найти свободный TCP-порт, пробуя забиндить (без зависимости от ss)."""
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise ValueError("Свободный порт не найден")


def generate_random_path() -> str:
    """Случайный WS/XHTTP путь: /v2/api/<32 hex>."""
    return "/v2/api/" + secrets.token_hex(16)


def _file_contains(path: str, needle: str) -> bool:
    if not os.path.isfile(path):
        return False
    with open(path, encoding="utf-8") as fh:
        return needle in fh.read()


if __name__ == "__main__":
    assert generate_random_path().startswith("/v2/api/")
    assert 50001 == find_free_port(50001, 50001)
    print("system: OK")
