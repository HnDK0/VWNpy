"""WARP tunnel — 3 метода: native (wgcf→Xray WG), amnezia (kernel only), warp-svc.

Каждый метод получает уникальный тег outbound в конфиге Xray:
  native   → "warp-native"
  amnezia  → "warp-amnezia"
  warp-svc → "warp-svc"

AmneziaWG требует linux-headers для текущего ядра. Если headers
недоступны — ошибка с рекомендацией использовать native.
"""

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from vwn.core import config, shell

WGCF_BIN = "/usr/local/bin/wgcf"
WGCF_WORKDIR = "/etc/wgcf"
WARP_KEYS_FILE = "/etc/vwn/warp-keys.env"
WARP_SERVER_PUBKEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

AWG_SERVICE = "amnezia-warp"
AWG_IFACE = "warp0"
AWG_CONF_DIR = "/etc/amnezia"
AWG_CONF = f"{AWG_CONF_DIR}/{AWG_IFACE}.conf"
AWG_SERVICE_FILE = f"/etc/systemd/system/{AWG_SERVICE}.service"
AWG_GO_BIN = "/usr/local/bin/amneziawg-go"
AWG_QUICK_BIN = "/usr/local/bin/awg-quick"

WG_QUICK_BIN = "/usr/bin/wg-quick"

WARP_TAG = "warp"
WARP_TAGS = {
    "native": "warp-native",
    "amnezia": "warp-amnezia",
    "warp-svc": "warp-svc",
}
SOCKS_TAG = "socks-warp"

AWG_GO_URL = "https://github.com/HnDK0/amneziawg-go-build/releases/latest/download/amneziawg-go-{arch}"

MODE_KERNEL = "kernel"


def _tag_for_method(method: str) -> str:
    return WARP_TAGS.get(method, "warp-svc")


def _is_warp_tag(tag: str) -> bool:
    return tag.startswith("warp-") or tag == WARP_TAG


def _is_warp_routing(rule: dict) -> bool:
    return _is_warp_tag(rule.get("outboundTag", ""))


def _xray_config_paths() -> list[str]:
    paths = []
    for p in (os.path.join(config.XRAY_DIR, "config.json"),
              os.path.join(config.XRAY_DIR, "xhttp.json"),
              os.path.join(config.XRAY_DIR, "xray-reality.json")):
        if os.path.exists(p):
            paths.append(p)
    return paths


def _remove_outbound(method: str = "") -> None:
    tag = _tag_for_method(method) if method else ""
    for path in _xray_config_paths():
        with open(path) as f:
            cfg = json.load(f)
        if tag:
            cfg["outbounds"] = [o for o in cfg.get("outbounds", [])
                               if o.get("tag") != tag]
        else:
            cfg["outbounds"] = [o for o in cfg.get("outbounds", [])
                               if not _is_warp_tag(o.get("tag", ""))]
        cfg["inbounds"] = [i for i in cfg.get("inbounds", [])
                          if i.get("tag") != SOCKS_TAG]
        cfg["routing"]["rules"] = [
            r for r in cfg.get("routing", {}).get("rules", [])
            if not _is_warp_routing(r)
        ]
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)


def _add_routing_rule_if_missing(tag: str, mode: str = "Global") -> None:
    from vwn.modules.tunnels import insert_before_catchall
    for path in _xray_config_paths():
        with open(path) as f:
            cfg = json.load(f)
        rules = cfg.setdefault("routing", {}).setdefault("rules", [])
        # Удаляем только warp routing rules БЕЗ inboundTag
        # (socks-warp rules с inboundTag не трогаем)
        rules[:] = [r for r in rules
                    if not (_is_warp_routing(r) and not r.get("inboundTag"))]
        if mode == "Global":
            insert_before_catchall(rules, {"type": "field", "port": "0-65535", "outboundTag": tag})
        elif mode == "Split":
            from vwn.modules._domains import list_domains
            domains = list_domains(tag)
            if not domains:
                domains = ["whoer.net"]
            domains_json = [f"domain:{d}" for d in domains]
            insert_before_catchall(rules, {"type": "field", "domain": domains_json, "outboundTag": tag})
        cfg["routing"]["rules"] = rules
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)


# ── Method A: native (wgcf → Xray WireGuard) ──────────────────────

def _install_wgcf() -> None:
    if os.path.exists(WGCF_BIN):
        return
    arch = (shell.run(["uname", "-m"], capture=True).stdout or "").strip()
    wgcf_arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch)
    if not wgcf_arch:
        raise RuntimeError(f"Unsupported arch: {arch}")
    r = shell.run(["curl", "-fL",
        "https://api.github.com/repos/ViRb3/wgcf/releases/latest"],
        capture=True, timeout=15)
    tag = re.search(r'"tag_name"\s*:\s*"([^"]+)"', r.stdout or "")
    if not tag:
        raise RuntimeError("Failed to get wgcf version")
    latest_tag = tag.group(1)
    version = latest_tag.lstrip("v")
    url = (f"https://github.com/ViRb3/wgcf/releases/download/"
           f"{latest_tag}/wgcf_{version}_linux_{wgcf_arch}")
    shell.run(["curl", "-fL", "-o", WGCF_BIN, url], timeout=60)
    os.chmod(WGCF_BIN, 0o755)


def _generate_keys() -> dict[str, str]:
    if not os.path.exists(WGCF_BIN):
        _install_wgcf()
    keys = {}
    if os.path.exists(WARP_KEYS_FILE):
        with open(WARP_KEYS_FILE) as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    keys[k] = v
        if keys.get("WARP_PRIVATE_KEY"):
            return keys
    os.makedirs(WGCF_WORKDIR, exist_ok=True)
    cwd = os.getcwd()
    os.chdir(WGCF_WORKDIR)
    try:
        for f in ("wgcf-account.toml", "wgcf-profile.conf"):
            (Path(WGCF_WORKDIR) / f).unlink(missing_ok=True)
        for attempt in range(3):
            r = shell.run([WGCF_BIN, "register", "--accept-tos"],
                         timeout=30, check=False)
            if r.returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError("wgcf register failed after 3 attempts")
        shell.run([WGCF_BIN, "generate"], timeout=30)
        prof = Path(WGCF_WORKDIR) / "wgcf-profile.conf"
        if not prof.exists():
            raise RuntimeError("wgcf-profile.conf not created")
        text = prof.read_text()
        private_key = re.search(r"^PrivateKey\s*=\s*(\S+)", text, re.M)
        addresses = re.findall(r"^Address\s*=\s*(\S+)", text, re.M)
        ipv4 = ipv6 = ""
        for a in addresses:
            a = a.split("/")[0]
            if ":" in a:
                ipv6 = a
            else:
                ipv4 = a
        pk = private_key.group(1) if private_key else ""
        keys = {"WARP_PRIVATE_KEY": pk, "WARP_IPV4": ipv4 or "172.16.0.2", "WARP_IPV6": ipv6}
        os.makedirs(os.path.dirname(WARP_KEYS_FILE), exist_ok=True)
        with open(WARP_KEYS_FILE, "w") as f:
            for k, v in keys.items():
                f.write(f"{k}={v}\n")
        os.chmod(WARP_KEYS_FILE, 0o600)
        return keys
    finally:
        os.chdir(cwd)


def _pick_endpoint(prefer_port: int = 2408) -> str:
    ranges = ["162.159.192", "162.159.195", "188.114.96",
              "188.114.97", "188.114.98"]
    suffixes = [1, 5, 10]
    candidates = [f"{r}.{s}" for r in ranges for s in suffixes]
    results: dict[str, float] = {}
    for ip in candidates:
        r = shell.run(["ping", "-c", "1", "-W", "1", ip],
                      check=False, capture=True, timeout=5)
        m = re.search(r"time=([0-9.]+)", r.stdout or "")
        if m:
            results[ip] = float(m.group(1))
    sorted_ips = sorted(results, key=results.get)[:3]
    if not sorted_ips:
        return f"162.159.192.1:{prefer_port}"
    ports = [2408, 500, 4500, 1701] if prefer_port == 2408 else [500, 2408, 4500, 1701]
    for ip in sorted_ips:
        for port in ports:
            r = shell.run(["nc", "-zu", "-w", "2", ip, str(port)],
                          check=False, timeout=5)
            if r.returncode == 0:
                return f"{ip}:{port}"
    return f"{sorted_ips[0]}:{prefer_port}"


def _apply_socks_inbound(path: str, port: int = 10808, warp_tag: str = "") -> None:
    """Добавить SOCKS inbound + routing rule в конфиг Xray."""
    WARP_SOCKS_PORTS = {10808, 10809}
    with open(path) as f:
        cfg = json.load(f)
    socks_inbound = {
        "listen": "127.0.0.1", "port": port,
        "protocol": "socks", "settings": {"udp": True},
        "tag": SOCKS_TAG,
    }
    cfg.setdefault("inbounds", [])
    cfg["inbounds"] = [i for i in cfg["inbounds"]
                       if i.get("tag") != SOCKS_TAG
                       or i.get("port") not in WARP_SOCKS_PORTS]
    cfg["inbounds"].append(socks_inbound)
    rules = cfg.setdefault("routing", {}).setdefault("rules", [])
    rules = [r for r in rules if r.get("inboundTag") != [SOCKS_TAG]]
    rules.insert(0, {"type": "field", "inboundTag": [SOCKS_TAG], "outboundTag": warp_tag})
    cfg["routing"]["rules"] = rules
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def _apply_native_outbound(private_key: str, ipv4: str, endpoint: str) -> None:
    tag = _tag_for_method("native")
    outbound = {
        "tag": tag, "protocol": "wireguard",
        "settings": {
            "secretKey": private_key,
            "address": [f"{ipv4}/32"],
            "peers": [{"publicKey": WARP_SERVER_PUBKEY, "endpoint": endpoint}],
            "mtu": 1280,
        },
    }
    paths = _xray_config_paths()
    for path in paths:
        with open(path) as f:
            cfg = json.load(f)
        cfg.setdefault("outbounds", [])
        cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") != tag]
        cfg["outbounds"].append(outbound)
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    if paths:
        _apply_socks_inbound(paths[0], 10808, tag)


def install_native() -> None:
    print("  wgcf...")
    _install_wgcf()
    print("  WARP keys...")
    keys = _generate_keys()
    if not keys.get("WARP_PRIVATE_KEY"):
        raise RuntimeError("Failed to get WARP private key")
    print("  Endpoint...")
    endpoint = _pick_endpoint()
    print(f"  {endpoint}")
    _apply_native_outbound(keys["WARP_PRIVATE_KEY"], keys["WARP_IPV4"], endpoint)
    config.vwn_conf_set("WARP_METHOD", "native")
    config.vwn_conf_set("WARP_ENDPOINT", endpoint)
    shell.run(["systemctl", "restart", "xray-reality", "xray-ws", "xray-xhttp"],
              check=False)
    print("  WARP (native) installed")


def remove_native() -> None:
    _remove_outbound("native")
    for f in (WARP_KEYS_FILE, WGCF_BIN):
        if os.path.exists(f):
            os.remove(f)
    if os.path.exists(WGCF_WORKDIR):
        shutil.rmtree(WGCF_WORKDIR, ignore_errors=True)


# ── Method B: AmneziaWG ────────────────────────────────────────────

def _kernel_module_available() -> bool:
    """Проверить, загружен ли amneziawg. Если нет — попробовать загрузить."""
    r = shell.run(["lsmod"], capture=True, check=False)
    if r.returncode == 0 and "amneziawg" in (r.stdout or ""):
        return True
    # Пробуем загрузить
    shell.run(["modprobe", "amneziawg"], check=False)
    r2 = shell.run(["lsmod"], capture=True, check=False)
    return r2.returncode == 0 and "amneziawg" in (r2.stdout or "")


def _add_ppa_and_install(packages: list[str]) -> bool:
    """Добавить PPA amnezia/ppa и установить пакеты. Вернёт True если успешно."""
    if shell.run(["add-apt-repository", "-y", "ppa:amnezia/ppa"],
                  timeout=60, check=False).returncode != 0:
        return False
    shell.run(["apt-get", "update"], timeout=60, check=False)
    r = shell.run(["apt-get", "install", "-y"] + packages, timeout=120, check=False)
    return r.returncode == 0


def _get_running_kernel() -> str:
    r = shell.run(["uname", "-r"], capture=True, check=True)
    return (r.stdout or "").strip()


def _cleanup_broken_dkms() -> None:
    """Очистить сломанное dpkg-состояние amneziawg."""
    shell.run(["dpkg", "--purge", "--force-remove-reinstreq",
               "amneziawg", "amneziawg-dkms"], check=False, timeout=30)
    shell.run(["apt-get", "-f", "install", "-y"], check=False, timeout=30)


def _remove_old_kernel_headers(running: str) -> None:
    """Удалить headers старых ядер чтобы DKMS не пытался для них собирать."""
    r = shell.run(["dpkg", "-l"], capture=True, check=False)
    if r.returncode != 0:
        return
    pkgs = []
    base = running.rsplit("-", 1)[0] if "-" in running else running
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[1]
        if name.startswith(f"linux-headers-{base}"):
            continue
        if name.startswith("linux-headers-"):
            pkgs.append(name)
    if pkgs:
        print(f"  Удаляю headers старых ядер: {', '.join(pkgs)}...")
        shell.run(["apt-get", "remove", "-y"] + pkgs, timeout=60, check=False)


def _ensure_kernel_env() -> str:
    """Подготовить окружение: почистить dpkg, убрать старые headers, поставить текущие."""
    _cleanup_broken_dkms()
    running = _get_running_kernel()
    _remove_old_kernel_headers(running)
    check = shell.run(["dpkg", "-s", f"linux-headers-{running}"],
                      check=False, capture=True)
    if check.returncode == 0 and "Status: install ok installed" in (check.stdout or ""):
        return running
    print(f"  Устанавливаю linux-headers-{running}...")
    inst = shell.run(["apt-get", "install", "-y", f"linux-headers-{running}"],
                     timeout=120, check=False)
    if inst.returncode == 0:
        return running
    raise RuntimeError(
        f"linux-headers-{running} недоступны. "
        f"AmneziaWG требует headers для текущего ядра. "
        f"Установите вручную или используйте метод native."
    )


def _dkms_build_for_running(version: str, running: str) -> bool:
    """Ручная сборка DKMS для конкретного ядра."""
    print(f"  DKMS: собираю модуль для {running}...")
    shell.run(["dkms", "build", "-m", "amneziawg", "-v", version,
                "-k", running], timeout=120, check=False)
    shell.run(["dkms", "install", "-m", "amneziawg", "-v", version,
                "-k", running], timeout=60, check=False)
    return _kernel_module_available()


def _install_amneziawg() -> str:
    """Установить AmneziaWG (kernel mode). Вернёт MODE_KERNEL."""
    if _kernel_module_available():
        if not shutil.which("awg-quick") or not shutil.which("awg"):
            shell.run(["apt-get", "install", "-y", "amneziawg-tools"],
                      timeout=60, check=False)
        if not shutil.which("resolvconf"):
            shell.run(["apt-get", "install", "-y", "openresolv"],
                      timeout=60, check=False)
        config.vwn_conf_set("AWG_MODE", MODE_KERNEL)
        return MODE_KERNEL

    running = _ensure_kernel_env()

    print("  Устанавливаю AmneziaWG через PPA...")
    if not _add_ppa_and_install(["amneziawg"]):
        _cleanup_broken_dkms()
        raise RuntimeError("Не удалось установить amneziawg из PPA")

    if _kernel_module_available():
        if not shutil.which("resolvconf"):
            shell.run(["apt-get", "install", "-y", "openresolv"],
                      timeout=60, check=False)
        config.vwn_conf_set("AWG_MODE", MODE_KERNEL)
        return MODE_KERNEL

    r = shell.run(["dkms", "status"], capture=True, check=False)
    m = re.search(r"amneziawg[/ ](\S+):", r.stdout or "")
    if m:
        if _dkms_build_for_running(m.group(1), running):
            if not shutil.which("resolvconf"):
                shell.run(["apt-get", "install", "-y", "openresolv"],
                          timeout=60, check=False)
            config.vwn_conf_set("AWG_MODE", MODE_KERNEL)
            return MODE_KERNEL

    _cleanup_broken_dkms()
    raise RuntimeError(
        f"AmneziaWG kernel module не загружается. "
        f"Проверьте: dkms status | grep amneziawg. "
        f"Возможно нужен ребут."
    )



# ponytail: I1/I2 генерики для AmneziaWG init пакетов — если реальный
# хендшейк с WARP потребует других значений, заменить константы.
_I1_VAL = "<b 0xc0><b 0x00000001><b 0x08><r 8><b 0x0000><b 0x4400><b 0x00><r 200>"
_I2_VAL = "<r 16><c><t><r 32>"


def _build_awg_conf(private_key: str, ipv4: str, endpoint: str,
                    mode: str = MODE_KERNEL) -> None:
    host, port = endpoint.split(":")
    obfuscation = ""
    if mode == MODE_KERNEL:
        obfuscation = f"""Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = {_I1_VAL}
I2 = {_I2_VAL}
"""
    conf = f"""[Interface]
PrivateKey = {private_key}
Address = {ipv4}/32
DNS = 1.1.1.1
MTU = 1280
Table = off
{obfuscation}
[Peer]
PublicKey = {WARP_SERVER_PUBKEY}
Endpoint = {host}:{port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    os.makedirs(os.path.dirname(AWG_CONF), exist_ok=True)
    with open(AWG_CONF, "w") as f:
        f.write(conf)
    os.chmod(AWG_CONF, 0o600)


def _create_awg_systemd() -> None:
    unit = f"""[Unit]
Description=AmneziaWG WARP tunnel (warp0)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={AWG_QUICK_BIN} up {AWG_CONF}
ExecStop={AWG_QUICK_BIN} down {AWG_CONF}

[Install]
WantedBy=multi-user.target
"""
    with open(AWG_SERVICE_FILE, "w") as f:
        f.write(unit)
    shell.run(["systemctl", "daemon-reload"], check=False)


def _apply_amnezia_outbound() -> None:
    tag = _tag_for_method("amnezia")
    outbound = {
        "tag": tag, "protocol": "freedom",
        "settings": {},
        "streamSettings": {"sockopt": {"interface": AWG_IFACE}},
    }
    paths = _xray_config_paths()
    for path in paths:
        with open(path) as f:
            cfg = json.load(f)
        cfg.setdefault("outbounds", [])
        cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") != tag]
        cfg["outbounds"].append(outbound)
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    if paths:
        _apply_socks_inbound(paths[0], 10809, tag)


def _download_amneziawg_go() -> None:
    """Скачать amneziawg-go (нужен для systemd unit в kernel mode)."""
    if os.path.exists(AWG_GO_BIN):
        return
    arch = (shell.run(["uname", "-m"], capture=True).stdout or "").strip()
    mapped = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, "amd64")
    url = AWG_GO_URL.format(arch=mapped)
    shell.run(["curl", "-fL", "-o", AWG_GO_BIN, url], timeout=60)
    os.chmod(AWG_GO_BIN, 0o755)


def install_amnezia() -> None:
    print("  WARP keys...")
    keys = _generate_keys()
    if not keys.get("WARP_PRIVATE_KEY"):
        raise RuntimeError("Failed to get WARP private key")
    print("  Endpoint...")
    endpoint = _pick_endpoint(500)
    print(f"  {endpoint}")
    print("  AmneziaWG...")
    mode = _install_amneziawg()
    print(f"  Mode: kernel module")
    _build_awg_conf(keys["WARP_PRIVATE_KEY"], keys["WARP_IPV4"], endpoint, mode)
    _create_awg_systemd()
    print("  Starting amnezia-warp...")
    r = shell.run(["systemctl", "enable", "--now", AWG_SERVICE], check=False, timeout=30)
    time.sleep(5)
    if not shell.service_active(AWG_SERVICE):
        j = shell.run(["journalctl", "-u", AWG_SERVICE, "-n", "10", "--no-pager"],
                      capture=True, check=False)
        raise RuntimeError(f"{AWG_SERVICE} не запустился:\n{j.stdout or j.stderr}")
    # ponytail: проверяем что интерфейс действительно поднят
    if not _check_tunnel_alive("amnezia"):
        raise RuntimeError(f"Интерфейс {AWG_IFACE} не появился после запуска {AWG_SERVICE}")
    _apply_amnezia_outbound()
    config.vwn_conf_set("WARP_METHOD", "amnezia")
    config.vwn_conf_set("WARP_ENDPOINT", endpoint)
    shell.run(["systemctl", "restart", "xray-reality", "xray-ws", "xray-xhttp"],
              check=False)
    print("  WARP (AmneziaWG) installed")


def remove_amnezia() -> None:
    shell.run(["systemctl", "stop", AWG_SERVICE], check=False)
    shell.run(["systemctl", "disable", AWG_SERVICE], check=False)
    for f in (AWG_SERVICE_FILE, AWG_CONF):
        if os.path.exists(f):
            os.remove(f)
    for b in (AWG_GO_BIN, "/usr/local/bin/wireguard-go"):
        if os.path.exists(b):
            os.remove(b)
    shell.run(["systemctl", "daemon-reload"], check=False)
    _remove_outbound("amnezia")
    config.vwn_conf_del("AWG_MODE")


# ── Method C: warp-svc (legacy) ────────────────────────────────────

def _install_warp_svc() -> None:
    if shutil.which("warp-cli"):
        return
    shell.run(["apt-get", "update"], timeout=60, check=False)
    shell.run(["curl", "-fL",
        "https://pkg.cloudflareclient.com/pubkey.gpg", "-o",
        "/tmp/cloudflare-warp.gpg.asc"], timeout=30, check=False)
    shell.run(["gpg", "--yes", "--dearmor", "-o",
        "/usr/share/keyrings/cloudflare-warp.gpg",
        "/tmp/cloudflare-warp.gpg.asc"], timeout=10, check=False)
    os.makedirs("/etc/apt/sources.list.d", exist_ok=True)
    lsb = (shell.run(["lsb_release", "-cs"], capture=True, check=False).stdout or "jammy").strip()
    with open("/etc/apt/sources.list.d/cloudflare-client.list", "w") as f:
        f.write(f"deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp.gpg] "
                f"https://pkg.cloudflareclient.com/ {lsb} main\n")
    shell.run(["apt-get", "update"], timeout=60, check=False)
    r = shell.run(["apt-get", "install", "-y", "cloudflare-warp"], timeout=120, check=False)
    if r.returncode != 0 or not shutil.which("warp-cli"):
        raise RuntimeError("Failed to install cloudflare-warp package")
    # stop after install — apt may auto-start and hijack routing
    shell.run(["systemctl", "stop", "warp-svc"], check=False)


def _run_warp_register() -> subprocess.CompletedProcess:
    return subprocess.run(
        ["script", "-q", "-c", "warp-cli registration new", "/dev/null"],
        input="y\n", capture_output=True, text=True, timeout=60)


def _config_warp_svc() -> None:
    # start daemon WITHOUT auto-connect (prevent full-tunnel hijack)
    shell.run(["systemctl", "start", "warp-svc"], check=False)
    time.sleep(3)
    # set proxy mode BEFORE registration
    shell.run(["warp-cli", "mode", "proxy"], check=False)
    shell.run(["warp-cli", "proxy", "port", "40000"], check=False)
    r = _run_warp_register()
    if r.returncode != 0:
        shell.run(["warp-cli", "registration", "delete"], check=False)
        time.sleep(2)
        for _ in range(3):
            r = _run_warp_register()
            if r.returncode == 0:
                break
            time.sleep(3)
    shell.run(["warp-cli", "connect"], check=False)
    time.sleep(5)
    # enable on boot only after everything is working
    shell.run(["systemctl", "enable", "warp-svc"], check=False)


def _apply_warp_svc_outbound() -> None:
    tag = _tag_for_method("warp-svc")
    outbound = {
        "tag": tag, "protocol": "freedom",
        "settings": {},
        "streamSettings": {"sockopt": {"dialerProxy": "socks5://127.0.0.1:40000"}},
    }
    for path in _xray_config_paths():
        with open(path) as f:
            cfg = json.load(f)
        cfg.setdefault("outbounds", [])
        cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") != tag]
        cfg["outbounds"].append(outbound)
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)


def install_warp_svc() -> None:
    print("  Installing cloudflare-warp package...")
    _install_warp_svc()
    print("  Configuring...")
    _config_warp_svc()
    # ponytail: проверяем что warp-svc реально подключился
    if not _check_tunnel_alive("warp-svc"):
        print("  Warning: warp-svc may not be connected, check 'warp-cli status'")
    print("  Applying Xray outbound...")
    _apply_warp_svc_outbound()
    config.vwn_conf_set("WARP_METHOD", "warp-svc")
    shell.run(["systemctl", "restart", "xray-reality", "xray-ws", "xray-xhttp"],
              check=False)
    print("  WARP (warp-svc) installed")


def remove_warp_svc() -> None:
    shell.run(["warp-cli", "disconnect"], check=False)
    shell.run(["systemctl", "stop", "warp-svc"], check=False)
    shell.run(["systemctl", "disable", "warp-svc"], check=False)
    shell.run(["apt-get", "remove", "-y", "cloudflare-warp"], check=False)
    for f in ("/etc/apt/sources.list.d/cloudflare-client.list",
              "/usr/share/keyrings/cloudflare-warp.gpg"):
        if os.path.exists(f):
            os.remove(f)
    _remove_outbound("warp-svc")


# ── Unified API ────────────────────────────────────────────────────

_METHODS = {
    "native": (install_native, remove_native),
    "amnezia": (install_amnezia, remove_amnezia),
    "warp-svc": (install_warp_svc, remove_warp_svc),
}


def install(method: str = "native") -> None:
    if method not in _METHODS:
        raise ValueError(f"Unknown WARP method: {method}")
    cur = config.vwn_conf_get("WARP_METHOD")
    if cur:
        print(f"  WARP already installed ({cur}). Remove first.")
        return
    _METHODS[method][0]()


def remove() -> None:
    cur = config.vwn_conf_get("WARP_METHOD") or ""
    remover = _METHODS.get(cur, (None, remove_native))[1]
    remover()
    config.vwn_conf_del("WARP_METHOD")
    config.vwn_conf_del("WARP_ENDPOINT")
    config.vwn_conf_del("WARP_TUNNEL_MODE")
    shell.run(["systemctl", "restart", "xray-reality", "xray-ws", "xray-xhttp"],
              check=False)
    print("  WARP removed")


# ponytail: stop/start без удаления (FIX #5 из оригинала).
# Stop убирает outbound + routing из конфигов, ключи и конфиг остаются.
# Start восстанавливает outbound + routing из сохранённых данных.

def stop() -> None:
    """Остановить WARP без удаления конфига и ключей."""
    method = config.vwn_conf_get("WARP_METHOD") or ""
    if not method:
        print("  WARP не настроен")
        return
    tag = _tag_for_method(method)
    if method == "native":
        pass  # ponytail: native — kernel wireguard, нет сервиса для остановки
    elif method == "amnezia":
        shell.run(["systemctl", "stop", AWG_SERVICE], check=False)
    elif method == "warp-svc":
        shell.run(["warp-cli", "disconnect"], check=False)
    _remove_outbound(method)
    # ponytail: WARP_TUNNEL_MODE НЕ удаляем — start() восстановит routing
    shell.run(["systemctl", "restart", "xray-reality", "xray-ws", "xray-xhttp"],
              check=False)
    print(f"  WARP ({method}) остановлен — ключи и конфиг сохранены")


def start() -> None:
    """Запустить ранее остановленный WARP (без переустановки)."""
    method = config.vwn_conf_get("WARP_METHOD") or ""
    if not method:
        print("  WARP не настроен")
        return
    keys = _load_saved_keys()
    endpoint = config.vwn_conf_get("WARP_ENDPOINT") or ""
    if method == "native":
        if not keys or not endpoint:
            print("  Ключи WARP не найдены, переустановите WARP")
            return
        _apply_native_outbound(keys["WARP_PRIVATE_KEY"], keys["WARP_IPV4"], endpoint)
    elif method == "amnezia":
        if not shell.service_active(AWG_SERVICE):
            shell.run(["systemctl", "start", AWG_SERVICE], check=False, timeout=30)
            time.sleep(3)
        if not _check_tunnel_alive("amnezia"):
            print(f"  Интерфейс {AWG_IFACE} не поднялся")
            return
        _apply_amnezia_outbound()
    elif method == "warp-svc":
        shell.run(["warp-cli", "connect"], check=False)
        time.sleep(5)
        _apply_warp_svc_outbound()
    tag = _tag_for_method(method)
    mode = config.vwn_conf_get("WARP_TUNNEL_MODE") or ""
    if mode and _check_tunnel_alive(method):
        _add_routing_rule_if_missing(tag, mode)
    shell.run(["systemctl", "restart", "xray-reality", "xray-ws", "xray-xhttp"],
              check=False)
    print(f"  WARP ({method}) запущен")


def _check_tunnel_alive(method: str) -> bool:
    """Проверить, что туннель WARP реально работает перед добавлением routing."""
    if method == "native":
        keys = _load_saved_keys()
        endpoint = config.vwn_conf_get("WARP_ENDPOINT") or ""
        return bool(keys.get("WARP_PRIVATE_KEY") and endpoint)
    elif method == "amnezia":
        r = shell.run(["ip", "link", "show", AWG_IFACE],
                      check=False, capture=True, timeout=5)
        return r.returncode == 0
    elif method == "warp-svc":
        r = shell.run(["warp-cli", "status"], check=False, capture=True, timeout=10)
        return r.returncode == 0 and "Connected" in (r.stdout or "")
    return False


def reapply_warp() -> None:
    """Повторно применить WARP outbound ко всем конфигам (после provision)."""
    method = config.vwn_conf_get("WARP_METHOD") or ""
    if not method:
        return
    tag = _tag_for_method(method)
    if method == "native":
        keys = _load_saved_keys()
        endpoint = config.vwn_conf_get("WARP_ENDPOINT") or ""
        if keys and endpoint:
            _apply_native_outbound(keys["WARP_PRIVATE_KEY"], keys["WARP_IPV4"], endpoint)
    elif method == "amnezia":
        _apply_amnezia_outbound()
    elif method == "warp-svc":
        _apply_warp_svc_outbound()
    mode = config.vwn_conf_get("WARP_TUNNEL_MODE") or ""
    if mode and _check_tunnel_alive(method):
        _add_routing_rule_if_missing(tag, mode)


def _load_saved_keys() -> dict[str, str]:
    """Прочитать сохранённые WARP-ключи из warp-keys.env."""
    if not os.path.exists(WARP_KEYS_FILE):
        return {}
    keys = {}
    with open(WARP_KEYS_FILE) as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                keys[k] = v
    return keys


def status() -> dict:
    method = config.vwn_conf_get("WARP_METHOD") or ""
    active = bool(method)
    return {"method": method, "active": active,
            "endpoint": config.vwn_conf_get("WARP_ENDPOINT") or "",
            "awg_mode": config.vwn_conf_get("AWG_MODE") or ""}

def add_domain(domain: str) -> bool:
    from vwn.modules._domains import add_domain as _ad
    method = config.vwn_conf_get("WARP_METHOD") or "warp-svc"
    return _ad(_tag_for_method(method), domain)


def remove_domain(index: int) -> None:
    from vwn.modules._domains import remove_domain as _rd
    method = config.vwn_conf_get("WARP_METHOD") or "warp-svc"
    _rd(_tag_for_method(method), index)


def list_domains() -> list[str]:
    from vwn.modules._domains import list_domains as _ld
    method = config.vwn_conf_get("WARP_METHOD") or "warp-svc"
    return _ld(_tag_for_method(method))


def check_ip() -> dict:
    import subprocess as _sp
    result: dict[str, str] = {"direct": "", "warp": "", "country": "", "error": ""}
    r = _sp.run(["curl", "-fL", "--max-time", "15", "https://api.ipify.org"],
                capture_output=True, text=True, timeout=20)
    result["direct"] = r.stdout.strip() if r.returncode == 0 else ""
    method = config.vwn_conf_get("WARP_METHOD") or ""
    if method == "native":
        r = _sp.run(["curl", "-fL", "--max-time", "15",
                     "--socks5-hostname", "127.0.0.1:10808",
                     "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=20)
    elif method == "warp-svc":
        r = _sp.run(["curl", "-fL", "--max-time", "15",
                     "-x", "socks5://127.0.0.1:40000",
                     "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=20)
    elif method == "amnezia":
        r = _sp.run(["curl", "-fL", "--max-time", "15",
                     "--socks5-hostname", "127.0.0.1:10809",
                     "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=20)
    else:
        r = _sp.run(["false"], capture_output=True, timeout=5)
    result["warp"] = r.stdout.strip() if r.returncode == 0 else ""
    if r.returncode != 0 and not result["warp"]:
        err = (r.stderr or "").strip()
        result["error"] = err[:200] if err else f"exit code {r.returncode}"
    if result["warp"]:
        try:
            r = _sp.run(["mmdblookup", "--file", "/usr/local/share/GeoLite2-Country.mmdb",
                         "--ip", result["warp"]],
                        capture_output=True, text=True, check=False)
        except FileNotFoundError:
            return result
        m = __import__("re").search(r'"iso_code":\s+"([A-Z]{2})"', r.stdout or "")
        result["country"] = m.group(1) if m else ""
    return result


def upgrade() -> None:
    method = config.vwn_conf_get("WARP_METHOD") or ""
    if not method:
        return
    if method == "native":
        old = WGCF_BIN + ".bak"
        if os.path.exists(WGCF_BIN):
            shutil.move(WGCF_BIN, old)
        try:
            _install_wgcf()
            for f in [WARP_KEYS_FILE]:
                if os.path.exists(f):
                    os.remove(f)
            keys = _generate_keys()
            endpoint = _pick_endpoint()
            _apply_native_outbound(keys["WARP_PRIVATE_KEY"], keys["WARP_IPV4"], endpoint)
            config.vwn_conf_set("WARP_ENDPOINT", endpoint)
        except Exception:
            if os.path.exists(old):
                shutil.move(old, WGCF_BIN)
            raise
        finally:
            Path(old).unlink(missing_ok=True)
    elif method == "amnezia":
        shell.run(["apt-get", "install", "-y", "--only-upgrade",
                   "amneziawg", "amneziawg-tools"], timeout=60, check=False)
        shell.run(["systemctl", "restart", AWG_SERVICE], check=False)
    elif method == "warp-svc":
        shell.run(["apt-get", "install", "-y", "--only-upgrade",
                   "cloudflare-warp"], timeout=120, check=False)
        shell.run(["systemctl", "restart", "warp-svc"], check=False)
    shell.run(["systemctl", "restart", "xray-reality", "xray-ws", "xray-xhttp"],
              check=False)
