import os
import time

from vwn.core import shell
from vwn.modules._outbound import add_outbound, remove_outbound

PORT = 40003
CONTROL_PORT = 40004
TAG = "tor"
CONFIG = "/etc/tor/torrc"
DOMAINS_FILE = "/usr/local/etc/xray/tor_domains.txt"
REPO_FILE = "/etc/apt/sources.list.d/tor.list"
KEYRING = "/usr/share/keyrings/tor-archive-keyring.gpg"

COUNTRIES = [
    ("AT", "Austria"), ("AU", "Australia"), ("BE", "Belgium"),
    ("BG", "Bulgaria"), ("CA", "Canada"), ("CH", "Switzerland"),
    ("CZ", "Czech Republic"), ("DE", "Germany"), ("DK", "Denmark"),
    ("EE", "Estonia"), ("ES", "Spain"), ("FI", "Finland"),
    ("FR", "France"), ("GB", "United Kingdom"), ("HR", "Croatia"),
    ("HU", "Hungary"), ("IE", "Ireland"), ("IN", "India"),
    ("IT", "Italy"), ("JP", "Japan"), ("LV", "Latvia"),
    ("NL", "Netherlands"), ("NO", "Norway"), ("PL", "Poland"),
    ("PT", "Portugal"), ("RO", "Romania"), ("RS", "Serbia"),
    ("SE", "Sweden"), ("SG", "Singapore"), ("SK", "Slovakia"),
    ("US", "United States"),
]


def _runcmd(cmd, check=True, timeout=60, capture=False):
    return shell.run(cmd, check=check, timeout=timeout, capture=capture)


def _codename():
    r = _runcmd(["lsb_release", "-sc"], check=False, capture=True)
    if r.returncode == 0:
        return r.stdout.strip()
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("VERSION_CODENAME="):
                    return line.strip().split("=", 1)[1].strip().strip('"')
    except (OSError, IOError):
        pass
    return ""


def _add_official_repo():
    cn = _codename()
    if not cn or os.path.isfile(REPO_FILE):
        return False
    _runcmd(["apt-get", "install", "-y", "apt-transport-https", "gpg"], check=False)
    _runcmd(["curl", "-fsSL",
             "https://deb.torproject.org/torproject.org/"
             "A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc",
             "-o", "/tmp/tor-key.asc"], check=False)
    if os.path.isfile("/tmp/tor-key.asc"):
        _runcmd(["gpg", "--dearmor", "-o", KEYRING, "/tmp/tor-key.asc"], check=False)
        os.remove("/tmp/tor-key.asc")
    with open(REPO_FILE, "w") as f:
        f.write(f"deb [signed-by={KEYRING}] https://deb.torproject.org/torproject.org {cn} main\n")
        f.write(f"deb-src [signed-by={KEYRING}] https://deb.torproject.org/torproject.org {cn} main\n")
    _runcmd(["apt-get", "update", "-qq"], check=False)
    return True


def _install_direct():
    _runcmd(["apt-get", "install", "-y", "tor"], timeout=180)
    _runcmd(["apt-get", "install", "-y", "tor-geoipdb"], check=False)


def install(country: str = "") -> None:
    if shell.run(["which", "tor"], capture=True, check=False).stdout.strip():
        return
    _add_official_repo()
    r = _runcmd(["apt-get", "install", "-y", "tor", "deb.torproject.org-keyring"],
                 check=False, timeout=180)
    if r.returncode != 0:
        _install_direct()
    _runcmd(["apt-get", "install", "-y", "tor-geoipdb"], check=False)
    _write_config(country)
    _runcmd(["systemctl", "enable", "tor"])
    _runcmd(["systemctl", "restart", "tor"])
    add_outbound(TAG, "socks", PORT)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        _runcmd(["systemctl", "restart", svc], check=False)
    time.sleep(3)


def upgrade() -> None:
    _add_official_repo()
    _runcmd(["apt-get", "install", "-y", "--only-upgrade", "tor", "tor-geoipdb"],
            check=False)
    _runcmd(["apt-get", "install", "-y", "tor", "tor-geoipdb"], check=False)
    _runcmd(["systemctl", "restart", "tor"])


def remove() -> None:
    _runcmd(["systemctl", "stop", "tor"], check=False)
    _runcmd(["systemctl", "disable", "tor"], check=False)
    remove_outbound(TAG)
    if os.path.isfile(CONFIG):
        os.remove(CONFIG)
    if os.path.isfile(DOMAINS_FILE):
        os.remove(DOMAINS_FILE)
    _runcmd(["apt-get", "remove", "-y", "tor"], timeout=60, check=False)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        _runcmd(["systemctl", "restart", svc], check=False)


def status() -> dict:
    active = shell.service_active("tor")
    country = ""
    bridges = False
    bridge_count = 0
    if os.path.isfile(CONFIG):
        for line in open(CONFIG):
            if line.startswith("ExitNodes"):
                m = __import__("re").search(r"\{(\w+)\}", line)
                if m:
                    country = m.group(1)
            if line.startswith("UseBridges 1"):
                bridges = True
            if line.startswith("Bridge "):
                bridge_count += 1
    return {"active": active, "country": country, "port": PORT,
            "bridges": bridges, "bridge_count": bridge_count}


def change_country(country: str) -> None:
    _write_config(country)
    _runcmd(["systemctl", "restart", "tor"])


def renew_circuit() -> None:
    import socket
    s = socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=5)
    s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
    s.close()


def check_ip() -> dict:
    import subprocess
    result = {"direct": "", "tor": "", "country": ""}
    r = subprocess.run(["curl", "-sS", "--max-time", "15", "https://api.ipify.org"],
                       capture_output=True, text=True, timeout=20)
    result["direct"] = r.stdout.strip() if r.returncode == 0 else ""
    r = subprocess.run(["curl", "-sS", "--max-time", "15",
                        "--socks5-hostname", f"127.0.0.1:{PORT}",
                        "https://api.ipify.org"],
                       capture_output=True, text=True, timeout=20)
    result["tor"] = r.stdout.strip() if r.returncode == 0 else ""
    if result["tor"]:
        r = subprocess.run(["curl", "-sS", "--max-time", "10",
                            f"https://ip-api.com/csv/{result['tor']}?fields=countryCode"],
                           capture_output=True, text=True, timeout=15)
        result["country"] = r.stdout.strip().upper()[:2] if r.returncode == 0 else ""
    return result


# ── Мосты (Bridges) ───────────────────────────────────────────

def install_obfs4() -> bool:
    if shell.run(["which", "obfs4proxy"], capture=True, check=False).stdout.strip():
        return True
    r = _runcmd(["apt-get", "install", "-y", "obfs4proxy"], check=False)
    if r.returncode == 0:
        return True
    r = _runcmd(["apt-get", "install", "-y", "lyrebird"], check=False)
    return r.returncode == 0


def add_bridges(bridge_type: str, bridges: list[str]) -> bool:
    if bridge_type in ("obfs4", "meek_lite"):
        if not install_obfs4():
            return False
    if bridge_type == "snowflake":
        _runcmd(["apt-get", "install", "-y", "snowflake-client"], check=False)
    if not bridges:
        return False
    lines = [l for l in open(CONFIG).read().splitlines()
             if not l.startswith(("UseBridges", "ClientTransportPlugin", "Bridge "))]
    lines.append("UseBridges 1")
    if bridge_type in ("obfs4", "meek_lite"):
        obfs4_bin = (shell.run(["which", "obfs4proxy"], capture=True, check=False).stdout.strip()
                     or shell.run(["which", "lyrebird"], capture=True, check=False).stdout.strip()
                     or "obfs4proxy")
        lines.append(f"ClientTransportPlugin obfs4,meek_lite exec {obfs4_bin}")
    if bridge_type == "snowflake":
        sf_bin = (shell.run(["which", "snowflake-client"], capture=True, check=False).stdout.strip()
                  or "snowflake-client")
        lines.append(f"ClientTransportPlugin snowflake exec {sf_bin} -log /var/log/tor/snowflake.log")
    for b in bridges:
        lines.append(f"Bridge {b}")
    with open(CONFIG, "w") as f:
        f.write("\n".join(lines) + "\n")
    _runcmd(["systemctl", "restart", "tor"])
    return True


def remove_bridges() -> None:
    if not os.path.isfile(CONFIG):
        return
    lines = [l for l in open(CONFIG).read().splitlines()
             if not l.startswith(("UseBridges", "ClientTransportPlugin", "Bridge "))]
    with open(CONFIG, "w") as f:
        f.write("\n".join(lines) + "\n")
    _runcmd(["systemctl", "restart", "tor"])


# ── Domains (Split-режим) ──────────────────────────────────────

def _apply_domains() -> None:
    import json
    if not os.path.isfile(DOMAINS_FILE):
        return
    domains = [l.strip() for l in open(DOMAINS_FILE) if l.strip()]
    if not domains:
        _remove_from_configs()
        return
    add_outbound(TAG, "socks", PORT)
    domains_json = [f"domain:{d}" for d in domains]
    from vwn.modules._outbound import _paths
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = json.load(f)
        for r in cfg.setdefault("routing", {}).setdefault("rules", []):
            if r.get("outboundTag") == TAG:
                r["domain"] = domains_json
                r.pop("port", None)
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        _runcmd(["systemctl", "restart", svc], check=False)


def _remove_from_configs() -> None:
    remove_outbound(TAG)


def add_domain(domain: str) -> None:
    os.makedirs(os.path.dirname(DOMAINS_FILE), exist_ok=True)
    with open(DOMAINS_FILE, "a") as f:
        f.write(domain + "\n")
    lines = sorted(set(l.strip() for l in open(DOMAINS_FILE) if l.strip()))
    with open(DOMAINS_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")
    _apply_domains()


def remove_domain(index: int) -> None:
    if not os.path.isfile(DOMAINS_FILE):
        return
    lines = [l.strip() for l in open(DOMAINS_FILE) if l.strip()]
    if 0 <= index < len(lines):
        lines.pop(index)
        with open(DOMAINS_FILE, "w") as f:
            f.write("\n".join(lines) + "\n" if lines else "")
        _apply_domains()


def list_domains() -> list[str]:
    if not os.path.isfile(DOMAINS_FILE):
        return []
    return [l.strip() for l in open(DOMAINS_FILE) if l.strip()]


def _write_config(country: str) -> None:
    with open(CONFIG, "w") as f:
        f.write(f"SocksPort 127.0.0.1:{PORT}\n")
        f.write(f"ControlPort 127.0.0.1:{CONTROL_PORT}\n")
        f.write("SocksPolicy accept 127.0.0.1\n")
        f.write("Log notice file /var/log/tor/notices.log\n")
        f.write("DataDirectory /var/lib/tor\n")
        if country:
            f.write(f"ExitNodes {{{country}}}\n")
            f.write("StrictNodes 1\n")
