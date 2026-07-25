"""CDN: Cloudflare IP scanner, watchdog, blacklist, country detection.

Modes:
  off          — no CDN override, use main domain directly
  manual       — fixed IP/domain set by user
  auto_resolve — resolve domains from cdn_domains.txt
  auto_list    — pick from static cdn_ips.txt
  auto_scan    — scan CIDR ranges, pick best from cdn_found.txt (50+ IPs)
"""

import ipaddress
import json
import os
import random
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from vwn.core import config, shell

# ── Paths ─────────────────────────────────────────────────────────
XRAY_DIR = "/usr/local/etc/xray"
VWN_CONF = os.path.join(XRAY_DIR, "vwn.conf")
DOMAINS_FILE = os.path.join(XRAY_DIR, "cdn_domains.txt")
IPS_FILE = os.path.join(XRAY_DIR, "cdn_ips.txt")
FOUND_FILE = os.path.join(XRAY_DIR, "cdn_found.txt")
ACTIVE_IP_FILE = os.path.join(XRAY_DIR, "cdn_active_ip")

def _connect_host_file() -> str:
    return os.path.join(XRAY_DIR, "connect_host")

BLACKLIST_FILE = os.path.join(XRAY_DIR, "cdn_blacklist.txt")
SCAN_LOCK = "/tmp/vwn-cdn-scan.lock"
WATCH_LOCK = "/tmp/vwn-cdn-watch.lock"
PING_CACHE = os.path.join(XRAY_DIR, "cdn_ping_cache")
BETTER_COUNT_FILE = os.path.join(XRAY_DIR, "cdn_better_count")

EMBEDDED_RANGES = [
    "5.9.0.0/16", "5.15.0.0/16", "5.36.0.0/16",
    "5.56.128.0/17", "5.79.0.0/17", "5.81.0.0/16",
    "5.188.150.0/23", "5.226.179.0/24", "5.253.84.0/22",
    "8.17.205.0/24", "8.23.240.0/24", "8.24.243.0/24",
    "8.209.0.0/16", "8.210.0.0/15", "8.212.0.0/14",
    "23.88.0.0/17", "23.227.38.0/24", "23.227.39.0/24",
    "23.227.60.0/24", "23.239.0.0/18", "23.247.163.0/24",
    "31.22.116.0/24", "31.43.179.0/24", "43.128.0.0/15",
    "43.130.0.0/15", "43.132.0.0/14", "43.136.0.0/14",
    "43.140.0.0/14", "45.8.104.0/24", "45.8.105.0/24",
    "45.8.106.0/24", "45.8.107.0/24", "45.8.211.0/24",
    "45.12.30.0/24", "45.12.31.0/24", "45.14.174.0/24",
    "45.32.0.0/16", "45.32.177.0/24", "45.33.0.0/17",
    "45.55.0.0/16", "45.56.0.0/21", "45.63.0.0/16",
    "45.67.215.0/24", "45.76.0.0/15", "45.79.0.0/16",
    "45.80.111.0/24", "45.85.118.0/24", "45.85.119.0/24",
    "45.87.175.0/24", "45.94.169.0/24", "45.95.241.0/24",
    "45.131.4.0/24", "45.131.5.0/24", "45.131.6.0/24",
    "45.131.7.0/24", "45.131.208.0/24", "45.131.209.0/24",
    "45.131.210.0/24", "45.131.211.0/24", "45.133.247.0/24",
    "45.142.120.0/24", "45.159.216.0/24", "45.159.217.0/24",
    "45.159.218.0/24", "45.159.219.0/24", "46.38.232.0/21",
    "47.52.0.0/14", "47.56.0.0/14", "47.74.0.0/15",
    "47.242.0.0/15", "49.51.0.0/16", "51.15.0.0/16",
    "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16",
    "51.89.0.0/16", "51.91.0.0/16", "51.158.0.0/15",
    "51.161.0.0/16", "51.195.0.0/16", "54.36.0.0/16",
    "54.38.0.0/15", "57.128.0.0/16", "62.171.128.0/17",
    "63.141.128.0/24", "64.68.192.0/24", "65.21.0.0/17",
    "66.81.247.0/24", "66.175.208.0/20", "66.235.200.0/24",
    "67.205.0.0/16", "69.84.182.0/24", "72.14.176.0/20",
    "72.249.0.0/18", "74.207.224.0/19", "78.46.0.0/15",
    "80.94.83.0/24", "80.249.144.0/21", "85.10.192.0/18",
    "85.17.0.0/16", "85.198.0.0/16", "87.98.128.0/17",
    "88.198.0.0/16", "89.47.56.0/24", "89.116.250.0/24",
    "89.207.18.0/24", "91.121.0.0/16", "91.193.58.0/24",
    "91.195.110.0/24", "92.222.0.0/16", "92.223.64.0/18",
    "93.123.32.0/19", "93.114.64.0/24", "94.23.0.0/16",
    "95.211.0.0/16", "95.216.0.0/16", "96.126.96.0/19",
    "103.160.204.0/24", "103.184.44.0/24", "103.184.45.0/24",
    "104.156.224.0/20", "104.193.213.0/24", "104.207.128.0/18",
    "104.234.158.0/24", "104.236.0.0/16", "104.238.177.0/24",
    "104.244.72.0/21", "104.254.140.0/24", "107.170.0.0/16",
    "108.61.0.0/17", "108.165.216.0/24", "116.202.0.0/15",
    "123.253.174.0/24", "128.140.0.0/17", "128.199.0.0/16",
    "130.162.158.0/24", "131.0.72.0/22", "135.125.0.0/16",
    "135.181.0.0/16", "136.244.64.0/18", "136.244.87.0/24",
    "136.244.103.0/24", "136.244.111.0/24", "138.68.0.0/15",
    "138.201.0.0/16", "139.162.0.0/16", "139.180.198.0/24",
    "140.27.79.0/24", "140.82.57.0/24", "140.238.170.0/24",
    "140.238.174.0/24", "141.94.0.0/16", "141.11.194.0/24",
    "141.193.213.0/24", "142.44.128.0/17", "144.91.64.0/18",
    "144.202.0.0/16", "145.239.0.0/16", "146.19.22.0/24",
    "146.59.0.0/16", "147.75.0.0/16", "147.78.121.0/24",
    "147.78.140.0/24", "147.78.178.0/24", "147.185.161.0/24",
    "148.252.128.0/17", "149.28.0.0/16", "154.51.129.0/24",
    "154.51.160.0/24", "154.83.2.0/24", "154.83.22.0/24",
    "154.83.30.0/24", "154.84.14.0/24", "154.84.16.0/24",
    "154.84.20.0/24", "154.84.24.0/24", "154.84.26.0/24",
    "154.84.175.0/24", "154.85.8.0/24", "154.85.9.0/24",
    "154.85.99.0/24", "154.94.8.0/24", "154.219.2.0/24",
    "154.219.3.0/24", "155.138.128.0/17", "156.237.4.0/24",
    "156.238.14.0/24", "156.238.18.0/24", "156.239.152.0/24",
    "156.239.154.0/24", "157.90.0.0/16", "158.69.0.0/16",
    "159.65.0.0/16", "159.65.138.0/24", "159.89.0.0/16",
    "159.112.235.0/24", "159.246.55.0/24", "160.153.0.0/24",
    "161.35.0.0/16", "162.44.104.0/24", "162.251.82.0/24",
    "164.38.155.0/24", "164.90.0.0/16", "164.132.0.0/16",
    "165.22.0.0/16", "167.1.148.0/24", "167.1.150.0/24",
    "167.172.0.0/16", "167.224.32.0/24", "167.235.0.0/16",
    "167.235.68.0/24", "168.100.6.0/24", "168.119.0.0/16",
    "170.64.0.0/16", "170.114.45.0/24", "170.114.46.0/24",
    "170.114.52.0/24", "172.104.0.0/15", "172.83.72.0/24",
    "172.83.73.0/24", "172.83.76.0/24", "173.230.128.0/18",
    "173.255.192.0/18", "174.138.0.0/17", "176.9.0.0/18",
    "176.31.0.0/16", "176.126.206.0/24", "178.32.0.0/15",
    "185.16.110.0/24", "185.18.250.0/24", "185.38.135.0/24",
    "185.59.218.0/24", "185.109.21.0/24", "185.122.0.0/24",
    "185.133.35.0/24", "185.135.9.0/24", "185.146.173.0/24",
    "185.148.104.0/24", "185.148.105.0/24", "185.148.106.0/24",
    "185.148.107.0/24", "185.162.228.0/24", "185.162.229.0/24",
    "185.162.230.0/24", "185.162.231.0/24", "185.170.166.0/24",
    "185.173.35.0/24", "185.176.24.0/24", "185.176.26.0/24",
    "185.190.224.0/22", "185.193.28.0/24", "185.193.29.0/24",
    "185.193.30.0/24", "185.193.31.0/24", "185.201.139.0/24",
    "185.215.180.0/22", "185.217.120.0/22", "185.221.160.0/24",
    "185.238.228.0/24", "185.244.106.0/24", "185.25.48.0/22",
    "185.4.104.0/22", "188.42.88.0/24", "188.42.89.0/24",
    "188.244.122.0/24", "192.0.54.0/24", "192.0.63.0/24",
    "192.65.217.0/24", "192.99.0.0/17", "192.133.11.0/24",
    "192.155.80.0/20", "192.200.160.0/24", "193.9.49.0/24",
    "193.70.0.0/17", "193.29.56.0/22", "193.227.99.0/24",
    "194.36.55.0/24", "194.53.53.0/24", "194.76.18.0/24",
    "194.87.58.0/24", "194.87.59.0/24", "194.152.44.0/24",
    "194.163.128.0/17", "195.85.23.0/24", "195.85.59.0/24",
    "195.137.167.0/24", "195.201.0.0/16", "196.13.241.0/24",
    "196.207.45.0/24", "198.23.128.0/18", "198.62.62.0/24",
    "198.74.48.0/21", "198.98.48.0/20", "198.100.144.0/20",
    "199.27.128.0/24", "199.60.103.0/24", "199.195.248.0/22",
    "199.212.90.0/24", "203.13.32.0/24", "203.17.126.0/24",
    "203.22.223.0/24", "203.23.103.0/24", "203.23.104.0/24",
    "203.23.106.0/24", "203.24.102.0/24", "203.24.103.0/24",
    "203.24.108.0/24", "203.24.109.0/24", "203.28.8.0/24",
    "203.28.9.0/24", "203.29.52.0/24", "203.29.53.0/24",
    "203.29.54.0/24", "203.29.55.0/24", "203.30.188.0/24",
    "203.30.189.0/24", "203.30.190.0/24", "203.30.191.0/24",
    "203.32.120.0/24", "203.32.121.0/24", "203.34.28.0/24",
    "203.34.80.0/24", "205.185.112.0/20", "205.233.181.0/24",
    "206.189.0.0/16", "207.246.96.0/20", "209.99.0.0/18",
    "209.123.0.0/19", "212.129.0.0/18", "212.183.88.0/24",
    "213.239.192.0/18", "213.186.0.0/16", "216.24.57.0/24",
    "216.116.134.0/24", "216.128.128.0/17",
]
MMDB_FILE = "/usr/local/share/GeoLite2-Country.mmdb"



def _read_lines(path: str) -> list[str]:
    try:
        return [l.strip() for l in Path(path).read_text().splitlines()
                if l.strip() and not l.strip().startswith("#")]
    except FileNotFoundError:
        return []


def _write(path: str, content: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content)


def _try_lock(path: str) -> bool:
    try:
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True
    except FileExistsError:
        try:
            pid = int(Path(path).read_text().strip())
            os.kill(pid, 0)
            return False
        except (ValueError, ProcessLookupError, FileNotFoundError):
            Path(path).unlink(missing_ok=True)
            return _try_lock(path)


def _release_lock(path: str) -> None:
    Path(path).unlink(missing_ok=True)


# ── GeoIP ─────────────────────────────────────────────────────────

def _get_country(ip: str) -> str:
    if not os.path.isfile(MMDB_FILE):
        return "??"
    if not shell.run(["which", "mmdblookup"], check=False, capture=True).returncode == 0:
        return "??"
    r = shell.run(["mmdblookup", "--file", MMDB_FILE, "--ip", ip],
                  capture=True, check=False)
    m = re.search(r'"iso_code":\s+"([A-Z]{2})"', r.stdout or "")
    return m.group(1) if m else "??"


# ── Network ───────────────────────────────────────────────────────

def check_ip(ip: str, timeout: int = 5) -> tuple[str, float, bool]:
    """curl via IP to cloudflare.com/cdn-cgi/trace.
    Returns (http_code, tcp_connect_ms, body_contains_h)."""
    try:
        r = shell.run([
            "curl", "-s", "-o", "/dev/null", "-w",
            "%{http_code} %{time_connect}",
            "--max-time", str(timeout), "--connect-timeout", str(timeout),
            "--connect-to", f"cloudflare.com:443:{ip}:443",
            "https://cloudflare.com/cdn-cgi/trace",
        ], capture=True, check=False, timeout=timeout + 3)
        parts = (r.stdout or "").strip().split()
        hc = parts[0] if parts else "000"
        ms = round(float(parts[1]) * 1000, 2) if len(parts) >= 2 and parts[1] != "0" else 9999
        r2 = shell.run([
            "curl", "-s", "--max-time", str(timeout),
            "--connect-timeout", str(timeout),
            "--connect-to", f"cloudflare.com:443:{ip}:443",
            "https://cloudflare.com/cdn-cgi/trace",
        ], capture=True, check=False, timeout=timeout + 3)
        ok = "h=cloudflare.com" in (r2.stdout or "")
        return hc, ms, ok
    except Exception:
        return "000", 9999, False


def ping(ip: str, timeout: int = 3) -> float:
    hc, ms, ok = check_ip(ip, timeout)
    return ms if hc == "200" and ok and ms < 9999 else 9999


def ping_with_country(ip: str, timeout: int = 3) -> tuple[float, str]:
    ms = ping(ip, timeout)
    return (ms, _get_country(ip)) if ms < 9999 else (9999, "??")


def resolve_domain(domain: str, timeout: int = 5) -> list[str]:
    ips: set[str] = set()
    try:
        for _, _, _, _, sa in socket.getaddrinfo(domain, None, socket.AF_INET):
            ips.add(sa[0])
    except Exception:
        pass
    if not ips:
        r = shell.run(["dig", "+short", "A", domain], capture=True, check=False,
                      timeout=timeout)
        if r.returncode == 0:
            for line in (r.stdout or "").splitlines():
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", line.strip()):
                    ips.add(line.strip())
    return sorted(ips)


# ── IP sources ────────────────────────────────────────────────────

def _random_ip_from_cidr(cidr: str) -> str:
    net = ipaddress.IPv4Network(cidr, strict=False)
    hosts = list(net.hosts())
    return str(hosts[secrets.randbelow(len(hosts))]) if hosts else str(net.network_address)


def _generate_sample(count: int) -> list[str]:
    ips: set[str] = set()
    attempts = 0
    while len(ips) < count and attempts < count * 10:
        attempts += 1
        cidr = random.choice(EMBEDDED_RANGES)
        try:
            ip = _random_ip_from_cidr(cidr)
            ips.add(ip)
        except Exception:
            pass
    result = list(ips)
    random.shuffle(result)
    return result


def _collect_candidates(mode: str) -> list[str]:
    ips: list[str] = []
    if mode == "auto_resolve":
        for d in _read_lines(DOMAINS_FILE):
            ips.extend(resolve_domain(d))
    elif mode == "auto_list":
        ips = [l.split()[0] for l in _read_lines(IPS_FILE) if l.split()]
    elif mode in ("auto_scan", "auto_list_found"):
        ips = [l.split()[0] for l in _read_lines(FOUND_FILE) if l.split()]
    elif mode == "auto_list_both":
        ips1 = [l.split()[0] for l in _read_lines(IPS_FILE) if l.split()]
        ips2 = [l.split()[0] for l in _read_lines(FOUND_FILE) if l.split()]
        ips = ips1 + ips2
    else:
        return []
    bl = set(_read_lines(BLACKLIST_FILE))
    return sorted(set(ip for ip in ips if ip and ip not in bl))


# ── Best IP finder ────────────────────────────────────────────────

def _scan_best(candidates: list[str], cur_ip: str = "",
               timeout: int = 3, workers: int = 40) -> tuple[str, float, float] | None:
    """Parallel ping all candidates + cur_ip. Returns (best_ip, best_ms, cur_ms)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    all_ips = list(candidates)
    if cur_ip and cur_ip not in all_ips:
        all_ips.append(cur_ip)
    results: dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fut = {ex.submit(ping, ip, timeout): ip for ip in all_ips}
        for f in as_completed(fut):
            ip = fut[f]
            try:
                results[ip] = f.result(timeout=timeout + 2)
            except Exception:
                results[ip] = 9999
    cur_ms = results.get(cur_ip, 9999) if cur_ip else 9999
    cand = sorted([(ms, ip) for ip, ms in results.items()
                   if ip != cur_ip and 0 < ms < 9999])
    if not cand:
        return None
    return cand[0][1], cand[0][0], cur_ms


def find_best(mode: str, cur_ip: str = "") -> str | None:
    candidates = _collect_candidates(mode)
    if not candidates:
        return None
    result = _scan_best(candidates, cur_ip)
    return result[0] if result else None


# ── Apply IP ──────────────────────────────────────────────────────

def apply_ip(ip: str) -> bool:
    if not ip:
        return False
    cur = ""
    try:
        cur = Path(_connect_host_file()).read_text().strip()
    except FileNotFoundError:
        pass
    if ip == cur:
        return True
    _write(_connect_host_file(), ip + "\n")
    _write(ACTIVE_IP_FILE, ip + "\n")
    for f in [BETTER_COUNT_FILE, f"{BETTER_COUNT_FILE}.ip"]:
        Path(f).unlink(missing_ok=True)
    from vwn.modules.sub import rebuild_all_sub_files
    rebuild_all_sub_files()
    shell.run(["logger", "-t", "vwn-cdn", f"CDN IP: {cur or 'none'} -> {ip}"], check=False)
    return True


# ── Scanner ───────────────────────────────────────────────────────

def _scan_and_save(count: int = 200, workers: int = 40, timeout: int = 3,
                   progress_cb=None) -> list[tuple[float, str, str]]:
    """Generate random sample, scan, return sorted (ms, ip, country) list (50+)."""
    sample = _generate_sample(count)
    if not sample:
        return []

    from concurrent.futures import ThreadPoolExecutor, as_completed
    results: list[tuple[float, str, str]] = []
    lock = threading.Lock()
    done = 0

    def _work(ip: str) -> None:
        nonlocal done
        ms, cc = ping_with_country(ip, timeout)
        with lock:
            done += 1
            if ms < 9999:
                results.append((ms, ip, cc))
            if progress_cb and done % 20 == 0:
                progress_cb(done, len(sample), len(results))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        ex.map(_work, sample)

    results.sort(key=lambda x: x[0])
    return results


def scan(foreground: bool = False, count: int | None = None,
         workers: int | None = None, timeout: int | None = None) -> int:
    count = count or int(config.vwn_conf_get("CDN_AUTOSCAN_COUNT") or "200")
    workers = workers or int(config.vwn_conf_get("CDN_SCAN_PARALLEL") or "40")
    timeout = timeout or int(config.vwn_conf_get("CDN_SCAN_TIMEOUT") or "3")
    if not foreground:
        return _scan_bg(count, workers, timeout)

    def _progress(done: int, total: int, found: int) -> None:
        print(f"\r  Scanned: {done}/{total} | Found: {found}      ", end="", flush=True)

    print("  Scanning...")
    results = _scan_and_save(count, workers, timeout, progress_cb=_progress)
    print()
    if not results:
        print("  No working IPs found")
        return 1

    lines = [f"{ip:<20} {ms:<6} {cc}" for ms, ip, cc in results]
    _write(FOUND_FILE, "\n".join(lines) + "\n")
    print(f"  Saved {len(results)} IPs to {FOUND_FILE}")
    print(f"  Best: {results[0][1]} ({results[0][0]}ms, {results[0][2]})")
    return 0


def _scan_bg(count: int, workers: int, timeout: int) -> int:
    if not _try_lock(SCAN_LOCK):
        return 1

    def _bg() -> None:
        results = _scan_and_save(count, workers, timeout)
        if results:
            lines = [f"{ip:<20} {ms:<6} {cc}" for ms, ip, cc in results]
            _write(FOUND_FILE, "\n".join(lines) + "\n")
        _release_lock(SCAN_LOCK)

    t = threading.Thread(target=_bg, daemon=True)
    t.start()
    return 0


def scan_status() -> dict:
    return {"running": not _try_lock(SCAN_LOCK)}


def scan_stop() -> None:
    Path(SCAN_LOCK).unlink(missing_ok=True)


# ── Watchdog ──────────────────────────────────────────────────────

def watch() -> int:
    if not _try_lock(WATCH_LOCK):
        return 0
    try:
        mode = config.vwn_conf_get("CDN_MODE") or ""
        if not mode or not mode.startswith("auto_"):
            return 0
        domain = config.vwn_conf_get("DOMAIN") or ""
        if not domain:
            return 0

        cur = ""
        try:
            cur = Path(_connect_host_file()).read_text().strip()
        except FileNotFoundError:
            pass

        if not cur:
            best = find_best(mode)
            if best:
                apply_ip(best)
            return 0

        cur_ms = ping(cur, int(config.vwn_conf_get("CDN_CHECK_TIMEOUT") or "5"))
        _write(PING_CACHE, f"{cur_ms}\n")

        if cur_ms >= 9999:
            best = find_best(mode, cur)
            if best:
                apply_ip(best)
            return 0

        candidates = _collect_candidates(mode)
        if not candidates:
            return 0

        to = int(config.vwn_conf_get("CDN_SCAN_TIMEOUT") or "3")
        workers = int(config.vwn_conf_get("CDN_SCAN_PARALLEL") or "40")
        result = _scan_best(candidates, cur, timeout=to, workers=workers)
        if not result:
            return 0

        best_ip, best_ms, cms = result
        if best_ip == cur or cms >= 9999:
            return 0

        gain = cms - best_ms
        threshold = int(config.vwn_conf_get("CDN_PING_THRESHOLD_MS") or "5")
        if gain < threshold:
            return 0

        cnt = 0
        try:
            cnt = int(Path(BETTER_COUNT_FILE).read_text().strip())
        except (ValueError, FileNotFoundError):
            pass
        saved = ""
        try:
            saved = Path(f"{BETTER_COUNT_FILE}.ip").read_text().strip()
        except FileNotFoundError:
            pass

        if saved != best_ip:
            cnt = 0
        cnt += 1
        _write(BETTER_COUNT_FILE, f"{cnt}\n")
        _write(f"{BETTER_COUNT_FILE}.ip", f"{best_ip}\n")

        confirm = int(config.vwn_conf_get("CDN_PING_CONFIRM_COUNT") or "2")
        if cnt >= confirm:
            apply_ip(best_ip)
        return 0
    finally:
        _release_lock(WATCH_LOCK)


# ── Watcher systemd ───────────────────────────────────────────────

def install_watcher() -> None:
    service = (
        "[Unit]\nDescription=VWN CDN watch\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=oneshot\n"
        "ExecStart=/usr/local/bin/vwn cdn-watch\n"
        "TimeoutStartSec=55\nKillMode=control-group\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    timer = (
        "[Unit]\nDescription=VWN CDN timer\n\n"
        "[Timer]\nOnBootSec=60\nOnUnitActiveSec=300\n"
        "AccuracySec=10\nPersistent=false\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    _write("/etc/systemd/system/vwn-cdn-watch.service", service)
    _write("/etc/systemd/system/vwn-cdn-watch.timer", timer)
    shell.run(["systemctl", "daemon-reload"], check=False)
    shell.run(["systemctl", "enable", "--now", "vwn-cdn-watch.timer"], check=False)


def remove_watcher() -> None:
    shell.run(["systemctl", "disable", "--now", "vwn-cdn-watch.timer"], check=False)
    for f in ["/etc/systemd/system/vwn-cdn-watch.service",
              "/etc/systemd/system/vwn-cdn-watch.timer"]:
        Path(f).unlink(missing_ok=True)
    shell.run(["systemctl", "daemon-reload"], check=False)


def watcher_active() -> bool:
    return shell.service_active("vwn-cdn-watch.timer")


# ── Mode management ───────────────────────────────────────────────

def set_mode(new_mode: str) -> None:
    config.vwn_conf_set("CDN_MODE", new_mode)
    if new_mode.startswith("auto_"):
        install_watcher()
        # сразу применить лучший IP из кэша, если есть
        if not Path(_connect_host_file()).is_file() or not Path(_connect_host_file()).read_text().strip():
            best = find_best(new_mode)
            if best:
                apply_ip(best)
    else:
        remove_watcher()
    if new_mode == "off":
        for f in [_connect_host_file(), ACTIVE_IP_FILE, BETTER_COUNT_FILE,
                  f"{BETTER_COUNT_FILE}.ip"]:
            Path(f).unlink(missing_ok=True)
        from vwn.modules.sub import rebuild_all_sub_files
        rebuild_all_sub_files()


# ── Status ────────────────────────────────────────────────────────

def status() -> dict:
    mode = config.vwn_conf_get("CDN_MODE") or "off"
    cur = ""
    try:
        cur = Path(_connect_host_file()).read_text().strip()
    except FileNotFoundError:
        pass
    cached_ping = ""
    if cur and os.path.isfile(PING_CACHE):
        try:
            age = time.time() - os.path.getmtime(PING_CACHE)
            if age < 300:
                cached_ping = Path(PING_CACHE).read_text().strip()
        except Exception:
            pass
    return {
        "mode": mode,
        "ip": cur,
        "ping_ms": cached_ping,
        "watcher": watcher_active(),
        "found_count": len(_read_lines(FOUND_FILE)),
    }


# ── Blacklist ─────────────────────────────────────────────────────

def blacklist_add(ip: str) -> None:
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")


def blacklist_list() -> list[str]:
    return _read_lines(BLACKLIST_FILE)


def blacklist_clear() -> None:
    Path(BLACKLIST_FILE).unlink(missing_ok=True)


# ── Domains list ──────────────────────────────────────────────────

def domains_list() -> list[str]:
    return _read_lines(DOMAINS_FILE)


def domains_add(domain: str) -> None:
    lines = _read_lines(DOMAINS_FILE)
    lines.append(domain)
    lines = sorted(set(lines))
    _write(DOMAINS_FILE, "\n".join(lines) + "\n")


def domains_remove(index: int) -> None:
    lines = _read_lines(DOMAINS_FILE)
    if 0 <= index < len(lines):
        lines.pop(index)
        _write(DOMAINS_FILE, "\n".join(lines) + "\n" if lines else "")


# ── Init ──────────────────────────────────────────────────────────

def init_sources() -> None:
    if not os.path.isfile(DOMAINS_FILE):
        _write(DOMAINS_FILE, "# Domains for resolution\n"
               "bestproxy.onecf.eu.org\nworkers.cloudflare.cyou\n")
    if not os.path.isfile(IPS_FILE):
        _write(IPS_FILE, "# Manual IP list\n")
    if not os.path.isfile(FOUND_FILE):
        _write(FOUND_FILE, "# Found by scanner: IP, ms, country\n")
