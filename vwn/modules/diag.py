"""Диагностика стека VWNpy."""

import datetime
import os
import subprocess
import sys

from vwn.core import config, shell
from vwn.core.color import C


def _ok(tag: str, val: str = "") -> str:
    return f"{C['green']}{tag}{C['reset']} {val}"


def _fail(tag: str, val: str = "") -> str:
    return f"{C['red']}{tag}{C['reset']} {val}"


def _warn(tag: str, val: str = "") -> str:
    return f"{C['yellow']}{tag}{C['reset']} {val}"


def _skip(tag: str) -> str:
    return f"{C['cyan']}{tag}{C['reset']}"


def _check_service(label: str, svc: str) -> str:
    r = shell.run(["systemctl", "is-active", "--quiet", svc], check=False, timeout=5)
    if r.returncode == 0:
        return f"  {label:16} {_ok('RUNNING')}"
    return f"  {label:16} {_fail('STOPPED')}"


def _cert_info() -> str:
    cert = os.path.join(config.CERT_DIR, "cert.pem")
    if not os.path.exists(cert):
        return _fail("NO CERT")
    try:
        r = subprocess.run(["openssl", "x509", "-in", cert, "-noout",
                            "-subject", "-dates", "-issuer"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            return _fail("CANT READ")
        lines = r.stdout.strip().splitlines()
        subject = ""
        issuer = ""
        dates = []
        for l in lines:
            if l.startswith("subject="): subject = l.split("=", 1)[1]
            if l.startswith("issuer="): issuer = l.split("=", 1)[1]
            if l.startswith("notBefore="): dates.append(l.split("=", 1)[1])
            if l.startswith("notAfter="): dates.append(l.split("=", 1)[1])
        cn = subject.split("=")[-1] if "=" in subject else subject
        ca = "LE" if "Let's Encrypt" in issuer else issuer.split("=")[-1] if "=" in issuer else issuer[:20]
        expire = datetime.datetime.strptime(dates[-1], "%b %d %H:%M:%S %Y %Z") if dates else None
        days = (expire - datetime.datetime.now()).days if expire else -1
        if expire and days <= 0:
            expiry_str = _fail(f"EXPIRED ({-days}d ago)")
        elif expire and days < 15:
            expiry_str = _warn(f"{days}d left")
        elif expire:
            expiry_str = _ok(f"OK ({days}d)")
        else:
            expiry_str = "?"
        lines_out = [f"  Cert: CN={cn}, CA={ca}  {expiry_str}"]
        return "\n".join(lines_out)
    except Exception:
        return _fail("CHECK FAILED")


def _config_summary() -> str:
    from vwn.modules import users as _usr
    _usr.init_users_file()
    users_list = _usr.list_users()
    users_info = f"{len(users_list)} user(s)"
    if users_list:
        users_info += ": " + ", ".join(f"{_usr.get_cached_flag()} {u['label']}" for u in users_list)
    pairs = [
        ("Domain", config.vwn_conf_get("DOMAIN") or "-"),
        ("Reality dest", config.vwn_conf_get("REALITY_DEST") or "-"),
        ("Reality port", config.vwn_conf_get("REALITY_PORT") or "443"),
        ("Users", users_info),
        ("Server IP", config.vwn_conf_get("SERVER_IP") or "-"),
    ]
    return "\n".join(f"  {k:14} {v}" for k, v in pairs)


def _sub_info() -> str:
    sub_dir = "/usr/local/etc/xray/sub"
    if not os.path.isdir(sub_dir):
        return _fail("NO SUB DIR")
    txts = sorted(f for f in os.listdir(sub_dir) if f.endswith(".txt"))
    htmls = [f for f in os.listdir(sub_dir) if f.endswith(".html")]
    if not txts:
        return _fail("NO SUB FILES")
    domain = config.vwn_conf_get("DOMAIN") or "?"
    lines = [f"  TXT: {len(txts)}, HTML: {len(htmls)}"]
    for t in txts[:5]:
        lines.append(f"    https://{domain}/sub/{t}")
    if len(txts) > 5:
        lines.append(f"    ... +{len(txts)-5} more")
    return "\n".join(lines)


def _diag_network() -> None:
    print("--- Network ---")
    domain = config.vwn_conf_get("DOMAIN")
    if domain:
        r = shell.run(["dig", "+short", "A", domain, "@8.8.8.8"],
                       capture=True, check=False, timeout=5)
        dns_ip = r.stdout.strip() if r.returncode == 0 else ""
        server_ip = config.vwn_conf_get("SERVER_IP") or ""
        if dns_ip and dns_ip == server_ip:
            print(f"  DNS: {_ok(domain)} -> {dns_ip}")
        elif dns_ip:
            print(f"  DNS: {_warn(domain)} -> {dns_ip} (server: {server_ip})")
        else:
            print(f"  DNS: {_fail(domain)} (unresolved)")
    for port, label in [(443, "HTTPS"), (80, "HTTP")]:
        r = shell.run(["ss", "-tlnp"], capture=True, check=False, timeout=5)
        if f":{port} " in (r.stdout or ""):
            print(f"  Port {port} ({label}): {_ok('LISTEN')}")
        else:
            print(f"  Port {port} ({label}): {_fail('NOT LISTEN')}")
    print()


def _diag_connectivity() -> None:
    print("--- Connectivity ---")
    r = shell.run(["curl", "-sS", "--connect-timeout", "8", "--max-time", "15",
                    "https://api.ipify.org"], capture=True, check=False, timeout=25)
    if r.returncode == 0 and r.stdout:
        print(f"  Internet: {_ok(r.stdout.strip())}")
    else:
        print(f"  Internet: {_fail('UNAVAILABLE')}")
    domain = config.vwn_conf_get("DOMAIN")
    if domain:
        r = shell.run(["curl", "-sS", "--connect-timeout", "8", "--max-time", "15",
                        "-o", "/dev/null", "-w", "%{http_code}",
                        f"https://{domain}/"], capture=True, check=False, timeout=25)
        code = r.stdout.strip() if r.returncode == 0 else "000"
        if code in ("200", "301", "302"):
            print(f"  Domain {domain}: {_ok(f'HTTP {code}')}")
        elif code == "000":
            print(f"  Domain {domain}: {_fail('UNREACHABLE')}")
        else:
            print(f"  Domain {domain}: {_warn(f'HTTP {code}')}")
    print()


def _diag_geoip() -> None:
    print("--- GeoIP / GeoSite ---")
    for f in ["/usr/local/share/xray/geoip.dat",
              "/usr/local/share/xray/geosite.dat"]:
        if os.path.isfile(f):
            size = os.path.getsize(f)
            print(f"  {os.path.basename(f)}: {_ok(f'{size/1024:.0f} KB')}")
        else:
            print(f"  {os.path.basename(f) if '/' not in f else os.path.basename(f)}: {_fail('MISSING')}")
    print()


def _diag_xray_test() -> None:
    print("--- Xray Config Tests ---")
    for label, path in [("Reality", os.path.join(config.XRAY_DIR, "xray-reality.json")),
                         ("WS", os.path.join(config.XRAY_DIR, "config.json")),
                         ("XHTTP", os.path.join(config.XRAY_DIR, "xhttp.json"))]:
        if not os.path.isfile(path):
            print(f"  {label:7}: {_skip('no config')}")
            continue
        r = shell.run([config.XRAY_BIN, "-test", "-config", path],
                       capture=True, check=False, timeout=15)
        ok = r.returncode == 0
        print(f"  {label:7}: {_ok('OK') if ok else _fail('FAIL')}")
        if not ok:
            for line in (r.stdout or "").splitlines()[-3:]:
                print(f"          {line}")
    print()


def _diag_nginx_test() -> None:
    print("--- Nginx Config Test ---")
    r = shell.run(["nginx", "-t"], capture=True, check=False, timeout=5)
    if r.returncode == 0:
        print(f"  {_ok('OK')}")
    else:
        print(f"  {_fail('FAIL')}")
        for line in (r.stderr or "").splitlines():
            print(f"  {line}")
    print()


def run_full_diag() -> None:
    sys.stdout.reconfigure(line_buffering=True)
    print(f"{C['cyan']}=== Диагностика VWNpy ==={C['reset']}")
    print()

    print("--- Services ---")
    for label, svc in [("xray-reality", "xray-reality.service"),
                        ("xray-ws", "xray-ws.service"),
                        ("xray-xhttp", "xray-xhttp.service"),
                        ("nginx", "nginx.service"),
                        ("warp-svc", "warp-svc.service"),
                        ("fail2ban", "fail2ban.service")]:
        print(_check_service(label, svc))
    print()

    print("--- Tunnels ---")
    for label, svc in [("Psiphon", "psiphon.service"),
                        ("Tor", "tor.service")]:
        print(_check_service(label, svc))
    from vwn.modules.relay import status as _relay_status
    rs = _relay_status()
    print(f"  {'Relay':16} {_ok('ON') if rs.get('configured') else _fail('OFF')}")
    print()

    print("--- Certificate ---")
    print(_cert_info())
    print()

    print("--- Config ---")
    print(_config_summary())
    print()

    print("--- Subscriptions ---")
    print(_sub_info())
    print()

    print("--- CDN ---")
    from vwn.modules.cdn import status as _cdn_status
    cdn = _cdn_status()
    mode = cdn["mode"]
    ip = cdn["ip"] or "-"
    watcher = "ON" if cdn["watcher"] else "OFF"
    found = cdn["found_count"]
    print(f"  Mode: {mode}  IP: {ip}  Watcher: {watcher}  Cached: {found}")
    print()

    print("--- Security ---")
    from vwn.modules.security import bbr_status, fail2ban_status, webjail_status, ipv6_status, ssh_password_auth_status
    bbr = bbr_status()
    f2b = fail2ban_status()
    wj = webjail_status()
    ipv6 = ipv6_status()
    sh = ssh_password_auth_status()
    print(f"  BBR: {'ON' if bbr['enabled'] else 'OFF'} ({bbr['algo']})")
    print(f"  Fail2Ban: {'ON' if f2b['active'] else 'OFF'} (jailed: {f2b['jailed']})")
    print(f"  WebJail: {'ON' if wj['enabled'] else 'OFF'} (banned: {wj['banned']})")
    print(f"  IPv6: {'OFF (disabled)' if ipv6['disabled'] else 'ON'}")
    if sh['password_auth']:
        print(f"  SSH password auth: {_fail('ON')}")
    else:
        print(f"  SSH password auth: {_ok('OFF')}")
    if sh['root_password_login']:
        print(f"  SSH root login: {_fail('YES (password allowed)')}")
    else:
        print(f"  SSH root login: {_ok('prohibit-password')}")
    print()

    print("--- System ---")
    try:
        r = subprocess.run(["uptime", "-p"], capture_output=True, text=True, timeout=3)
        print(f"  Uptime: {r.stdout.strip()}")
    except Exception:
        pass
    try:
        r = subprocess.run(["df", "-h", "/", "--output=pcent"], capture_output=True, text=True, timeout=3)
        disk = r.stdout.strip().splitlines()[-1].strip() if r.returncode == 0 else "?"
        print(f"  Disk: {disk} used")
    except Exception:
        pass
    try:
        r = subprocess.run(["free", "-m"], capture_output=True, text=True, timeout=3)
        for l in r.stdout.splitlines():
            if l.startswith("Mem:"):
                parts = l.split()
                print(f"  RAM: {parts[2]}MB / {parts[1]}MB used")
                break
    except Exception:
        pass
    print()

    _diag_network()
    _diag_connectivity()
    _diag_geoip()
    _diag_xray_test()
    _diag_nginx_test()
