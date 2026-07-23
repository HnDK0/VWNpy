"""Security: BBR, Fail2Ban, UFW, SSH port."""

import os
import re
import time

from vwn.core import shell


# ── BBR ────────────────────────────────────────────────────────────

def bbr_status() -> dict:
    r = shell.run(["sysctl", "net.ipv4.tcp_congestion_control"],
                   capture=True, check=False)
    algo = ""
    if r.returncode == 0:
        m = re.search(r"= (\S+)", r.stdout or "")
        if m:
            algo = m.group(1)
    return {"enabled": algo == "bbr", "algo": algo or "unknown"}


def bbr_enable() -> None:
    if bbr_status()["enabled"]:
        return
    for param, val in [("net.core.default_qdisc", "fq"),
                       ("net.ipv4.tcp_congestion_control", "bbr")]:
        shell.run(["sysctl", "-w", f"{param}={val}"], check=False)
    _append_if_missing("/etc/sysctl.conf",
                       "net.core.default_qdisc = fq\n"
                       "net.ipv4.tcp_congestion_control = bbr\n")


# ── Fail2Ban ───────────────────────────────────────────────────────

_F2B_JAIL_LOCAL = "/etc/fail2ban/jail.local"

_F2B_CONFIG = """[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = systemd
"""


def fail2ban_install() -> None:
    if shell.service_active("fail2ban"):
        return
    shell.run(["apt-get", "install", "-y", "fail2ban"], timeout=60, check=False)
    os.makedirs(os.path.dirname(_F2B_JAIL_LOCAL), exist_ok=True)
    with open(_F2B_JAIL_LOCAL, "w") as f:
        f.write(_F2B_CONFIG)
    shell.run(["systemctl", "enable", "--now", "fail2ban"], check=False)
    time.sleep(2)


def fail2ban_status() -> dict:
    active = shell.service_active("fail2ban")
    jailed = 0
    if active:
        r = shell.run(["fail2ban-client", "status", "sshd"],
                       capture=True, check=False)
        if r.returncode == 0:
            m = re.search(r"Currently banned:\s*(\d+)", r.stdout or "")
            if m:
                jailed = int(m.group(1))
    return {"active": active, "jailed": jailed}


def fail2ban_start() -> None:
    shell.run(["systemctl", "start", "fail2ban"], check=False)


def fail2ban_stop() -> None:
    shell.run(["systemctl", "stop", "fail2ban"], check=False)


# ── UFW ────────────────────────────────────────────────────────────

def ufw_installed() -> bool:
    return shell.run(["which", "ufw"], check=False).returncode == 0


def ufw_status() -> dict:
    if not ufw_installed():
        return {"active": False, "installed": False, "rules": []}
    active = shell.run(["ufw", "status"], capture=True, check=False)
    is_active = "Status: active" in (active.stdout or "")
    rules = []
    r = shell.run(["ufw", "status", "numbered"], capture=True, check=False)
    if r.returncode == 0:
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                rules.append(line)
    return {"active": is_active, "installed": True, "rules": rules}


def ufw_allow(port: int, proto: str = "tcp", comment: str = "") -> None:
    if not ufw_installed():
        shell.run(["apt-get", "install", "-y", "ufw"], timeout=60, check=False)
    args = ["ufw", "allow", f"{port}/{proto}"]
    if comment:
        args += ["comment", comment]
    shell.run(args, check=False)


def ufw_deny(port: int, proto: str = "tcp") -> None:
    if not ufw_installed():
        return
    shell.run(["ufw", "delete", "allow", f"{port}/{proto}"], check=False)


# ── SSH port ───────────────────────────────────────────────────────

def _sshd_config_path() -> str:
    return "/etc/ssh/sshd_config"


def _parse_ssh_port() -> int:
    """Прочитать текущий порт SSH из sshd_config."""
    path = _sshd_config_path()
    if not os.path.isfile(path):
        return 22
    with open(path) as f:
        for line in f:
            line = line.strip()
            # Port 22 (без #), игнорируем закомментированные
            m = re.match(r"^Port\s+(\d+)$", line)
            if m:
                return int(m.group(1))
    return 22


# ponytail: ss -tlnp не кросс-платформенный (нет на минимальных установках),
# используем /proc/net/tcp как fallback. Если и его нет — ошибка.
def _port_in_use(port: int) -> bool:
    r = shell.run(["ss", "-tlnp"], capture=True, check=False)
    if r.returncode == 0:
        for line in (r.stdout or "").splitlines():
            if f":{port}" in line and "LISTEN" in line:
                return True
    # fallback: /proc/net/tcp
    try:
        with open("/proc/net/tcp") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    local = parts[1]
                    if ":" not in local:
                        continue
                    hex_port = local.split(":")[1]
                    try:
                        if int(hex_port, 16) == port:
                            return True
                    except ValueError:
                        continue
    except OSError:
        pass
    return False


def _sshd_set(key: str, value: str) -> None:
    path = _sshd_config_path()
    with open(path) as f:
        content = f.read()
    pattern = rf"^\s*#?\s*{re.escape(key)}\s+.+"
    replacement = f"{key} {value}"
    if re.search(pattern, content, re.M):
        content = re.sub(pattern, replacement, content, flags=re.M)
    else:
        content = content.rstrip() + f"\n{replacement}\n"
    with open(path, "w") as f:
        f.write(content)


def ssh_disable_password_auth() -> None:
    _sshd_set("PasswordAuthentication", "no")
    _sshd_set("ChallengeResponseAuthentication", "no")
    _sshd_set("PermitRootLogin", "prohibit-password")
    for svc in ("sshd", "ssh"):
        if shell.run(["systemctl", "restart", svc], check=False).returncode == 0:
            return


def ssh_password_auth_status() -> dict:
    path = _sshd_config_path()
    pw = True
    root = True
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                m = re.match(r"PasswordAuthentication\s+(\S+)", line)
                if m:
                    pw = m.group(1).lower() == "yes"
                m = re.match(r"PermitRootLogin\s+(\S+)", line)
                if m:
                    root = m.group(1).lower() == "yes"
    except OSError:
        pass
    return {"password_auth": pw, "root_password_login": root}


def change_ssh_port(new_port: int) -> None:
    """Сменить SSH порт с rollback при ошибке."""
    if new_port < 1 or new_port > 65535:
        raise ValueError(f"Port out of range: {new_port}")
    if _port_in_use(new_port):
        raise RuntimeError(f"Port {new_port} already in use")

    old_port = _parse_ssh_port()
    if new_port == old_port:
        return

    path = _sshd_config_path()
    ufw_allow(new_port, "tcp", "SSH")

    old_content = ""
    with open(path) as f:
        old_content = f.read()

    if re.search(r"^#?\s*Port\s+\d+", old_content, re.M):
        new_content = re.sub(r"^#?\s*Port\s+\d+", f"Port {new_port}",
                             old_content, flags=re.M)
    else:
        new_content = old_content.rstrip() + f"\nPort {new_port}\n"

    with open(path, "w") as f:
        f.write(new_content)

    # restart и проверка
    for svc in ("sshd", "ssh"):
        if shell.run(["systemctl", "restart", svc], check=False).returncode == 0:
            time.sleep(2)
            if shell.service_active(svc):
                # проверить что слушает на новом порту
                if _port_in_use(new_port) and not _port_in_use(old_port):
                    # убрать старый порт из UFW если он был 22
                    if old_port == 22:
                        ufw_deny(old_port, "tcp")
                    return
                # rollback
                with open(path, "w") as f:
                    f.write(old_content)
                shell.run(["systemctl", "restart", svc], check=False)
                raise RuntimeError(
                    f"SSHd started but not listening on {new_port}, rolled back to {old_port}")
            # rollback
            with open(path, "w") as f:
                f.write(old_content)
            shell.run(["systemctl", "restart", svc], check=False)
            ufw_deny(new_port, "tcp")
            raise RuntimeError(
                f"SSHd failed to start on {new_port}, rolled back to {old_port}")

    raise RuntimeError("No sshd/ssh service found")


# ── BBR disable ────────────────────────────────────────────────────

def bbr_disable() -> None:
    for param, val in [("net.core.default_qdisc", "pfifo_fast"),
                       ("net.ipv4.tcp_congestion_control", "cubic")]:
        shell.run(["sysctl", "-w", f"{param}={val}"], check=False)
    _remove_line("/etc/sysctl.conf",
                 "net.core.default_qdisc|net.ipv4.tcp_congestion_control")


# ── Fail2Ban remove ────────────────────────────────────────────────

def fail2ban_remove() -> None:
    shell.run(["systemctl", "stop", "fail2ban"], check=False)
    shell.run(["systemctl", "disable", "fail2ban"], check=False)
    shell.run(["apt-get", "remove", "-y", "fail2ban"], timeout=60, check=False)


# ── WebJail (nginx-probe fail2ban jail) ────────────────────────────

_WEBJAIL_FILTER = "/etc/fail2ban/filter.d/nginx-probe.conf"
_WEBJAIL_FILTER_CONF = """[Definition]
failregex = ^<HOST> -.*(?:404|400|403|444|405|500|502|503).*
ignoreregex =
"""


def webjail_enable() -> None:
    """Включить nginx-probe jail (fail2ban filter для сканеров)."""
    if not shell.service_active("fail2ban"):
        fail2ban_install()
    os.makedirs(os.path.dirname(_WEBJAIL_FILTER), exist_ok=True)
    with open(_WEBJAIL_FILTER, "w") as f:
        f.write(_WEBJAIL_FILTER_CONF)
    # добавить секцию в jail.local
    jail_section = "\n[nginx-probe]\nenabled = true\nport = http,https\nfilter = nginx-probe\nlogpath = /var/log/nginx/access.log\nmaxretry = 10\nfindtime = 600\nbantime = 3600\n"
    _append_if_missing(_F2B_JAIL_LOCAL, jail_section)
    shell.run(["systemctl", "restart", "fail2ban"], check=False)


def webjail_disable() -> None:
    """Отключить nginx-probe jail."""
    if os.path.isfile(_F2B_JAIL_LOCAL):
        with open(_F2B_JAIL_LOCAL) as f:
            lines = f.readlines()
        with open(_F2B_JAIL_LOCAL, "w") as f:
            skip = False
            for line in lines:
                if line.strip() == "[nginx-probe]":
                    skip = True
                elif skip and line.startswith("["):
                    skip = False
                elif not skip:
                    f.write(line)
    if os.path.isfile(_WEBJAIL_FILTER):
        os.remove(_WEBJAIL_FILTER)
    shell.run(["systemctl", "restart", "fail2ban"], check=False)


def webjail_status() -> dict:
    if not shell.service_active("fail2ban"):
        return {"enabled": False, "banned": 0}
    r = shell.run(["fail2ban-client", "status", "nginx-probe"],
                   capture=True, check=False)
    if r.returncode != 0:
        return {"enabled": False, "banned": 0}
    m = re.search(r"Currently banned:\s*(\d+)", r.stdout or "")
    banned = int(m.group(1)) if m else 0
    return {"enabled": True, "banned": banned}


# ── IPv6 toggle ────────────────────────────────────────────────────

_IPV6_SYSCTL = "/etc/sysctl.d/99-vwn-ipv6.conf"


def ipv6_status() -> dict:
    r = shell.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"],
                   capture=True, check=False)
    disabled = r.stdout.strip() == "1" if r.returncode == 0 else False
    return {"disabled": disabled}


def ipv6_disable() -> None:
    for iface in ("all", "default", "lo"):
        shell.run(["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=1"],
                  check=False)
    shell.run(["sysctl", "-w", "net.ipv6.icmp.echo_ignore_all=1"], check=False)
    _append_if_missing(_IPV6_SYSCTL,
                       "net.ipv6.conf.all.disable_ipv6 = 1\n"
                       "net.ipv6.conf.default.disable_ipv6 = 1\n"
                       "net.ipv6.conf.lo.disable_ipv6 = 1\n"
                       "net.ipv6.icmp.echo_ignore_all = 1\n")


def ipv6_enable() -> None:
    for iface in ("all", "default", "lo"):
        shell.run(["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=0"],
                  check=False)
    shell.run(["sysctl", "-w", "net.ipv6.icmp.echo_ignore_all=0"], check=False)
    if os.path.isfile(_IPV6_SYSCTL):
        os.remove(_IPV6_SYSCTL)


# ── Helpers ────────────────────────────────────────────────────────

def _remove_line(path: str, pattern: str) -> None:
    if not os.path.isfile(path):
        return
    with open(path) as f:
        lines = f.readlines()
    kept = [l for l in lines if not re.search(pattern, l)]
    if len(kept) != len(lines):
        with open(path, "w") as f:
            f.writelines(kept)


def _append_if_missing(path: str, text: str) -> None:
    if not os.path.isfile(path):
        with open(path, "w") as f:
            f.write(text)
        return
    with open(path) as f:
        content = f.read()
    if text.strip() not in content:
        with open(path, "a") as f:
            f.write("\n" + text)


# ── CPU Guard (systemd cgroup priority) ─────────────────────────────

_CPU_GUARD_SVCS = ["xray-reality.service", "xray-ws.service", "xray-xhttp.service", "nginx.service"]


def cpu_guard_status() -> bool:
    return os.path.isfile("/etc/systemd/system/xray-reality.service.d/cpuguard.conf")


def cpu_guard_enable() -> None:
    for svc in _CPU_GUARD_SVCS:
        shell.run(["systemctl", "set-property", svc, "CPUWeight=200"], check=False)
    shell.run(["systemctl", "set-property", "user.slice", "CPUWeight=20"], check=False)
    for svc_name in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
        drop_in = f"/etc/systemd/system/{svc_name}.service.d"
        os.makedirs(drop_in, exist_ok=True)
        with open(os.path.join(drop_in, "cpuguard.conf"), "w") as f:
            f.write("[Service]\nCPUWeight=200\nNice=-10\n")
    os.makedirs("/etc/systemd/system/user.slice.d", exist_ok=True)
    with open("/etc/systemd/system/user.slice.d/cpuguard.conf", "w") as f:
        f.write("[Slice]\nCPUWeight=20\n")
    shell.run(["systemctl", "daemon-reload"], check=False)


def cpu_guard_disable() -> None:
    for svc_name in ["xray-reality", "xray-ws", "xray-xhttp", "nginx"]:
        p = f"/etc/systemd/system/{svc_name}.service.d/cpuguard.conf"
        if os.path.isfile(p):
            os.remove(p)
        try:
            os.rmdir(f"/etc/systemd/system/{svc_name}.service.d")
        except OSError:
            pass
    p = "/etc/systemd/system/user.slice.d/cpuguard.conf"
    if os.path.isfile(p):
        os.remove(p)
    try:
        os.rmdir("/etc/systemd/system/user.slice.d")
    except OSError:
        pass
    shell.run(["systemctl", "daemon-reload"], check=False)
    shell.run(["systemctl", "set-property", "user.slice", "CPUWeight=100"], check=False)
    for svc in _CPU_GUARD_SVCS:
        shell.run(["systemctl", "set-property", svc, "CPUWeight=100"], check=False)
