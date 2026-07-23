"""Тесты security.py (BBR, Fail2Ban, UFW, SSH port)."""

import os
import re

import pytest

from vwn.modules import security


# ── BBR ────────────────────────────────────────────────────────────

def test_bbr_status_disabled(monkeypatch):
    class R:
        returncode = 0
        stdout = "net.ipv4.tcp_congestion_control = cubic"
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    assert security.bbr_status() == {"enabled": False, "algo": "cubic"}


def test_bbr_status_enabled(monkeypatch):
    class R:
        returncode = 0
        stdout = "net.ipv4.tcp_congestion_control = bbr"
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    assert security.bbr_status() == {"enabled": True, "algo": "bbr"}


def test_bbr_status_error(monkeypatch):
    class R:
        returncode = 1
        stdout = ""
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    assert security.bbr_status() == {"enabled": False, "algo": "unknown"}


def test_bbr_enable_already_enabled(monkeypatch):
    class R:
        returncode = 0
        stdout = "net.ipv4.tcp_congestion_control = bbr"
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    # should not call sysctl -w
    security.bbr_enable()


def test_bbr_enable_sets_params(monkeypatch, tmp_path):
    monkeypatch.setattr(security, "bbr_status",
                        lambda: {"enabled": False, "algo": "cubic"})
    monkeypatch.setattr(security, "_append_if_missing", lambda p, t: None)
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(security.shell, "run", fake_run)
    security.bbr_enable()
    sysctl_w = [c for c in calls if c[0:2] == ["sysctl", "-w"]]
    assert len(sysctl_w) == 2
    assert any("fq" in str(c) for c in sysctl_w)
    assert any("bbr" in str(c) for c in sysctl_w)


# ── Fail2Ban ───────────────────────────────────────────────────────

def test_fail2ban_install_already_active(monkeypatch):
    monkeypatch.setattr(security.shell, "service_active", lambda s: True)
    security.fail2ban_install()  # no-op


def test_fail2ban_install(monkeypatch):
    monkeypatch.setattr(security.shell, "service_active", lambda s: False)
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(security.shell, "run", fake_run)
    # mock jail.local write
    monkeypatch.setattr(security, "_F2B_JAIL_LOCAL", "/tmp/nonexist/jail.local")
    security.fail2ban_install()
    apt_calls = [c for c in calls if "apt-get" in str(c)]
    assert any("fail2ban" in str(c) for c in apt_calls)


def test_fail2ban_status_inactive(monkeypatch):
    monkeypatch.setattr(security.shell, "service_active", lambda s: False)
    assert security.fail2ban_status() == {"active": False, "jailed": 0}


def test_fail2ban_status_active(monkeypatch):
    monkeypatch.setattr(security.shell, "service_active", lambda s: True)
    class R:
        returncode = 0
        stdout = "Status for the jail: sshd\n|- Currently banned: 3\n|`- Total banned: 10\n`- Banned IP list: ..."
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    assert security.fail2ban_status()["active"] is True
    assert security.fail2ban_status()["jailed"] == 3


# ── UFW ────────────────────────────────────────────────────────────

def test_ufw_status_not_installed(monkeypatch):
    monkeypatch.setattr(security, "ufw_installed", lambda: False)
    assert security.ufw_status() == {"active": False, "installed": False, "rules": []}


def test_ufw_status_inactive(monkeypatch):
    monkeypatch.setattr(security, "ufw_installed", lambda: True)
    class R:
        returncode = 0
        stdout = "Status: inactive\n"
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    r = security.ufw_status()
    assert r["active"] is False


def test_ufw_allow_install_if_missing(monkeypatch):
    monkeypatch.setattr(security, "ufw_installed", lambda: False)
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(security.shell, "run", fake_run)
    security.ufw_allow(80, "tcp")
    assert any("ufw" in str(c) for c in calls)


# ── SSH port ───────────────────────────────────────────────────────

def test_parse_ssh_port_default(tmp_path):
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(security, "_sshd_config_path", lambda: str(tmp_path / "nonexist"))
    assert security._parse_ssh_port() == 22


def test_parse_ssh_port_from_file(tmp_path):
    monkeypatch = pytest.MonkeyPatch()
    cfg = tmp_path / "sshd_config"
    cfg.write_text("#Port 22\nPort 2222\n")
    monkeypatch.setattr(security, "_sshd_config_path", lambda: str(cfg))
    assert security._parse_ssh_port() == 2222


def test_change_ssh_port_invalid():
    with pytest.raises(ValueError):
        security.change_ssh_port(0)
    with pytest.raises(ValueError):
        security.change_ssh_port(70000)


def test_change_ssh_port_port_in_use(monkeypatch):
    monkeypatch.setattr(security, "_port_in_use", lambda p: p == 2222)
    with pytest.raises(RuntimeError, match="already in use"):
        security.change_ssh_port(2222)


def test_change_ssh_port_same_port(monkeypatch, tmp_path):
    monkeypatch.setattr(security, "_port_in_use", lambda p: False)
    monkeypatch.setattr(security, "_parse_ssh_port", lambda: 22)
    monkeypatch.setattr(security, "_sshd_config_path", lambda: str(tmp_path / "sshd_config"))
    security.change_ssh_port(22)  # no-op


# ── _port_in_use ───────────────────────────────────────────────────

def test_port_in_use_ss(monkeypatch):
    class R:
        returncode = 0
        stdout = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    assert security._port_in_use(22) is True
    assert security._port_in_use(2222) is False


def test_port_in_use_proc_net_fallback(monkeypatch, tmp_path):
    """ss fails, _port_in_use falls back to /proc/net/tcp-like parsing."""
    class FailR:
        returncode = 1
        stdout = ""
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: FailR())
    proc_net = tmp_path / "proc_net_tcp"
    proc_net.write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 00000000 100 0 0 10 0\n"
    )

    def port_in_use_fallback(port):
        try:
            with open(str(proc_net)) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        local_part = parts[1]
                        if ":" in local_part:
                            hex_port = local_part.split(":")[1]
                            if int(hex_port, 16) == port:
                                return True
        except OSError:
            pass
        return False

    assert port_in_use_fallback(22) is True  # 0x0016 = 22
    assert port_in_use_fallback(2222) is False


# ── BBR disable ────────────────────────────────────────────────────

def test_bbr_disable(monkeypatch):
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(security.shell, "run", fake_run)
    monkeypatch.setattr(security, "_remove_line", lambda p, t: None)
    security.bbr_disable()
    sysctl_w = [c for c in calls if c[0:2] == ["sysctl", "-w"]]
    assert len(sysctl_w) == 2
    assert any("cubic" in str(c) for c in sysctl_w)


# ── Fail2Ban remove ────────────────────────────────────────────────

def test_fail2ban_remove(monkeypatch):
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(security.shell, "run", fake_run)
    security.fail2ban_remove()
    flat = [" ".join(c) for c in calls]
    assert any("apt-get remove" in c for c in flat)


# ── WebJail ─────────────────────────────────────────────────────────

def test_webjail_status_disabled(monkeypatch):
    monkeypatch.setattr(security.shell, "service_active", lambda s: False)
    assert security.webjail_status() == {"enabled": False, "banned": 0}


def test_webjail_status_active(monkeypatch):
    monkeypatch.setattr(security.shell, "service_active", lambda s: True)
    class R:
        returncode = 0
        stdout = "Status for the jail: nginx-probe\n|- Currently banned: 5\n"
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    s = security.webjail_status()
    assert s["enabled"] is True
    assert s["banned"] == 5


# ── IPv6 ────────────────────────────────────────────────────────────

def test_ipv6_status(monkeypatch):
    class R:
        returncode = 0
        stdout = "1\n"
    monkeypatch.setattr(security.shell, "run", lambda *a, **k: R())
    assert security.ipv6_status() == {"disabled": True}


def test_ipv6_disable(monkeypatch):
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(security.shell, "run", fake_run)
    monkeypatch.setattr(security, "_append_if_missing", lambda p, t: None)
    security.ipv6_disable()
    dis = [c for c in calls if "disable_ipv6=1" in str(c)]
    assert len(dis) >= 3  # all, default, lo


def test_ipv6_enable(monkeypatch):
    calls = []
    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": ""})()
    monkeypatch.setattr(security.shell, "run", fake_run)
    security.ipv6_enable()
    en = [c for c in calls if "disable_ipv6=0" in str(c)]
    assert len(en) >= 3
