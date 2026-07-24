"""Tests for warp module."""

import subprocess

from vwn.modules import warp


class _R:
    returncode = 0
    stdout = ""
    stderr = ""


def test_check_ip_direct_only(monkeypatch):
    monkeypatch.setattr(warp.config, "vwn_conf_get", lambda k: "")

    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        r = _R()
        if "api.ipify.org" in str(cmd) and "socks5" not in str(cmd) and "-x" not in str(cmd):
            r.stdout = "1.2.3.4\n"
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = warp.check_ip()

    assert result["direct"] == "1.2.3.4"
    assert result["warp"] == ""
    assert result["country"] == ""


def test_check_ip_native(monkeypatch):
    monkeypatch.setattr(warp.config, "vwn_conf_get", lambda k: "native")

    calls = []

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        r = _R()
        s = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else str(cmd)
        if "api.ipify.org" in s and "--socks5" not in s:
            r.stdout = "1.2.3.4\n"
        if "--socks5-hostname" in s and "127.0.0.1:10808" in s:
            r.stdout = "100.100.1.1\n"
        if "mmdblookup" in s:
            r.stdout = '  { "country": { "iso_code": "DE" <packets> } }\n'
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = warp.check_ip()

    assert result["direct"] == "1.2.3.4"
    assert result["warp"] == "100.100.1.1"
    assert result["country"] == "DE"
