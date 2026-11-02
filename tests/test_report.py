"""vwn report: сбор диагностики и маскирование секретов."""
import os
import re
import subprocess
import sys

import pytest

from vwn.core import config
from vwn.modules import xray

SCRIPT = os.path.join(os.path.dirname(xray.__file__), "..", "data", "collect_report.sh")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


@pytest.fixture
def stack(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path / "xray"))
    monkeypatch.setattr(config, "NGINX_LOOPBACK_CONF", str(tmp_path / "xray.conf"))
    monkeypatch.setattr(config, "SYSTEMD_DIR", str(tmp_path / "systemd"))
    monkeypatch.setattr(xray, "_bbr_available", lambda: True)
    for mod in ("warp", "psiphon", "tor", "relay"):
        m = __import__(f"vwn.modules.{mod}", fromlist=["x"])
        for fn in ("reapply_warp", "reapply_routing"):
            if hasattr(m, fn):
                monkeypatch.setattr(m, fn, lambda *a, **k: None)
    params = xray.provision_configs("vpn.example.com", "https://www.openstreetmap.org/",
                                    "microsoft.com:443", private_key="TOPSECRETPRIVKEY")
    return tmp_path, params


def _run(tmp_path):
    out = tmp_path / "report.txt"
    env = dict(os.environ, VWN_XRAY_DIR=str(tmp_path / "xray"),
               VWN_NGX_CONF=str(tmp_path / "xray.conf"), VWN_REPORT_SKIP_NET="1")
    r = subprocess.run(["bash", SCRIPT, str(out)], env=env, capture_output=True,
                       text=True, timeout=180)
    assert r.returncode == 0, r.stderr
    return out.read_text(encoding="utf-8")


def test_report_masks_secrets(stack):
    tmp_path, p = stack
    txt = _run(tmp_path)
    assert "TOPSECRETPRIVKEY" not in txt
    assert p["uuid"] not in txt and not UUID_RE.search(txt)
    assert p["short_id"] not in txt
    assert p["grpc_service"] not in txt and p["xhttp_path"] not in txt
    assert "<path len=" in txt                     # пути заменены хэшем


def test_report_paths_match_and_sections(stack):
    tmp_path, _ = stack
    txt = _run(tmp_path)
    assert "serviceName gRPC из xray есть в nginx location: yes" in txt
    assert "путь XHTTP из xray есть в nginx location: yes" in txt
    for sec in ("Проверки цепочки gRPC", "Проверки цепочки XHTTP", "Ядро / TCP",
                "Исходящая сеть и DNS", "Автовыводы"):
        assert sec in txt
    assert "grpc_pass" in txt


def test_report_flags_bbr_without_kernel_support(stack):
    """BBR в конфиге, а в ядре его нет → автовывод должен это показать."""
    tmp_path, _ = stack
    if not os.path.exists("/proc/sys/net/ipv4/tcp_available_congestion_control"):
        pytest.skip("нет /proc/sys/net/ipv4")
    avail = open("/proc/sys/net/ipv4/tcp_available_congestion_control").read().split()
    txt = _run(tmp_path)
    flagged = "tcpCongestion=bbr, а BBR в ядре недоступен" in txt
    assert flagged == ("bbr" not in avail)


def test_report_path_mismatch_detected(stack):
    tmp_path, p = stack
    conf = tmp_path / "xray.conf"
    # ломаем именно location gRPC: в nginx другой префикс, чем serviceName в xray
    old = f"location ^~ /{p['grpc_service']} {{"
    text = conf.read_text(encoding="utf-8")
    assert old in text
    conf.write_text(text.replace(old, "location ^~ /zz {"), encoding="utf-8")
    txt = _run(tmp_path)
    assert "serviceName gRPC из xray есть в nginx location: no" in txt
    assert "serviceName gRPC из xray не найден среди location nginx" in txt


def test_report_flags_legacy_ws_leftovers(stack):
    tmp_path, _ = stack
    (tmp_path / "xray" / "config.json").write_text("{}", encoding="utf-8")
    txt = _run(tmp_path)
    assert "Остались следы WebSocket" in txt


def test_cli_report_command(monkeypatch):
    from click.testing import CliRunner
    from vwn import cli as vcli
    calls = []
    monkeypatch.setattr(subprocess, "call", lambda a: calls.append(a) or 0)
    r = CliRunner().invoke(vcli.cli, ["report", "/tmp/x.txt"])
    assert r.exit_code == 0
    assert calls[0][0] == "bash" and calls[0][1].endswith("collect_report.sh")
    assert calls[0][2] == "/tmp/x.txt"
