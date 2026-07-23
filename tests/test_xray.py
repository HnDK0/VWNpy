import json
import os

import pytest

from vwn.core import config
from vwn.modules import xray


@pytest.fixture
def paths(tmp_path, monkeypatch):
    xray_dir = tmp_path / "xray"
    monkeypatch.setattr(config, "XRAY_DIR", str(xray_dir))
    monkeypatch.setattr(config, "VWN_CONF", str(tmp_path / "vwn.conf"))
    monkeypatch.setattr(config, "NGINX_LOOPBACK_CONF", str(tmp_path / "xray_loopback.conf"))
    monkeypatch.setattr(config, "SYSTEMD_DIR", str(tmp_path / "systemd"))
    monkeypatch.setattr(config, "REALITY_PUBLIC_PORT", 443)
    monkeypatch.setattr(config, "NGINX_LOOPBACK_PORT", 8443)
    monkeypatch.setattr(config, "XRAY_WS_PORT", 50001)
    monkeypatch.setattr(config, "XRAY_XHTTP_PORT", 50002)
    return tmp_path


def test_generate_uuid_format():
    import uuid as _uuid
    assert _uuid.UUID(xray.generate_uuid())


def test_reality_config_shape():
    c = xray.reality_config("uuid-1", "microsoft.com:443", "vpn.example.com",
                            "PRIV", "SHORT", port=443, fallback_port=8443)
    ib = c["inbounds"][0]
    assert ib["port"] == 443
    assert ib["streamSettings"]["security"] == "reality"
    assert ib["streamSettings"]["realitySettings"]["privateKey"] == "PRIV"
    # Fallback dest → nginx loopback
    assert ib["streamSettings"]["realitySettings"]["dest"] == "127.0.0.1:8443"
    assert ib["streamSettings"]["realitySettings"]["serverNames"] == ["vpn.example.com"]
    assert c["outbounds"][-1]["protocol"] == "blackhole"   # общие outbounds
    assert "warp" in [o["tag"] for o in c["outbounds"]]
    assert ib["sniffing"]["routeOnly"] is True
    assert ib["streamSettings"]["sockopt"]["tcpCongestion"] == "bbr"


def test_ws_config_shape():
    c = xray.ws_config("uuid-1", 50001, "/v2/api/abc", "vpn.example.com")
    ib = c["inbounds"][0]
    assert ib["listen"] == "127.0.0.1"
    assert ib["port"] == 50001
    assert ib["streamSettings"]["network"] == "ws"
    assert ib["streamSettings"]["wsSettings"]["path"] == "/v2/api/abc"
    assert ib["streamSettings"]["wsSettings"]["host"] == "vpn.example.com"
    assert ib["streamSettings"]["sockopt"]["tcpCongestion"] == "bbr"
    assert ib["sniffing"]["routeOnly"] is True


def test_xhttp_config_shape():
    c = xray.xhttp_config("uuid-1", 50002, "/v2/api/xyz", "vpn.example.com", mode="stream")
    ib = c["inbounds"][0]
    assert ib["port"] == 50002
    assert ib["streamSettings"]["network"] == "xhttp"
    assert ib["streamSettings"]["xhttpSettings"]["mode"] == "stream"


def test_provision_writes_valid_configs(paths):
    params = xray.provision_configs(
        "vpn.example.com", "https://www.openstreetmap.org/",
        "microsoft.com:443", private_key="PRIV",
    )
    rc = json.loads((paths / "xray" / "xray-reality.json").read_text(encoding="utf-8"))
    assert rc["inbounds"][0]["port"] == 443
    # serverNames должен совпадать с dest-хостом (microsoft.com), а не с доменом
    assert rc["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"] == ["microsoft.com"]
    # Fallback dest → nginx loopback (не-Reality трафик)
    assert rc["inbounds"][0]["streamSettings"]["realitySettings"]["dest"] == "127.0.0.1:8443"

    wc = json.loads((paths / "xray" / "config.json").read_text(encoding="utf-8"))
    assert wc["inbounds"][0]["port"] == 50001

    xc = json.loads((paths / "xray" / "xhttp.json").read_text(encoding="utf-8"))
    assert xc["inbounds"][0]["port"] == 50002

    ng = (paths / "xray_loopback.conf").read_text(encoding="utf-8")
    assert "127.0.0.1:8443" in ng                          # nginx loopback (через Reality fallback)
    assert "log_format main_safe" in ng                  # иначе nginx -t падает
    assert "127.0.0.1:50001" in ng
    assert "grpc_pass grpc://127.0.0.1:50002" in ng     # XHTTP только gRPC (со схемой)
    assert "grpc_buffer_size 64k" in ng                  # полный блок, не пустышка
    assert "grpc_read_timeout 315s" in ng
    assert "root /usr/local/etc/xray" in ng              # подписки (root, файлы в sub/)
    assert "proxy_pass https://www.openstreetmap.org/" in ng
    assert "Strict-Transport-Security" in ng

    # 3 независимых unit-файла (reality/ws/xhttp)
    sd = paths / "systemd"
    for unit, cfg in (("xray-reality.service", "xray-reality.json"),
                      ("xray-ws.service", "config.json"),
                      ("xray-xhttp.service", "xhttp.json")):
        u = (sd / unit).read_text(encoding="utf-8")
        assert f"run -config {paths / 'xray' / cfg}" in u
        assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE" in u
        assert "WantedBy=multi-user.target" in u

    assert config.vwn_conf_get("DOMAIN") == "vpn.example.com"
    assert config.vwn_conf_get("UUID") == params["uuid"]


def test_provision_rejects_bad_domain(paths):
    with pytest.raises(ValueError):
        xray.provision_configs("bad domain", "https://x.com/", "microsoft.com:443",
                               private_key="PRIV", server_name="x.com")
