import json

from vwn.core import config
from vwn.cores import mihomo_tunnels
from vwn.modules import _outbound


def _write_xray(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path / "xray"))
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    (tmp_path / "xray").mkdir()
    cfg = {
        "inbounds": [
            {"protocol": "socks", "tag": "socks-warp", "listen": "127.0.0.1", "port": 10808},
        ],
        "outbounds": [
            {"tag": "dns-out", "protocol": "dns"},
            {"tag": "free", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
            {"tag": "warp-svc", "protocol": "socks",
             "settings": {"servers": [{"address": "127.0.0.1", "port": 40000}]}},
            {"tag": "warp-native", "protocol": "wireguard",
             "settings": {"secretKey": "priv", "address": ["172.16.0.2/32"],
                          "peers": [{"publicKey": "pub",
                                     "endpoint": "engage.cloudflareclient.com:2408"}]}},
            {"tag": "relay", "protocol": "vless",
             "settings": {"vnext": [{"address": "example.com", "port": 443,
                                     "users": [{"id": "uuid", "flow": "xtls-rprx-vision",
                                                "encryption": "none"}]}]},
             "streamSettings": {"network": "tcp", "security": "reality",
                                "realitySettings": {"serverName": "cdn.example.com",
                                                    "publicKey": "pbk", "shortId": "sid",
                                                    "fingerprint": "chrome"}}},
            {"tag": "warp-amnezia", "protocol": "freedom",
             "streamSettings": {"sockopt": {"interface": "awg0"}}},
        ],
        "routing": {"rules": [
            {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "port": "25, 587", "network": "tcp", "outboundTag": "block"},
            {"type": "field", "inboundTag": ["socks-warp"], "outboundTag": "warp-native"},
            {"type": "field", "domain": ["domain:whoer.net"], "outboundTag": "warp-native"},
            {"type": "field", "domain": ["domain:only-warp.example"],
             "inboundTag": ["socks-warp"], "outboundTag": "warp-native"},
            {"type": "field", "port": "0-65535", "outboundTag": "free"},
        ]},
    }
    (tmp_path / "xray" / "xray-reality.json").write_text(json.dumps(cfg), encoding="utf-8")


def test_translate_proxies(tmp_path, monkeypatch):
    _write_xray(tmp_path, monkeypatch)
    proxies, rules, listeners = mihomo_tunnels.state()
    names = {p["name"] for p in proxies}
    assert names == {"warp-svc", "warp-native", "relay", "warp-amnezia"}
    by_name = {p["name"]: p for p in proxies}
    assert by_name["warp-svc"]["type"] == "socks5"
    assert by_name["warp-native"]["type"] == "wireguard"
    assert by_name["warp-native"]["server"] == "engage.cloudflareclient.com"
    assert by_name["warp-native"]["port"] == 2408
    assert by_name["relay"]["type"] == "vless"
    assert by_name["relay"]["flow"] == "xtls-rprx-vision"
    assert by_name["relay"]["reality-opts"]["public-key"] == "pbk"
    assert by_name["warp-amnezia"]["type"] == "direct"
    assert by_name["warp-amnezia"]["interface-name"] == "awg0"
    assert [l["name"] for l in listeners] == ["socks-warp"]


def test_freedom_before_socks_still_resolves_dialer(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path / "xray"))
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    (tmp_path / "xray").mkdir()
    cfg = {"outbounds": [
        {"tag": "warp-amnezia", "protocol": "freedom",
         "settings": {"sockopt": {"dialerProxy": "warp-svc"}}},
        {"tag": "warp-svc", "protocol": "socks",
         "settings": {"servers": [{"address": "127.0.0.1", "port": 40000}]}},
    ]}
    (tmp_path / "xray" / "xray-reality.json").write_text(
        json.dumps(cfg), encoding="utf-8")
    by_name = {p["name"]: p for p in mihomo_tunnels.proxies()}
    assert by_name["warp-amnezia"]["type"] == "socks5"
    assert by_name["warp-amnezia"]["port"] == 40000


def test_translate_rules(tmp_path, monkeypatch):
    _write_xray(tmp_path, monkeypatch)
    _, rules, _ = mihomo_tunnels.state()
    assert "GEOSITE,category-ads-all,REJECT" in rules
    assert "GEOIP,LAN,REJECT,no-resolve" in rules
    assert ("AND,((NETWORK,tcp),(OR,((DST-PORT,25),(DST-PORT,587)))),"
            "REJECT") in rules
    assert "IN-NAME,socks-warp,warp-native" in rules
    assert "DOMAIN-SUFFIX,whoer.net,warp-native" in rules
    assert ("AND,((DOMAIN-SUFFIX,only-warp.example),(IN-NAME,socks-warp)),"
            "warp-native") in rules
    assert rules[-1] == "MATCH,DIRECT"


def test_tunnel_state_syncs_from_xray_configs(tmp_path, monkeypatch):
    from vwn.core import tunnel_state

    _write_xray(tmp_path, monkeypatch)
    tunnel_state.sync()
    data = json.loads(config.vwn_conf_get("TUNNELS_STATE"))
    tags = {o.get("tag") for o in data["outbounds"]}
    assert "warp-native" in tags
    assert any(r.get("outboundTag") == "warp-native"
               for r in data["routing"]["rules"])


def test_state_file_created_for_mihomo(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path / "xray"))
    monkeypatch.setattr(config, "MIHOMO_DIR", str(tmp_path / "mihomo"))
    monkeypatch.setattr(config, "core_name", lambda: "mihomo")
    paths = _outbound._paths()
    assert len(paths) == 1
    assert "vwn-tunnels" in paths[0]
    assert paths[0].startswith(str(tmp_path / "xray"))
    assert not paths[0].startswith("/tmp")
