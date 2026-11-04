import base64
import os
import re

import pytest

from vwn.core import config
from vwn.modules import sub


@pytest.fixture
def conf(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    monkeypatch.setattr(config, "NGINX_CONF_DIR", str(tmp_path / "conf.d"))
    monkeypatch.setattr(config, "NGINX_LOOPBACK_PORT", 8443)
    config.vwn_conf_set("DOMAIN", "vpn.example.com")
    config.vwn_conf_set("UUID", "550e8400-e29b-41d4-a716-446655440000")
    config.vwn_conf_set("GRPC_SERVICE", "svcabc123")
    config.vwn_conf_set("XHTTP_PATH", "/v2/api/xyz")
    config.vwn_conf_set("XHTTP_MODE", "auto")
    config.vwn_conf_set("REALITY_PORT", "443")
    config.vwn_conf_set("REALITY_DEST", "microsoft.com:443")
    config.vwn_conf_set("REALITY_PUBKEY", "test-pub-key")
    config.vwn_conf_set("SHORT_ID", "abcdef0123456789")
    config.vwn_conf_set("SERVER_IP", "1.2.3.4")
    return tmp_path


def test_generate_reality_url():
    url = sub.generate_reality_url(
        "uuid-1", "1.2.3.4", 443, "abc", "microsoft.com",
        "pub-key", "Reality user1 1.2.3.4",
    )
    assert url.startswith("vless://uuid-1@1.2.3.4:443")
    assert "security=reality" in url
    assert "sni=microsoft.com" in url
    assert "pbk=pub-key" in url
    assert "sid=abc" in url
    assert "support-x25519mlkem768=true" in url
    assert "flow=xtls-rprx-vision" in url
    assert "Reality" in url


def test_generate_grpc_url():
    url = sub.generate_grpc_url(
        "uuid-1", "vpn.example.com", 8443, "svcabc123",
        "vpn.example.com", "gRPC user1 1.2.3.4",
    )
    assert url.startswith("vless://uuid-1@vpn.example.com:8443")
    assert "encryption=none" in url
    assert "security=tls" in url
    assert "type=grpc" in url
    assert "serviceName=svcabc123" in url
    assert "mode=gun" in url                       # по умолчанию — совместимый gun
    assert "authority=vpn.example.com" in url      # через CDN :authority = домен, не IP
    assert "sni=vpn.example.com" in url
    assert "type=ws" not in url
    assert "path=svcabc123" in url


def test_generate_grpc_url_multi_and_cdn_host():
    url = sub.generate_grpc_url("u", "1.2.3.4", 443, "svc", "d.example.com", "n", mode="multi")
    assert url.startswith("vless://u@1.2.3.4:443")
    assert "mode=multi" in url
    assert "sni=d.example.com" in url and "authority=d.example.com" in url


def test_generate_xhttp_url():
    url = sub.generate_xhttp_url(
        "uuid-1", "vpn.example.com", 8443, "/v2/api/xyz",
        "vpn.example.com", "XHTTP user1 1.2.3.4",
        mode="auto",
    )
    assert url.startswith("vless://uuid-1@vpn.example.com:8443")
    assert "type=xhttp" in url
    assert "mode=auto" in url
    assert "alpn=h2" in url


def test_safe_label():
    assert sub.safe_label("Hello World!") == "HelloWorld"
    assert sub.safe_label("user_123") == "user_123"
    assert sub.safe_label("a|b|c") == "abc"


def test_sub_filename():
    assert sub.sub_filename("user1", "ABC123") == "user1_ABC123.txt"
    assert sub.sub_filename("Hello World", "tok") == "HelloWorld_tok.txt"


def test_generate_token_length():
    assert len(sub.generate_token()) == 32
    assert len(sub.generate_token(16)) == 16


def test_write_sub_file(tmp_path):
    lines = ["vless://...line1", "vless://...line2"]
    path = sub.write_sub_file(str(tmp_path), "user1", "TOKEN1", lines)
    assert os.path.isfile(path)
    with open(path) as f:
        raw = f.read()
    decoded = base64.b64decode(raw).decode()
    assert "line1" in decoded
    assert "line2" in decoded
    # mode 0o644 (Unix) — пропускаем на Windows, где stat иной
    if os.name != "nt":
        assert os.stat(path).st_mode & 0o777 == 0o644


def test_write_sub_map(tmp_path):
    conf_d = tmp_path / "conf.d"
    os.makedirs(conf_d)
    path = sub.write_sub_map(str(conf_d), "DE")
    assert os.path.isfile(path)
    content = open(path).read()
    assert "DE VLESS" in content
    assert "$sub_label" in content
    assert "\\.yaml$" in content


def test_build_user_html_page(tmp_path):
    tpl = tmp_path / "user_page.html"
    tpl.write_text(
        "<html>{{PAGE_TITLE}} {{SUB_URL}} {{SUB_YAML_URL}} {{CONFIGS_HTML}}</html>"
    )
    out = tmp_path / "out.html"
    sub.build_user_html_page(
        str(tpl), str(out),
        "uuid-1", "user1", "https://vpn.example.com/sub/user1_TOKEN1.txt",
        ["vless://abc@1.2.3.4:443?security=reality#test"],
        sub_yaml_url="https://vpn.example.com/sub/user1_TOKEN1.yaml",
        page_title="user1 \xb7 vpn.example.com",
        server_ip="1.2.3.4",
    )
    html = out.read_text(encoding="utf-8")
    assert "user1" in html
    assert "vpn.example.com" in html
    assert "vless://abc@1.2.3.4:443?security=reality#test" in html
    assert "user1_TOKEN1.yaml" in html


def test_build_user_sub_file(conf, tmp_path, monkeypatch):
    monkeypatch.setattr(sub, "SUB_DIR", str(tmp_path))
    sub.build_user_sub_file(
        "550e8400-e29b-41d4-a716-446655440000",
        "user1", "TOKEN1",
        "vpn.example.com", "1.2.3.4",
        output_dir=str(tmp_path),
    )
    # .txt created
    txt_path = tmp_path / "user1_TOKEN1.txt"
    assert txt_path.exists()
    b64 = txt_path.read_text()
    decoded = base64.b64decode(b64).decode()
    # прямой XHTTP/Reality → серверный IP
    assert "1.2.3.4:443" in decoded
    # .html created
    found_html = list(tmp_path.glob("user1*.html"))
    assert len(found_html) == 1
    html = found_html[0].read_text(encoding="utf-8")
    assert "vpn.example.com" in html
    # .yaml created
    yaml_path = tmp_path / "user1_TOKEN1.yaml"
    assert yaml_path.exists()
    assert "proxies:" in yaml_path.read_text(encoding="utf-8")


# ── XHTTP/gRPC ссылки: ALPN и режим клиента ─────────────────────────

def test_xhttp_url_alpn_h2_only():
    u = sub.generate_xhttp_url("u", "h.example.com", 443, "/x", "d.example.com", "n", mode="stream-one")
    assert "alpn=h2&" in u and "http%2F1.1" not in u   # stream-up/one по HTTP/1.1 не работают
    assert "mode=stream-one" in u and "encryption=none" in u


def test_grpc_url_alpn_h2_only():
    u = sub.generate_grpc_url("u", "h.example.com", 443, "svc", "d.example.com", "n")
    assert "alpn=h2&" in u and "http%2F1.1" not in u   # gRPC живёт только поверх h2


def test_grpc_url_encodes_service_name():
    u = sub.generate_grpc_url("u", "h", 443, "a.b-c_d", "d.example.com", "n")
    assert "serviceName=a.b-c_d" in u
    assert "path=a.b-c_d" in u

def test_user_sub_contains_grpc_not_ws(conf, tmp_path):
    (tmp_path / "connect_host").write_text("cdn.example.com", encoding="utf-8")
    sub.build_user_sub_file("550e8400-e29b-41d4-a716-446655440000", "user1", "TOKEN1",
                            "vpn.example.com", "1.2.3.4", output_dir=str(tmp_path))
    decoded = base64.b64decode((tmp_path / "user1_TOKEN1.txt").read_text()).decode()
    grpc_lines = [l for l in decoded.splitlines() if "type=grpc" in l]
    assert len(grpc_lines) == 1
    assert "serviceName=svcabc123" in grpc_lines[0]
    assert "VL-gRPC" in grpc_lines[0] or "VL-gRPC" in __import__("urllib.parse").parse.unquote(grpc_lines[0])
    assert "type=ws" not in decoded
    html = (tmp_path / "user1_TOKEN1.html").read_text(encoding="utf-8")
    assert "gRPC + TLS" in html and 'class="cfg-icon grpc"' in html
    assert "WS + TLS" not in html


def test_user_sub_grpc_mode_and_disabled(conf, tmp_path):
    (tmp_path / "connect_host").write_text("cdn.example.com", encoding="utf-8")
    config.vwn_conf_set("GRPC_MODE", "multi")
    sub.build_user_sub_file("u", "user1", "T", "vpn.example.com", "1.2.3.4",
                            output_dir=str(tmp_path))
    decoded = base64.b64decode((tmp_path / "user1_T.txt").read_text()).decode()
    assert "mode=multi" in [l for l in decoded.splitlines() if "type=grpc" in l][0]
    config.vwn_conf_set("DISABLED_PROTOCOLS", "grpc")
    sub.build_user_sub_file("u", "user1", "T", "vpn.example.com", "1.2.3.4",
                            output_dir=str(tmp_path))
    decoded = base64.b64decode((tmp_path / "user1_T.txt").read_text()).decode()
    assert "type=grpc" not in decoded and "type=xhttp" in decoded


@pytest.mark.parametrize("given,expected", [
    ("auto", "stream-one"), ("", "stream-one"),
    ("stream-one", "stream-one"), ("packet-up", "packet-up"),
])
def test_reality_xhttp_url_never_auto(given, expected):
    u = sub.generate_reality_url("u", "1.2.3.4", 443, "sid", "microsoft.com", "pbk", "n",
                                 mode="xhttp", xhttp_path="/r", xhttp_mode=given)
    assert f"mode={expected}" in u and "mode=auto" not in u
    assert "alpn=h2" in u


def test_generate_mihomo_yaml_grpc():
    proxies = [{"name": "gRPC", "type": "vless", "server": "example.com", "port": 443,
                "uuid": "u", "udp": True, "tls": True, "servername": "example.com",
                "client-fingerprint": "chrome", "network": "grpc",
                "grpc-opts": {"grpc-service-name": "svc", "ping-interval": 15}}]
    y = sub.generate_mihomo_yaml(proxies)
    assert "proxies:" in y
    assert "ping-interval: 15" in y
    assert "grpc-service-name: svc" in y


def test_generate_mihomo_yaml_reality():
    proxies = [{"name": "Reality", "type": "vless", "server": "1.2.3.4", "port": 443,
                "uuid": "u", "udp": True, "flow": "xtls-rprx-vision", "encryption": "",
                "tls": True, "servername": "dest.com", "client-fingerprint": "chrome",
                "reality-opts": {"public-key": "pbk", "short-id": "sid",
                                 "support-x25519mlkem768": True},
                "network": "tcp"}]
    y = sub.generate_mihomo_yaml(proxies)
    assert "support-x25519mlkem768: true" in y
    assert "flow: xtls-rprx-vision" in y


def test_build_mihomo_proxies():
    proxies = sub.build_mihomo_proxies(
        "uuid", "label", "domain.com", "cdn.com", "1.2.3.4",
        "svc", "gun", "/xhttp", "auto", "443", "dest.com", "pbk", "sid",
        "tcp", "", "auto", set(),
    )
    assert len(proxies) >= 2
    grpc = [p for p in proxies if p.get("network") == "grpc"][0]
    assert grpc["grpc-opts"]["ping-interval"] == 15


@pytest.mark.parametrize("given,expected", [
    ("auto", "stream-one"), ("", "stream-one"),
    ("stream-one", "stream-one"), ("packet-up", "packet-up"),
])
def test_mihomo_reality_xhttp_mode_never_auto(given, expected):
    proxies = sub.build_mihomo_proxies(
        "u", "label", "d.com", "c.com", "1.2.3.4",
        "", "", "", "", "443", "dest.com", "pbk", "sid",
        "xhttp", "/r", given, set(),
    )
    y = sub.generate_mihomo_yaml(proxies)
    assert f"mode: {expected}" in y and "mode: auto" not in y
    assert proxies[0]["alpn"] == ["h2"]


def test_generate_mihomo_yaml_empty():
    assert sub.generate_mihomo_yaml([]) == "proxies: []\n"


def test_generate_mihomo_yaml_escapes_quotes():
    proxies = [{"name": 'a "b c', "type": "vless", "server": "s", "port": 443,
                "uuid": "u", "udp": True, "tls": True, "servername": "s",
                "client-fingerprint": "chrome"}]
    y = sub.generate_mihomo_yaml(proxies)
    assert 'name: "a \\"b c"' in y


def test_generate_mihomo_yaml_quotes_reserved():
    proxies = [{"name": "yes", "type": "vless", "server": "s", "port": 443,
                "uuid": "u", "udp": True, "tls": True, "servername": "s",
                "client-fingerprint": "chrome"}]
    assert 'name: "yes"' in sub.generate_mihomo_yaml(proxies)


def test_write_sub_file_removes_stale_and_keeps_other_prefix(tmp_path):
    stale = tmp_path / "user1_OLD.yaml"
    other = tmp_path / "user1_2_OLD.txt"   # чужой label с тем же префиксом
    stale.write_text("old")
    other.write_text("other")
    sub.write_sub_file(str(tmp_path), "user1", "TOKEN1", ["vless://x"])
    assert not stale.exists()
    assert other.exists()


def test_write_sub_yaml_creates_file(tmp_path):
    path = sub.write_sub_yaml(str(tmp_path), "user one", "TOK", [])
    assert os.path.basename(path) == "userone_TOK.yaml"
    assert os.path.exists(path)


def test_sub_yaml_filename_matches_nginx_regex():
    name = f"{sub.safe_label('Hello World')}_{sub.generate_token()}.yaml"
    assert re.fullmatch(r"/sub/[A-Za-z0-9_-]+_[A-Za-z0-9]+\.yaml", "/sub/" + name)


def test_html_ws_host_has_no_fragment(conf, tmp_path):
    url = sub.generate_ws_url(
        "uuid-1", "1.2.3.4", 443, "/ws", "vpn.example.com",
        "WS user", vless_encryption="none",
    )
    tpl = os.path.join(os.path.dirname(sub.__file__), "..", "data", "user_page.html")
    out = tmp_path / "page.html"
    sub.build_user_html_page(
        tpl, str(out), "uuid-1", "user", "https://vpn.example.com/sub/x.txt",
        [url], domain="vpn.example.com", server_ip="1.2.3.4",
    )
    html = out.read_text(encoding="utf-8")
    m = re.search(r'<div class="cfg-host">(.*?)</div>', html, re.S)
    assert m is not None
    assert m.group(1) == "vpn.example.com"
    assert "#%F0" not in m.group(1)


def test_rebuild_all_sub_files_refreshes_ip_and_flag(conf, tmp_path, monkeypatch):
    from vwn.core import system
    from vwn.modules import users

    users._VWN_FLAG_CACHE = None
    config.vwn_conf_set("SERVER_IP", "1.1.1.1")
    monkeypatch.setattr(system, "get_server_ip", lambda: "2.2.2.2")
    monkeypatch.setattr(users, "get_country_flag", lambda ip: f"flag:{ip}")
    users_file = tmp_path / "users.conf"
    users_file.write_text("uuid-1|user|token\n", encoding="utf-8")
    monkeypatch.setattr(users, "USERS_FILE", str(users_file))
    monkeypatch.setattr(sub, "build_user_sub_file", lambda *a, **k: None)

    count = sub.rebuild_all_sub_files(
        output_dir=str(tmp_path / "sub"), refresh_ip=True,
    )
    assert count == 1
    assert config.vwn_conf_get("SERVER_IP") == "2.2.2.2"
    assert users.get_cached_flag() == "flag:2.2.2.2"
    users._VWN_FLAG_CACHE = None
