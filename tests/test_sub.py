import base64
import os

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


def test_build_user_html_page(tmp_path):
    tpl = tmp_path / "user_page.html"
    tpl.write_text(
        "<html>{{PAGE_TITLE}} {{SUB_URL}} {{CONFIGS_HTML}}</html>"
    )
    out = tmp_path / "out.html"
    sub.build_user_html_page(
        str(tpl), str(out),
        "uuid-1", "user1", "https://vpn.example.com/sub/user1_TOKEN1.txt",
        ["vless://abc@1.2.3.4:443?security=reality#test"],
        page_title="user1 \xb7 vpn.example.com",
        server_ip="1.2.3.4",
    )
    html = out.read_text(encoding="utf-8")
    assert "user1" in html
    assert "vpn.example.com" in html
    assert "vless://abc@1.2.3.4:443?security=reality#test" in html


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
    # gRPC/XHTTP через Reality fallback → порт 443
    assert "vpn.example.com:443" in decoded
    assert "1.2.3.4:443" in decoded
    # .html created
    found_html = list(tmp_path.glob("user1*.html"))
    assert len(found_html) == 1
    html = found_html[0].read_text(encoding="utf-8")
    assert "vpn.example.com" in html


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
                                 mode="xhttp", xhttp_path="/r", xhttp_extra=given)
    assert f"mode={expected}" in u and "mode=auto" not in u
