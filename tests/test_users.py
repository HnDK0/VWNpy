import os
import json

import pytest

from vwn.core import config
from vwn.modules import users


@pytest.fixture
def conf(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VWN_CONF", str(tmp_path / "vwn.conf"))
    monkeypatch.setattr(config, "NGINX_CONF_DIR", str(tmp_path / "conf.d"))
    monkeypatch.setattr(config, "NGINX_LOOPBACK_PORT", 8443)
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path / "xray"))
    monkeypatch.setattr(users, "USERS_FILE", str(tmp_path / "users.conf"))
    monkeypatch.setattr(users, "SUB_DIR", str(tmp_path / "sub"))
    config.vwn_conf_set("DOMAIN", "vpn.example.com")
    config.vwn_conf_set("UUID", "550e8400-e29b-41d4-a716-446655440000")
    config.vwn_conf_set("SERVER_IP", "1.2.3.4")
    return tmp_path


# ── helpers ────────────────────────────────────────────────

def test_safe_label():
    assert users.safe_label("Hello World!") == "HelloWorld"
    assert users.safe_label("user_123") == "user_123"
    assert users.safe_label("a|b|c") == "abc"
    assert users.safe_label("тест") == ""
    assert users.safe_label("") == ""
    assert users.safe_label("---") == "---"
    assert users.safe_label("a" * 200) == "a" * 200


def test_sub_filename():
    assert users.sub_filename("user1", "ABC123") == "user1_ABC123.txt"
    assert users.sub_filename("Hello World", "tok") == "HelloWorld_tok.txt"
    assert users.sub_filename("", "t") == "_t.txt"


def test_generate_token_length():
    assert len(users.generate_token()) == 32
    assert len(users.generate_token(16)) == 16
    assert len(users.generate_token(64)) == 64
    assert len(users.generate_token(0)) == 0
    tok = users.generate_token()
    assert all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for c in tok)


# ── _read_lines / _write_lines ─────────────────────────────

def test_read_lines_missing(tmp_path):
    assert users._read_lines(str(tmp_path / "nope")) == []


def test_read_lines_skips_blanks(tmp_path):
    p = str(tmp_path / "f")
    with open(p, "w") as f:
        f.write("a|b|c\n\n\nd|e|f\n")
    assert users._read_lines(p) == ["a|b|c", "d|e|f"]


def test_write_lines_creates_file(tmp_path):
    p = str(tmp_path / "out.txt")
    users._write_lines(p, ["a|b|c", "d|e|f"])
    with open(p) as f:
        assert f.read() == "a|b|c\nd|e|f\n"
    perms = os.stat(p).st_mode & 0o777
    assert perms == 0o600 or os.name == "nt"


def test_write_lines_overwrites(tmp_path):
    p = str(tmp_path / "out.txt")
    users._write_lines(p, ["x"])
    users._write_lines(p, ["y", "z"])
    with open(p) as f:
        assert f.read() == "y\nz\n"


def test_write_lines_empty(tmp_path):
    p = str(tmp_path / "out.txt")
    users._write_lines(p, [])
    with open(p) as f:
        assert f.read() == ""


# ── _country_code_to_flag ──────────────────────────────────

def test_country_code_to_flag():
    de = users._country_code_to_flag("DE")
    assert len(de) == 2
    assert ord(de[0]) >= 0x1F1E6
    ru = users._country_code_to_flag("RU")
    assert len(ru) == 2
    globe = users._country_code_to_flag("XYZ")
    assert globe == "\U0001f310"
    assert users._country_code_to_flag("") == "\U0001f310"
    assert users._country_code_to_flag("DEU") == "\U0001f310"
    assert users._country_code_to_flag("d") == "\U0001f310"


# ── get_country_flag ───────────────────────────────────────

def test_get_country_flag_fallback_on_error(monkeypatch):
    import urllib.request
    def _raise(*a, **kw):
        raise OSError("mock network error")
    monkeypatch.setattr(urllib.request, "urlopen", _raise)

    flag = users.get_country_flag("")
    assert flag == "\U0001f310"

    flag = users.get_country_flag("999.999.999.999")
    assert flag == "\U0001f310"


# ── get_cached_flag ────────────────────────────────────────

def test_get_cached_flag_no_ip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VWN_CONF", str(tmp_path / "empty.conf"))
    monkeypatch.setattr(users, "_VWN_FLAG_CACHE", None)
    flag = users.get_cached_flag()
    assert flag == "\U0001f310"


def test_get_cached_flag_uses_cache(conf, monkeypatch):
    monkeypatch.setattr(users, "_VWN_FLAG_CACHE", None)
    flag = users.get_cached_flag()
    assert flag == "\U0001f310" or len(flag) == 2


# ── _read_json / _write_json ───────────────────────────────

def test_read_json_missing(tmp_path):
    assert users._read_json(str(tmp_path / "nope.json")) is None


def test_read_json_valid(tmp_path):
    p = str(tmp_path / "test.json")
    with open(p, "w") as f:
        json.dump({"a": 1}, f)
    assert users._read_json(p) == {"a": 1}


def test_write_json(tmp_path):
    p = str(tmp_path / "out.json")
    users._write_json(p, {"x": [1, 2]})
    with open(p) as f:
        assert json.load(f) == {"x": [1, 2]}


# ── get_active_modes_suffix ────────────────────────────────

def test_get_active_modes_suffix_no_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path / "empty"))
    assert users.get_active_modes_suffix() == ""


def test_get_active_modes_suffix_no_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    os.makedirs(str(tmp_path), exist_ok=True)
    with open(str(tmp_path / "config.json"), "w") as f:
        json.dump({"routing": {"rules": []}}, f)
    assert users.get_active_modes_suffix() == ""


def test_get_active_modes_suffix_with_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path))
    os.makedirs(str(tmp_path), exist_ok=True)
    with open(str(tmp_path / "config.json"), "w") as f:
        json.dump({
            "routing": {
                "rules": [
                    {"type": "field", "port": "0-65535", "outboundTag": "warp"},
                    {"type": "field", "port": "0-65535", "outboundTag": "tor"},
                ]
            }
        }, f)
    suffix = users.get_active_modes_suffix()
    assert "\U0001f310" in suffix
    assert "\u2601\ufe0f" in suffix  # WARP cloud
    assert "\U0001f9c5" in suffix  # Tor onion


# ── get_config_name ────────────────────────────────────────

def test_get_config_name_ws(conf, monkeypatch):
    monkeypatch.setattr(users, "_VWN_FLAG_CACHE", "\U0001f310")
    name = users.get_config_name("WS", "test")
    assert "VL-WS" in name
    assert "test" in name
    assert "\U0001f310" in name


def test_get_config_name_reality(conf, monkeypatch):
    monkeypatch.setattr(users, "_VWN_FLAG_CACHE", "\U0001f310")
    monkeypatch.setattr(config, "VWN_CONF", str(conf / "vwn.conf"))
    name = users.get_config_name("Reality", "test")
    assert "VL-Reality" in name


def test_get_config_name_reality_xhttp(conf, monkeypatch):
    monkeypatch.setattr(users, "_VWN_FLAG_CACHE", "\U0001f310")
    config.vwn_conf_set("REALITY_MODE", "xhttp")
    name = users.get_config_name("Reality", "test")
    assert "VL-Reality-XHTTP" in name


def test_get_config_name_xhttp(conf, monkeypatch):
    monkeypatch.setattr(users, "_VWN_FLAG_CACHE", "\U0001f310")
    name = users.get_config_name("XHTTP", "test")
    assert "VL-XHTTP" in name


def test_get_config_name_unknown_type(conf, monkeypatch):
    monkeypatch.setattr(users, "_VWN_FLAG_CACHE", "\U0001f310")
    name = users.get_config_name("Custom", "x")
    assert "VL-Custom" in name


def test_get_config_name_empty_label(conf, monkeypatch):
    monkeypatch.setattr(users, "_VWN_FLAG_CACHE", "\U0001f310")
    name = users.get_config_name("WS", "")
    assert name.endswith(" \U0001f310")
    assert "VL-WS" in name


# ── init_users_file ────────────────────────────────────────

def test_init_users_file_from_uuid(conf, tmp_path):
    assert not os.path.isfile(str(tmp_path / "users.conf"))
    users.init_users_file()
    assert os.path.isfile(str(tmp_path / "users.conf"))
    with open(str(tmp_path / "users.conf")) as f:
        line = f.read().strip()
    parts = line.split("|")
    assert parts[0] == "550e8400-e29b-41d4-a716-446655440000"
    assert len(parts) == 3
    assert len(parts[2]) == 32


def test_init_users_file_idempotent(conf, tmp_path):
    users.init_users_file()
    users.init_users_file()
    with open(str(tmp_path / "users.conf")) as f:
        lines = f.readlines()
    assert len(lines) == 1


def test_init_users_file_no_uuid(tmp_path, monkeypatch):
    monkeypatch.setattr(users, "USERS_FILE", str(tmp_path / "users.conf"))
    monkeypatch.setattr(config, "VWN_CONF", str(tmp_path / "empty.conf"))
    users.init_users_file()
    assert not os.path.isfile(str(tmp_path / "users.conf"))


def test_init_users_file_perms(conf, tmp_path):
    users.init_users_file()
    perms = os.stat(str(tmp_path / "users.conf")).st_mode & 0o777
    assert perms == 0o600 or os.name == "nt"


# ── list_users ─────────────────────────────────────────────

def test_list_users_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(users, "USERS_FILE", str(tmp_path / "nope"))
    assert users.list_users() == []


def test_list_users(conf, tmp_path):
    users.init_users_file()
    lst = users.list_users()
    assert len(lst) == 1
    assert lst[0]["uuid"] == "550e8400-e29b-41d4-a716-446655440000"
    assert lst[0]["label"].startswith("default_")
    assert len(lst[0]["token"]) == 32


def test_list_users_skips_partial_lines(tmp_path, monkeypatch):
    p = str(tmp_path / "users.conf")
    monkeypatch.setattr(users, "USERS_FILE", p)
    users._write_lines(p, [
        "full-uuid|label|token",
        "uuid-only",
        "uuid|label",
    ])
    lst = users.list_users()
    assert len(lst) == 2
    assert lst[0]["uuid"] == "full-uuid"
    assert lst[0]["label"] == "label"
    assert lst[1]["uuid"] == "uuid"
    assert lst[1]["label"] == "label"


def test_list_users_extra_parts_ignored(tmp_path, monkeypatch):
    p = str(tmp_path / "users.conf")
    monkeypatch.setattr(users, "USERS_FILE", p)
    users._write_lines(p, ["a|b|c|d|e"])
    lst = users.list_users()
    assert len(lst) == 1
    assert lst[0]["uuid"] == "a"
    assert lst[0]["label"] == "b"
    assert lst[0]["token"] == "c|d|e"


# ── uuid/label/token helpers ───────────────────────────────

def test_line_helpers_invalid(conf, tmp_path):
    users.init_users_file()
    assert users._uuid_by_line(0) == ""
    assert users._uuid_by_line(99) == ""
    assert users._label_by_line(99) == ""
    assert users._token_by_line(99) == ""


def test_line_helpers_valid(conf, tmp_path):
    users.init_users_file()
    uuid = users._uuid_by_line(1)
    label = users._label_by_line(1)
    token = users._token_by_line(1)
    assert uuid == "550e8400-e29b-41d4-a716-446655440000"
    assert label.startswith("default_")
    assert len(token) == 32


# ── users_count ────────────────────────────────────────────

def test_users_count(conf, tmp_path):
    assert users.users_count() == 0
    users.init_users_file()
    assert users.users_count() == 1
    users.add_user("two")
    assert users.users_count() == 2


# ── add_user ───────────────────────────────────────────────

def test_add_user(conf, tmp_path):
    users.init_users_file()
    r = users.add_user("testuser")
    assert r["uuid"] is not None
    assert r["label"] == "testuser"
    assert len(r["token"]) == 32
    lst = users.list_users()
    assert len(lst) == 2
    assert lst[1]["label"] == "testuser"


def test_add_user_auto_label(conf, tmp_path):
    users.init_users_file()
    r = users.add_user()
    assert r["label"].startswith("user")
    r2 = users.add_user()
    assert r2["label"] not in (r["label"],)  # unique


def test_add_user_with_pipe_in_label(conf, tmp_path):
    users.init_users_file()
    r = users.add_user("a|b")
    assert r["label"] == "ab"
    assert "|" not in r["label"]


def test_add_user_unique_uuid(conf, tmp_path):
    users.init_users_file()
    r1 = users.add_user("u1")
    r2 = users.add_user("u2")
    assert r1["uuid"] != r2["uuid"]


def test_add_user_unique_token(conf, tmp_path):
    users.init_users_file()
    r1 = users.add_user("u1")
    r2 = users.add_user("u2")
    assert r1["token"] != r2["token"]


def test_add_user_many(tmp_path, monkeypatch):
    monkeypatch.setattr(users, "USERS_FILE", str(tmp_path / "users.conf"))
    monkeypatch.setattr(users, "SUB_DIR", str(tmp_path / "sub"))
    monkeypatch.setattr(config, "VWN_CONF", str(tmp_path / "vwn.conf"))
    monkeypatch.setattr(config, "XRAY_DIR", str(tmp_path / "xray"))
    config.vwn_conf_set("DOMAIN", "x.com")
    config.vwn_conf_set("UUID", "u1")
    config.vwn_conf_set("SERVER_IP", "1.1.1.1")
    users.init_users_file()
    for i in range(100):
        users.add_user(f"u{i}")
    assert users.users_count() == 101


# ── remove_user ───────────────────────────────────────────

def test_remove_user(conf, tmp_path):
    users.init_users_file()
    users.add_user("testuser")
    assert len(users.list_users()) == 2
    ok = users.remove_user(2)
    assert ok
    assert len(users.list_users()) == 1


def test_remove_user_first(conf, tmp_path):
    users.init_users_file()
    users.add_user("two")
    assert len(users.list_users()) == 2
    users.remove_user(1)
    lst = users.list_users()
    assert len(lst) == 1
    assert lst[0]["label"] == "two"


def test_remove_user_invalid(conf, tmp_path):
    users.init_users_file()
    ok = users.remove_user(99)
    assert not ok
    assert users.users_count() == 1


def test_remove_user_zero(conf, tmp_path):
    users.init_users_file()
    assert not users.remove_user(0)


def test_remove_user_cleans_sub_files(conf, tmp_path):
    users.init_users_file()
    u = users.add_user("delete_me")
    os.makedirs(str(tmp_path / "sub"), exist_ok=True)
    safe = users.safe_label("delete_me")
    for suffix in ["_xxx.txt", "_yyy.html"]:
        open(str(tmp_path / "sub" / (safe + suffix)), "w").close()
    users.remove_user(2)
    remaining = os.listdir(str(tmp_path / "sub"))
    assert all("delete_me" not in f for f in remaining)


# ── rename_user ───────────────────────────────────────────

def test_rename_user(conf, tmp_path):
    users.init_users_file()
    users.add_user("oldname")
    ok = users.rename_user(2, "newname")
    assert ok
    assert users.list_users()[1]["label"] == "newname"


def test_rename_user_empty(conf, tmp_path):
    users.init_users_file()
    users.add_user("old")
    assert not users.rename_user(2, "")


def test_rename_user_invalid_index(conf, tmp_path):
    users.init_users_file()
    assert not users.rename_user(99, "x")


def test_rename_user_same_label(conf, tmp_path):
    users.init_users_file()
    ok = users.rename_user(1, users.list_users()[0]["label"])
    assert ok


def test_rename_user_cleans_old_sub_files(conf, tmp_path, monkeypatch):
    monkeypatch.setattr(users, "apply_users_to_configs", lambda: None)
    import vwn.modules.sub as sub
    monkeypatch.setattr(sub, "build_user_sub_file", lambda *a, **kw: None)
    users.init_users_file()
    u = users.add_user("aaa")
    subdir = str(tmp_path / "sub")
    monkeypatch.setattr(users, "SUB_DIR", subdir)
    os.makedirs(subdir, exist_ok=True)
    for suffix in ["_t.txt", "_t.html"]:
        open(str(tmp_path / "sub" / ("aaa" + suffix)), "w").close()
    users.rename_user(2, "bbb")
    remaining = os.listdir(subdir)
    assert all("aaa" not in f for f in remaining)


# ── rekey_user ────────────────────────────────────────────

def test_rekey_user(conf, tmp_path):
    users.init_users_file()
    old_uuid = users.list_users()[0]["uuid"]
    new_uuid = users.rekey_user(1)
    assert new_uuid is not None
    assert new_uuid != old_uuid
    assert len(new_uuid) == 36
    assert users.list_users()[0]["uuid"] == new_uuid


def test_rekey_user_invalid(conf, tmp_path):
    assert users.rekey_user(99) is None


def test_rekey_user_invalid_zero(conf, tmp_path):
    assert users.rekey_user(0) is None


def test_rekey_user_multi(conf, tmp_path):
    users.init_users_file()
    users.add_user("a")
    users.add_user("b")
    uid2 = users.list_users()[1]["uuid"]
    uid3 = users.list_users()[2]["uuid"]
    users.rekey_user(2)
    assert users.list_users()[1]["uuid"] != uid2
    assert users.list_users()[2]["uuid"] == uid3  # untouched


# ── reissue_token ─────────────────────────────────────────

def test_reissue_token(conf, tmp_path):
    users.init_users_file()
    old_token = users.list_users()[0]["token"]
    new_token = users.reissue_token(1)
    assert new_token is not None
    assert new_token != old_token
    assert len(new_token) == 32


def test_reissue_token_invalid(conf, tmp_path):
    assert users.reissue_token(99) is None


def test_reissue_token_adds_missing(conf, tmp_path, monkeypatch):
    p = str(tmp_path / "users.conf")
    monkeypatch.setattr(users, "USERS_FILE", p)
    users._write_lines(p, ["u|l"])
    new_tok = users.reissue_token(1)
    assert new_tok is not None
    assert users.list_users()[0]["token"] == new_tok


# ── get_sub_url ───────────────────────────────────────────

def test_get_sub_url(conf, tmp_path):
    url = users.get_sub_url("user1", "TOKEN1")
    assert url == "https://vpn.example.com/sub/user1_TOKEN1.txt"


def test_get_sub_url_no_domain(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "VWN_CONF", str(tmp_path / "empty.conf"))
    url = users.get_sub_url("user1", "TOKEN1")
    assert url is None


def test_get_sub_url_special_label(conf, tmp_path):
    url = users.get_sub_url("Hello World", "tok")
    assert url == "https://vpn.example.com/sub/HelloWorld_tok.txt"


# ── apply_users_to_configs ────────────────────────────────

def test_apply_no_users(tmp_path, monkeypatch):
    monkeypatch.setattr(users, "USERS_FILE", str(tmp_path / "empty"))
    monkeypatch.setattr(users, "list_users", lambda: [])
    users.apply_users_to_configs()


def test_apply_writes_to_ws_config(conf, tmp_path, monkeypatch):
    os.makedirs(str(tmp_path / "xray"), exist_ok=True)
    ws = str(tmp_path / "xray" / "config.json")
    with open(ws, "w") as f:
        json.dump({"inbounds": [{"settings": {"clients": []}}]}, f)
    users.init_users_file()
    users.apply_users_to_configs()
    with open(ws) as f:
        cfg = json.load(f)
    assert len(cfg["inbounds"][0]["settings"]["clients"]) == 1


def test_apply_writes_to_xhttp_config(conf, tmp_path, monkeypatch):
    os.makedirs(str(tmp_path / "xray"), exist_ok=True)
    xh = str(tmp_path / "xray" / "xhttp.json")
    with open(xh, "w") as f:
        json.dump({"inbounds": [{"settings": {"clients": []}}]}, f)
    users.init_users_file()
    users.apply_users_to_configs()
    with open(xh) as f:
        cfg = json.load(f)
    assert len(cfg["inbounds"][0]["settings"]["clients"]) == 1


def test_apply_writes_to_reality_config(conf, tmp_path, monkeypatch):
    os.makedirs(str(tmp_path / "xray"), exist_ok=True)
    rl = str(tmp_path / "xray" / "xray-reality.json")
    with open(rl, "w") as f:
        json.dump({"inbounds": [{"settings": {"clients": []}}]}, f)
    users.init_users_file()
    users.apply_users_to_configs()
    with open(rl) as f:
        cfg = json.load(f)
    assert len(cfg["inbounds"][0]["settings"]["clients"]) == 1
    assert "flow" in cfg["inbounds"][0]["settings"]["clients"][0]


def test_apply_multi_user(conf, tmp_path, monkeypatch):
    os.makedirs(str(tmp_path / "xray"), exist_ok=True)
    ws = str(tmp_path / "xray" / "config.json")
    with open(ws, "w") as f:
        json.dump({"inbounds": [{"settings": {"clients": []}}]}, f)
    users.init_users_file()
    users.add_user("second")
    users.apply_users_to_configs()
    with open(ws) as f:
        cfg = json.load(f)
    assert len(cfg["inbounds"][0]["settings"]["clients"]) == 2


def test_apply_no_rules_for_flow(conf, tmp_path, monkeypatch):
    os.makedirs(str(tmp_path / "xray"), exist_ok=True)
    ws = str(tmp_path / "xray" / "config.json")
    with open(ws, "w") as f:
        json.dump({"inbounds": [{"settings": {"clients": []}}]}, f)
    users.init_users_file()
    users.apply_users_to_configs()
    with open(ws) as f:
        cfg = json.load(f)
    assert "flow" not in cfg["inbounds"][0]["settings"]["clients"][0]


# ── Edge cases: write consistency ─────────────────────────

def test_write_lines_atomic(tmp_path):
    p = str(tmp_path / "target.txt")
    users._write_lines(p, ["line1"])
    users._write_lines(p, ["line2"])
    with open(p) as f:
        assert f.read().strip() == "line2"


def test_write_lines_no_partial_writes(tmp_path):
    p = str(tmp_path / "target.txt")
    users._write_lines(p, ["good"])
    with open(p, "w") as f:
        f.write("corrupt")
    # даже если tmp-файл не создастся, os.replace не удалит оригинал
    users._write_lines(p, ["final"])
    with open(p) as f:
        assert f.read().strip() == "final"
