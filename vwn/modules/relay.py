import json
import os
import re
import urllib.parse

from vwn.core import shell
from vwn.modules._outbound import add_outbound, remove_outbound

TAG = "relay"
CONFIG = "/usr/local/etc/xray/relay.json"


def configure(url: str) -> dict:
    parsed = _parse_url(url)
    _save_config(parsed)
    ob = _build_outbound(parsed)
    _apply_outbound(ob)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        shell.run(["systemctl", "restart", svc], check=False)
    return parsed


def remove() -> None:
    if os.path.isfile(CONFIG):
        os.remove(CONFIG)
    remove_outbound(TAG)
    from vwn.modules._domains import remove_file as _rmd
    _rmd(TAG)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        shell.run(["systemctl", "restart", svc], check=False)


def add_domain(domain: str) -> None:
    from vwn.modules._domains import add_domain as _ad
    _ad(TAG, domain)


def remove_domain(index: int) -> None:
    from vwn.modules._domains import remove_domain as _rd
    _rd(TAG, index)


def list_domains() -> list[str]:
    from vwn.modules._domains import list_domains as _ld
    return _ld(TAG)


def status() -> dict:
    if not os.path.isfile(CONFIG):
        return {"configured": False}
    with open(CONFIG) as f:
        cfg = json.load(f)
    return {"configured": True, **cfg}


def _apply_outbound(ob: dict) -> None:
    import os as _os
    from vwn.core import config as _cfg
    for path in [_os.path.join(_cfg.XRAY_DIR, p)
                 for p in ("config.json", "xhttp.json", "xray-reality.json")]:
        if not _os.path.isfile(path):
            continue
        with open(path) as f:
            xcfg = json.load(f)
        obs = xcfg.setdefault("outbounds", [])
        obs = [o for o in obs if o.get("tag") != TAG]
        obs.insert(-1, ob)
        xcfg["outbounds"] = obs
        with open(path, "w") as f:
            json.dump(xcfg, f, indent=2, ensure_ascii=False)


def _save_config(data: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
    with open(CONFIG, "w") as f:
        json.dump(data, f, indent=2)


def _parse_url(url: str) -> dict:
    if url.startswith("vmess://"):
        import base64
        b64 = url.replace("vmess://", "", 1)
        try:
            padded = b64 + "=" * (4 - len(b64) % 4) if len(b64) % 4 else b64
            decoded = base64.b64decode(padded).decode()
            v = json.loads(decoded)
            return {"protocol": "vmess", "host": v.get("add", ""),
                    "port": v.get("port", 0), "uuid": v.get("id", ""),
                    "security": v.get("tls", "none"), "sni": v.get("sni", ""),
                    "pbk": "", "sid": "", "net": v.get("net", "tcp"),
                    "path": v.get("path", "/"),
                    "ws_host": v.get("host", v.get("add", ""))}
        except Exception as e:
            raise ValueError(f"Failed to parse VMess URL: {e}")

    parsed = urllib.parse.urlparse(url)
    proto = parsed.scheme
    if proto == "socks5":
        proto = "socks"
    host = parsed.hostname or ""
    port = parsed.port or 0
    if not host or not port:
        raise ValueError(f"Invalid relay URL: {url}")
    result = {"protocol": proto, "host": host, "port": port,
              "uuid": "", "security": "none", "sni": "", "pbk": "",
              "sid": "", "net": "tcp", "path": "/", "ws_host": host}
    if proto in ("vless", "trojan"):
        result["uuid"] = parsed.username or ""
        qs = urllib.parse.parse_qs(parsed.query)
        result["security"] = qs.get("security", ["none"])[0]
        result["sni"] = qs.get("sni", [""])[0]
        result["pbk"] = qs.get("pbk", [""])[0]
        result["sid"] = qs.get("sid", [""])[0]
        result["net"] = qs.get("type", ["tcp"])[0]
        result["path"] = qs.get("path", ["/"])[0]
        if qs.get("host"):
            result["ws_host"] = qs["host"][0]
    return result


def _build_outbound(cfg: dict) -> dict:
    proto = cfg["protocol"]
    if proto == "socks":
        return {"tag": TAG, "protocol": "socks",
                "settings": {"servers": [{"address": cfg["host"],
                                          "port": cfg["port"]}]}}
    stream = {"network": cfg["net"], "security": cfg["security"]}
    if cfg["security"] == "reality":
        stream["realitySettings"] = {"serverName": cfg["sni"],
                                      "publicKey": cfg["pbk"],
                                      "shortId": cfg["sid"],
                                      "fingerprint": "chrome"}
    elif cfg["net"] == "ws":
        stream["wsSettings"] = {"path": cfg["path"],
                                "headers": {"Host": cfg["ws_host"]}}
        stream["tlsSettings"] = {"serverName": cfg["sni"],
                                  "allowInsecure": False}
    else:
        stream["tlsSettings"] = {"serverName": cfg["sni"],
                                  "allowInsecure": False}
    if proto == "vmess":
        return {"tag": TAG, "protocol": "vmess",
                "settings": {"vnext": [{"address": cfg["host"],
                                        "port": cfg["port"],
                                        "users": [{"id": cfg["uuid"],
                                                   "alterId": 0,
                                                   "security": "auto"}]}]},
                "streamSettings": stream}
    return {"tag": TAG, "protocol": proto,
            "settings": {"vnext": [{"address": cfg["host"],
                                    "port": cfg["port"],
                                    "users": [{"id": cfg["uuid"],
                                               "encryption": "none",
                                               "flow": ""}]}]},
            "streamSettings": stream}
