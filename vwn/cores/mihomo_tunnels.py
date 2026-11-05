"""Трансляция Xray outbounds/rules/inbounds в mihomo-конфиг.

Существующие модули туннелей (WARP/Psiphon/Tor/Relay/_domains) продолжают
писать Xray-JSON. Mihomo backend читает эти же JSON и переводит состояние
в proxies/rules/listeners, поэтому переключение ядра не теряет туннели.
"""

from __future__ import annotations

import json
import os

from vwn.core import config

_SKIP_TAGS = {"", "block", "free", "dns-out"}


def _configs() -> list[dict]:
    out = []
    from vwn.core import tunnel_state
    paths = [os.path.join(config.XRAY_DIR, name)
             for name in config.XRAY_CONFIG_FILES]
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                out.append(json.load(fh))
        except (OSError, ValueError):
            continue
    out.append(tunnel_state.load())
    return out


def _wireguard_proxy(tag: str, settings: dict) -> dict:
    peer = (settings.get("peers") or [{}])[0]
    endpoint = peer.get("endpoint") or ""
    host, _, port = endpoint.rpartition(":")
    try:
        port_i = int(port)
    except ValueError:
        port_i = 0
    address = (settings.get("address") or [""])[0]
    proxy = {
        "name": tag,
        "type": "wireguard",
        "private-key": settings.get("secretKey", ""),
        "server": host,
        "port": port_i,
        "public-key": peer.get("publicKey", ""),
        "ip": address.split("/", 1)[0],
        "udp": True,
    }
    if settings.get("reserved"):
        proxy["reserved"] = settings["reserved"]
    return proxy


def _vless_vmess_proxy(tag: str, protocol: str, outbound: dict) -> dict:
    settings = outbound.get("settings", {})
    vnext = (settings.get("vnext") or [{}])[0]
    user = (vnext.get("users") or [{}])[0]
    proxy = {
        "name": tag,
        "type": protocol,
        "server": vnext.get("address", ""),
        "port": vnext.get("port", 0),
        "uuid": user.get("id", ""),
        "udp": True,
    }
    if user.get("flow"):
        proxy["flow"] = user["flow"]
    if user.get("encryption") and user["encryption"] != "none":
        proxy["encryption"] = user["encryption"]
    stream = outbound.get("streamSettings", {}) or {}
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")
    reality = stream.get("realitySettings", {}) or {}
    tls = stream.get("tlsSettings", {}) or {}
    if security == "reality":
        proxy["tls"] = True
        proxy["servername"] = reality.get("serverName", "")
        proxy["client-fingerprint"] = reality.get("fingerprint") or "chrome"
        proxy["reality-opts"] = {
            "public-key": reality.get("publicKey", ""),
            "short-id": reality.get("shortId", ""),
        }
    elif security == "tls":
        proxy["tls"] = True
        proxy["servername"] = tls.get("serverName", "")
        proxy["skip-cert-verify"] = bool(tls.get("allowInsecure"))
        proxy["client-fingerprint"] = tls.get("fingerprint") or "chrome"
    if network == "ws":
        ws = stream.get("wsSettings", {}) or {}
        proxy["network"] = "ws"
        proxy["ws-opts"] = {
            "path": ws.get("path", "/"),
            "headers": ws.get("headers", {}) or {},
        }
    elif network == "grpc":
        grpc = stream.get("grpcSettings", {}) or {}
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": grpc.get("serviceName", "")}
    elif network in ("tcp", "raw"):
        proxy["network"] = "tcp"
    elif network == "httpupgrade":
        hu = stream.get("httpupgradeSettings", {}) or {}
        proxy["network"] = "ws"
        proxy["ws-opts"] = {
            "path": hu.get("path", "/"),
            "headers": {"Host": hu.get("host", "")},
        }
    return proxy


def _socks_proxy(tag: str, outbound: dict) -> dict:
    server = (outbound.get("settings", {}).get("servers") or [{}])[0]
    return {
        "name": tag, "type": "socks5",
        "server": server.get("address", "127.0.0.1"),
        "port": server.get("port", 0),
        "udp": True,
    }


def proxies() -> list[dict]:
    """Уникальные outbound'ы Xray, кроме служебных."""
    configs = _configs()
    socks_by_tag: dict[str, dict] = {}
    for cfg in configs:
        for outbound in cfg.get("outbounds", []):
            tag = outbound.get("tag", "")
            if (outbound.get("protocol") != "socks" or not tag
                    or tag in _SKIP_TAGS or tag in socks_by_tag):
                continue
            socks_by_tag[tag] = _socks_proxy(tag, outbound)

    result: list[dict] = []
    seen: set[str] = set()
    for cfg in configs:
        for outbound in cfg.get("outbounds", []):
            tag = outbound.get("tag", "")
            if not tag or tag in _SKIP_TAGS or tag in seen:
                continue
            protocol = outbound.get("protocol", "")
            if protocol == "socks":
                proxy = socks_by_tag.get(tag)
                if not proxy:
                    continue
            elif protocol == "wireguard":
                proxy = _wireguard_proxy(tag, outbound.get("settings", {}))
            elif protocol in ("vless", "vmess"):
                proxy = _vless_vmess_proxy(tag, protocol, outbound)
            elif protocol == "freedom":
                sockopt = ((outbound.get("settings", {}) or {}).get("sockopt")
                           or (outbound.get("streamSettings", {}) or {}).get("sockopt")
                           or {})
                dialer = sockopt.get("dialerProxy", "")
                interface = sockopt.get("interface", "")
                if interface:
                    proxy = {"name": tag, "type": "direct",
                             "interface-name": interface}
                elif dialer in socks_by_tag:
                    proxy = dict(socks_by_tag[dialer])
                    proxy["name"] = tag
                elif dialer.startswith("socks5://"):
                    hp = dialer.split("://", 1)[1]
                    host, _, port = hp.rpartition(":")
                    proxy = {"name": tag, "type": "socks5", "server": host,
                             "port": int(port or 0), "udp": True}
                else:
                    continue
            else:
                continue
            result.append(proxy)
            seen.add(tag)
    return result


def _domain_conds(entries: list[str]) -> list[str]:
    out = []
    for entry in entries:
        if entry.startswith("geosite:"):
            out.append(f"GEOSITE,{entry.split(':', 1)[1]}")
        elif entry.startswith("domain:"):
            out.append(f"DOMAIN-SUFFIX,{entry.split(':', 1)[1]}")
        elif entry.startswith("full:"):
            out.append(f"DOMAIN,{entry.split(':', 1)[1]}")
        elif entry.startswith("keyword:"):
            out.append(f"DOMAIN-KEYWORD,{entry.split(':', 1)[1]}")
        elif entry.startswith("regexp:"):
            out.append(f"DOMAIN-REGEX,{entry.split(':', 1)[1]}")
        elif entry.startswith("ext:"):
            continue
        else:
            out.append(f"DOMAIN-SUFFIX,{entry}")
    return out


def _ip_conds(entries: list[str]) -> list[str]:
    out = []
    for entry in entries:
        if entry.startswith("geoip:private"):
            out.append("GEOIP,LAN")
        elif entry.startswith("geoip:"):
            out.append(f"GEOIP,{entry.split(':', 1)[1].upper()}")
        elif entry.startswith("ext:"):
            continue
        else:
            out.append(f"IP-CIDR,{entry}")
    return out


def _port_conds(port) -> list[str]:
    if not port or str(port) == "0-65535":
        return []
    parts = [part for part in str(port).replace(",", " ").split() if part]
    if len(parts) == 1:
        return [f"DST-PORT,{parts[0]}"]
    inner = ",".join(f"(DST-PORT,{part})" for part in parts)
    return [f"OR,({inner})"]


def _rule_line(conds: list[str], target: str, no_resolve: bool = False) -> str:
    if not conds:
        return f"MATCH,{target}"
    if len(conds) == 1:
        line = f"{conds[0]},{target}"
    else:
        inner = ",".join(f"({c})" for c in conds)
        line = f"AND,({inner}),{target}"
    return line + (",no-resolve" if no_resolve else "")


def rules(proxy_tags: set[str]) -> list[str]:
    """Перевести routing.rules Xray в mihomo-правила (порядок сохраняется)."""
    result: list[str] = []
    match_rules: list[str] = []

    def target_of(rule: dict) -> "str | None":
        tag = rule.get("outboundTag", "")
        if tag == "block":
            return "REJECT"
        if tag == "free":
            return "DIRECT"
        if tag in proxy_tags:
            return tag
        return None

    def add(line: str) -> None:
        if line.startswith("MATCH,"):
            match_rules.append(line)
        elif line not in result:
            result.append(line)

    for cfg in _configs():
        for rule in cfg.get("routing", {}).get("rules", []):
            target = target_of(rule)
            if not target:
                continue
            if rule.get("protocol"):
                # bittorrent-правила у mihomo нет
                continue

            base: list[str] = []
            names = rule.get("inboundTag") or []
            if isinstance(names, str):
                names = [names]
            if names:
                if len(names) == 1:
                    base.append(f"IN-NAME,{names[0]}")
                else:
                    inner = ",".join(f"(IN-NAME,{n})" for n in names)
                    base.append(f"OR,({inner})")
            if rule.get("network"):
                base.append(f"NETWORK,{rule['network']}")
            base.extend(_port_conds(rule.get("port")))

            domains = _domain_conds(rule.get("domain") or [])
            ips = _ip_conds(rule.get("ip") or [])
            if not domains and not ips:
                if base:
                    add(_rule_line(base, target))
                elif str(rule.get("port") or "") == "0-65535":
                    add(_rule_line([], target))
                continue
            for cond in domains:
                add(_rule_line([cond] + base, target))
            for cond in ips:
                add(_rule_line([cond] + base, target, no_resolve=True))

    # MATCH всегда последний; при нескольких оставляем последний.
    if match_rules:
        result = [r for r in result if not r.startswith("MATCH,")]
        result.append(match_rules[-1])
    return result


def listeners() -> list[dict]:
    """SOCKS-inbound'ы Xray (WARP health-check) как mihomo listeners."""
    result = []
    seen = set()
    for cfg in _configs():
        for inbound in cfg.get("inbounds", []):
            if inbound.get("protocol") != "socks":
                continue
            key = (inbound.get("tag", ""), inbound.get("port"))
            if key in seen:
                continue
            seen.add(key)
            name = inbound.get("tag") or f"socks-{inbound.get('port')}"
            result.append({
                "name": name,
                "type": "socks",
                "listen": inbound.get("listen", "127.0.0.1"),
                "port": inbound.get("port", 0),
            })
    return result


def state() -> tuple[list[dict], list[str], list[dict]]:
    px = proxies()
    tags = {p["name"] for p in px}
    return px, rules(tags), listeners()
