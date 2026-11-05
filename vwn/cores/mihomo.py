"""mihomo backend: YAML-конфиги, unit-файлы, валидация."""

from __future__ import annotations

import json
import os
import shutil
import tempfile

from vwn.core import config, shell
from vwn.modules import users as users_mod

from .base import ProvisionParams
from . import keystore

_UNIT_TPL = """[Unit]
Description=VWN mihomo {proto}
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=mihomo
ExecStartPre={bin} -t -f {config} -d {home}
ExecStart={bin} -d {home} -f {config}
Restart=on-failure
RestartPreventExitStatus=23
RestartSec=3
StartLimitBurst=5
LimitNPROC=10000
LimitNOFILE=1000000
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""

_SERVICE_NAMES = {
    "reality": "mihomo-reality",
    "grpc": "mihomo-grpc",
    "xhttp": "mihomo-xhttp",
    "ws": "mihomo-ws",
}
_CONFIG_NAMES = {
    "reality": "reality.yaml",
    "grpc": "grpc.yaml",
    "xhttp": "xhttp.yaml",
    "ws": "ws.yaml",
}


def _scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def _yaml_dump(obj, indent: int = 0) -> list[str]:
    lines: list[str] = []
    sp = "  " * indent
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, dict):
                if value:
                    lines.append(f"{sp}{key}:")
                    lines.extend(_yaml_dump(value, indent + 1))
                else:
                    lines.append(f"{sp}{key}: {{}}")
            elif isinstance(value, list):
                if value:
                    lines.append(f"{sp}{key}:")
                    lines.extend(_yaml_dump(value, indent + 1))
                else:
                    lines.append(f"{sp}{key}: []")
            else:
                lines.append(f"{sp}{key}: {_scalar(value)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                if item:
                    lines.append(f"{sp}-")
                    lines.extend(_yaml_dump(item, indent + 1))
                else:
                    lines.append(f"{sp}- {{}}")
            elif isinstance(item, list):
                lines.append(f"{sp}-")
                lines.extend(_yaml_dump(item, indent + 1))
            else:
                lines.append(f"{sp}- {_scalar(item)}")
    return lines


def _write_config(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = "\n".join(_yaml_dump(data)) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".mihomo-", dir=os.path.dirname(path))
    try:
        os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    try:
        os.chmod(path, 0o640)
        if os.geteuid() == 0:
            import grp
            gid = grp.getgrnam("mihomo").gr_gid
            os.chown(path, 0, gid)
    except (OSError, KeyError):
        pass


def _dns() -> dict:
    v4_primary = config.vwn_conf_get("DNS_V4_PRIMARY") or "1.1.1.1"
    v4_fallback = config.vwn_conf_get("DNS_V4_FALLBACK") or "9.9.9.9"
    v6_primary = config.vwn_conf_get("DNS_V6_PRIMARY") or ""
    servers = [v4_primary, v4_fallback]
    if v6_primary:
        servers.append(v6_primary)
    dns = {
        "enable": True,
        "enhanced-mode": "redir-host",
        "nameserver": servers,
    }
    if v6_primary:
        dns["fallback"] = [v6_primary]
    return dns


def _rules() -> list[str]:
    return [
        "GEOSITE,category-ads-all,REJECT",
        "GEOIP,LAN,REJECT,no-resolve",
        "DST-PORT,25,REJECT",
        "DST-PORT,587,REJECT",
        "DST-PORT,465,REJECT",
        "DST-PORT,2525,REJECT",
        "MATCH,DIRECT",
    ]


def _base_config(proxies: "list[dict] | None" = None,
                 extra_rules: "list[str] | None" = None,
                 extra_listeners: "list[dict] | None" = None) -> dict:
    v6 = bool(config.vwn_conf_get("DNS_V6_PRIMARY"))
    data = {
        "log-level": config.vwn_conf_get("MIHOMO_LOG_LEVEL") or "warning",
        "mode": "rule",
        "ipv6": v6,
        "external-controller": "",
        "allow-lan": False,
        "mixed-port": 0,
        "socks-port": 0,
        "redir-port": 0,
        "tproxy-port": 0,
        "profile": {"store-selected": False, "store-fake-ip": False},
        "dns": _dns(),
        "sniffer": {"enable": True, "override-destination": True},
        "rules": _rules(),
    }
    if proxies:
        data["proxies"] = proxies
    if extra_rules:
        rules = [r for r in data["rules"] if not r.startswith("MATCH,")]
        for rule in extra_rules:
            if rule not in rules:
                rules.append(rule)
        match = [r for r in rules if r.startswith("MATCH,")]
        if match:
            rules = [r for r in rules if not r.startswith("MATCH,")] + [match[-1]]
        else:
            rules.append("MATCH,DIRECT")
        data["rules"] = rules
    if extra_listeners:
        data["listeners"] = list(extra_listeners)
    return data


def _usernames(users: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result = []
    for user in users:
        label = users_mod.safe_label(user.get("label") or "") or "user"
        name = label
        i = 1
        while name in seen:
            i += 1
            name = f"{label}-{i}"
        seen.add(name)
        result.append({"username": name, "uuid": user.get("uuid", ""),
                       "label": user.get("label") or name})
    return result


def _listener_users(params: ProvisionParams, users: list[dict], flow: bool) -> list[dict]:
    out = []
    for user in _usernames(users):
        entry = {"username": user["username"], "uuid": user["uuid"]}
        if flow:
            entry["flow"] = "xtls-rprx-vision"
        out.append(entry)
    return out


def _reality_listener(params: ProvisionParams, users: list[dict]) -> dict:
    flow = params.reality_mode == "tcp"
    listener = {
        "name": "reality-in",
        "type": "vless",
        "listen": "0.0.0.0",
        "port": params.reality_port,
        "users": _listener_users(params, users, flow),
        "reality-config": {
            "dest": f"127.0.0.1:{params.fallback_port}",
            "proxy": "DIRECT",
            "private-key": params.private_key,
            "short-id": [params.short_id],
            "server-names": [params.domain],
        },
    }
    if not flow:
        listener["xhttp-config"] = {"path": params.xhttp_path, "mode": "auto"}
    return listener


def _loopback_listener(kind: str, params: ProvisionParams,
                       users: list[dict]) -> dict:
    ports = {
        "grpc": config.XRAY_GRPC_PORT,
        "xhttp": config.XRAY_XHTTP_PORT,
        "ws": config.XRAY_WS_PORT,
    }
    listener = {
        "name": f"{kind}-in",
        "type": "vless",
        "listen": "127.0.0.1",
        "port": ports[kind],
        "allow-insecure": True,
        "users": _listener_users(params, users, flow=False),
    }
    if params.decryption and params.decryption != "none":
        listener["decryption"] = params.decryption
    if kind == "grpc":
        listener["grpc-service-name"] = params.grpc_service
    elif kind == "xhttp":
        listener["xhttp-config"] = {"path": params.xhttp_path, "mode": "auto"}
    elif kind == "ws":
        listener["ws-path"] = params.ws_path
    return listener


def _link_geo(home: str) -> None:
    os.makedirs(home, exist_ok=True)
    for src, dst in (
        ("/usr/local/share/xray/geoip.dat", "GeoIP.dat"),
        ("/usr/local/share/xray/geosite.dat", "GeoSite.dat"),
    ):
        target = os.path.join(home, dst)
        try:
            if os.path.exists(src) and not os.path.lexists(target):
                os.symlink(src, target)
        except OSError:
            pass


def _ensure_dirs() -> None:
    os.makedirs(config.MIHOMO_DIR, exist_ok=True)
    for key in _CONFIG_NAMES:
        home = os.path.join(config.MIHOMO_DIR, key)
        os.makedirs(home, exist_ok=True)
        _link_geo(home)
    if os.geteuid() == 0:
        try:
            import grp
            gid = grp.getgrnam("mihomo").gr_gid
            os.chown(config.MIHOMO_DIR, 0, gid)
            os.chmod(config.MIHOMO_DIR, 0o750)
            for key in _CONFIG_NAMES:
                home = os.path.join(config.MIHOMO_DIR, key)
                os.chown(home, gid, gid)
                os.chmod(home, 0o750)
        except (OSError, KeyError):
            pass


def _render_all(params: ProvisionParams, users: list[dict]) -> dict[str, str]:
    from . import mihomo_tunnels

    _ensure_dirs()
    proxies, extra_rules, socks_listeners = mihomo_tunnels.state()
    disabled = _disabled_protocols()
    socks_key = next(
        (k for k in ("reality", "grpc", "xhttp", "ws") if k not in disabled),
        None,
    )
    files = {
        "reality": _reality_listener(params, users),
        "grpc": _loopback_listener("grpc", params, users),
        "xhttp": _loopback_listener("xhttp", params, users),
        "ws": _loopback_listener("ws", params, users),
    }
    paths = {}
    for key, listener in files.items():
        listeners = [listener]
        if key == socks_key:
            listeners.extend(socks_listeners)
        data = _base_config(proxies, extra_rules, listeners)
        path = os.path.join(config.MIHOMO_DIR, key, _CONFIG_NAMES[key])
        _write_config(path, data)
        paths[key] = path
    return paths


def _params_from_conf(users: list[dict]) -> ProvisionParams:
    domain = config.vwn_conf_get("DOMAIN")
    stub = config.vwn_conf_get("STUB_URL")
    uuid_ = config.vwn_conf_get("UUID")
    grpc_service = config.vwn_conf_get("GRPC_SERVICE")
    xhttp_path = config.vwn_conf_get("XHTTP_PATH")
    ws_path = config.vwn_conf_get("WS_PATH")
    short_id = config.vwn_conf_get("SHORT_ID")
    if not all([domain, stub, uuid_, grpc_service, xhttp_path, short_id]):
        raise RuntimeError("Конфиг неполный — сначала выполните vwn install")
    private_key = keystore.reality_private_key()
    if not private_key:
        raise RuntimeError("Reality private key не найден (vwn.conf/xray-reality.json)")
    return ProvisionParams(
        domain=domain,
        stub=stub,
        uuid=uuid_,
        grpc_service=grpc_service,
        xhttp_path=xhttp_path,
        ws_path=ws_path or "/ws",
        short_id=short_id,
        private_key=private_key,
        grpc_mode=config.vwn_conf_get("GRPC_MODE") or "gun",
        xhttp_mode=config.vwn_conf_get("XHTTP_MODE") or "auto",
        xhttp_cdn_mode=config.vwn_conf_get("XHTTP_CDN_MODE") or "auto",
        reality_mode=config.vwn_conf_get("REALITY_MODE") or "tcp",
        reality_port=int(config.vwn_conf_get("REALITY_PORT") or config.REALITY_PUBLIC_PORT),
        fallback_port=config.NGINX_LOOPBACK_PORT,
        reality_decryption="none",
        decryption=keystore.vless_decryption(),
        server_ip=config.vwn_conf_get("SERVER_IP") or "",
    )


def _disabled_protocols() -> set[str]:
    from vwn.modules.sub import get_disabled_protocols
    return get_disabled_protocols()


def _render_nginx(params: ProvisionParams) -> None:
    from vwn.modules import xray

    tpl = os.path.join(os.path.dirname(__file__), "..", "data", "nginx_loopback.conf")
    disabled = _disabled_protocols()
    public = "reality" in disabled
    bind = "0.0.0.0" if public else "127.0.0.1"
    port = 443 if public else config.NGINX_LOOPBACK_PORT
    if "ws" in disabled or not params.ws_path:
        ws_map = ""
        ws_location = ""
    else:
        ws_map = ("map $http_upgrade $connection_upgrade {\n"
                  "    default upgrade;\n"
                  "    '' close;\n"
                  "}")
        ws_location = (
            "location ^~ " + params.ws_path + " {\n"
        '    if ($http_upgrade !~* "websocket") { return 404; }\n'
        "    client_max_body_size 0;\n"
        "    proxy_http_version 1.1;\n"
        "    proxy_set_header Upgrade $http_upgrade;\n"
        "    proxy_set_header Connection $connection_upgrade;\n"
        "    proxy_set_header Host $host;\n"
        "    proxy_set_header X-Real-IP $remote_addr;\n"
        "    proxy_buffering off;\n"
        "    proxy_read_timeout 1w;\n"
        "    proxy_send_timeout 1w;\n"
        "    access_log off;\n"
        "    proxy_pass http://127.0.0.1:" + str(config.XRAY_WS_PORT) + ";\n"
        "}"
    )
    import urllib.parse

    try:
        from vwn.core import system
        system._write_nginx_main_conf()
    except OSError:
        pass
    proxy_host = urllib.parse.urlparse(params.stub).netloc or params.domain
    xray.write_nginx_loopback_config(
        tpl, config.NGINX_LOOPBACK_CONF,
        NGINX_BIND=bind,
        NGINX_LOOPBACK_PORT=port,
        DOMAIN=params.domain,
        STUB=params.stub,
        PROXY_HOST=proxy_host,
        GRPC_SERVICE=params.grpc_service,
        XHTTP_PATH=params.xhttp_path,
        WS_PATH=params.ws_path,
        XRAY_WS_PORT=config.XRAY_WS_PORT,
        WS_MAP=ws_map,
        WS_LOCATION=ws_location,
        GRPC_LOCATION=("" if "grpc" in disabled else
                       xray.nginx_grpc_location(params.grpc_service,
                                                config.XRAY_GRPC_PORT)),
        XHTTP_LOCATION=("" if "xhttp" in disabled else
                        xray.nginx_xhttp_location(params.xhttp_path,
                                                  config.XRAY_XHTTP_PORT)),
        XRAY_GRPC_PORT=config.XRAY_GRPC_PORT,
        XRAY_XHTTP_PORT=config.XRAY_XHTTP_PORT,
    )


class MihomoBackend:
    name = "mihomo"
    bin = config.MIHOMO_BIN
    config_dir = config.MIHOMO_DIR
    config_files = config.MIHOMO_CONFIG_FILES
    services = config.MIHOMO_SERVICES
    capabilities = frozenset({
        "reality-tcp", "reality-xhttp", "xhttp", "grpc", "ws",
        "vless-enc", "mptcp-out",
    })

    def available(self) -> bool:
        return os.path.isfile(self.bin)

    def install(self, version: "str | None" = None) -> None:
        from . import versions

        shell.run(["useradd", "-r", "-s", "/usr/sbin/nologin",
                   "-d", config.MIHOMO_DIR, "mihomo"], check=False)
        versions.install_mihomo(version)
        try:
            from vwn.core import system
            system._install_geo_databases()
        except Exception:
            pass
        _ensure_dirs()

    def validate(self, config_path: str) -> None:
        if not os.path.isfile(self.bin):
            return
        home = os.path.dirname(config_path)
        r = shell.run([self.bin, "-t", "-f", config_path, "-d", home],
                      capture=True, check=False, timeout=30)
        if r is not None and r.returncode != 0:
            raise RuntimeError(
                f"mihomo config invalid: {config_path}\n"
                + (r.stdout or r.stderr or "").strip()[-500:]
            )

    def provision(self, params: ProvisionParams) -> list[str]:
        key = keystore.reality_private_key()
        if not key:
            keystore.set("REALITY_PRIVKEY", params.private_key)
        keystore.set("REALITY_PUBKEY", config.vwn_conf_get("REALITY_PUBKEY"))
        keystore.set("SHORT_ID", params.short_id)
        if params.decryption and params.decryption != "none":
            keystore.set("VLESS_DECRYPTION", params.decryption)
        users = users_mod.list_users()
        if not users:
            users = [{"uuid": params.uuid, "label": "default"}]
        paths = _render_all(params, users)
        for path in paths.values():
            self.validate(path)
        _render_nginx(params)
        return self.write_units(include_ws=True)

    def refresh(self) -> None:
        """Перегенерировать YAML из vwn.conf + Xray-состояния туннелей."""
        users = users_mod.list_users()
        params = _params_from_conf(users)
        paths = _render_all(params, users)
        for path in paths.values():
            self.validate(path)
        _render_nginx(params)
        for svc in self.services:
            if shell.service_active(svc):
                shell.run(["systemctl", "restart", svc], check=False)

    def rebuild(self, refresh_ip: bool = False) -> None:
        self.refresh()
        self.write_units(include_ws=True)
        from vwn.modules import sub

        sub.rebuild_all_sub_files(refresh_ip=refresh_ip)

    def write_units(self, include_ws: bool = True) -> list[str]:
        units_dir = config.SYSTEMD_DIR
        os.makedirs(units_dir, exist_ok=True)
        written = []
        disabled = _disabled_protocols()
        names = ["reality", "grpc", "xhttp"] + (["ws"] if include_ws else [])
        names = [n for n in names if n not in disabled]
        for key in names:
            home = os.path.join(config.MIHOMO_DIR, key)
            cfg = os.path.join(home, _CONFIG_NAMES[key])
            content = _UNIT_TPL.format(
                proto=key, bin=self.bin, config=cfg, home=home,
            )
            path = os.path.join(units_dir, _SERVICE_NAMES[key] + ".service")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            written.append(path)
        for key, svc in _SERVICE_NAMES.items():
            if key in names:
                continue
            unit = os.path.join(units_dir, svc + ".service")
            if os.path.isfile(unit):
                os.remove(unit)
            shutil.rmtree(os.path.join(units_dir, svc + ".service.d"),
                          ignore_errors=True)
        return written

    def apply_users(self, users: list[dict]) -> None:
        if not users:
            return
        self.refresh()

    def disable_protocol(self, proto: str) -> None:
        from vwn.modules.xray import _add_disabled

        svc = _SERVICE_NAMES.get(proto)
        if not svc:
            raise ValueError(f"Неизвестный протокол: {proto}")
        shell.run(["systemctl", "stop", svc], check=False)
        shell.run(["systemctl", "disable", svc], check=False)
        _add_disabled(proto)
        self.rebuild(refresh_ip=False)
        shell.run(["systemctl", "reload", "nginx"], check=False)

    def enable_protocol(self, proto: str) -> None:
        from vwn.modules.xray import _del_disabled

        svc = _SERVICE_NAMES.get(proto)
        if not svc:
            raise ValueError(f"Неизвестный протокол: {proto}")
        _del_disabled(proto)
        self.rebuild(refresh_ip=False)
        shell.run(["systemctl", "enable", svc], check=False)
        shell.run(["systemctl", "start", svc], check=False)
        shell.run(["systemctl", "reload", "nginx"], check=False)

    def restart_services(self) -> None:
        for svc in self.services:
            if shell.service_active(svc):
                shell.run(["systemctl", "restart", svc], check=False)

    def generate_reality_keypair(self) -> tuple[str, str]:
        if not os.path.isfile(self.bin):
            raise RuntimeError("mihomo не установлен")
        r = shell.run([self.bin, "generate", "reality-keypair"],
                      capture=True, check=False, timeout=20)
        private = public = ""
        for line in (r.stdout or "").splitlines():
            if line.startswith("PrivateKey:"):
                private = line.split(":", 1)[1].strip()
            elif line.startswith("PublicKey:"):
                public = line.split(":", 1)[1].strip()
        if not private or not public:
            raise RuntimeError("mihomo: не удалось разобрать reality-keypair")
        return private, public

    def generate_vless_keypair(self, strict: bool = False):
        if not os.path.isfile(self.bin):
            from .xray_backend import XrayBackend

            return XrayBackend().generate_vless_keypair(strict=strict)
        r = shell.run([self.bin, "generate", "vless-mlkem768"],
                      capture=True, check=False, timeout=20)
        out = r.stdout or ""
        decryption = encryption = ""
        for line in out.splitlines():
            if "[Server]" in line and "decryption:" in line:
                decryption = line.split("decryption:", 1)[1].strip().strip('"')
            elif "[Client]" in line and "encryption:" in line:
                encryption = line.split("encryption:", 1)[1].strip().strip('"')
        if not decryption or not encryption:
            from .xray_backend import XrayBackend

            return XrayBackend().generate_vless_keypair(strict=strict)
        return decryption, encryption
