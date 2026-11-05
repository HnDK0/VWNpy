"""Staged switch между ядрами."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

from vwn.core import config, shell

from . import keystore, registry

_PENDING = "CORE_SWITCH_PENDING"
_FROM = "CORE_SWITCH_FROM"
_KEY_NAMES = ("REALITY_PUBKEY", "SHORT_ID", "VLESS_ENCRYPTION")


def _units_reload() -> None:
    shell.run(["systemctl", "daemon-reload"], check=False)


def _stop_services(services: tuple[str, ...]) -> None:
    for svc in services:
        shell.run(["systemctl", "stop", svc], check=False)
        shell.run(["systemctl", "disable", svc], check=False)


def _stop_services_only(services: tuple[str, ...]) -> None:
    for svc in services:
        shell.run(["systemctl", "stop", svc], check=False)


def _disable_services(services: tuple[str, ...]) -> None:
    for svc in services:
        shell.run(["systemctl", "disable", svc], check=False)


def _enable_services(services: tuple[str, ...]) -> None:
    for svc in services:
        shell.run(["systemctl", "enable", svc], check=False)


def _start_services(services: tuple[str, ...]) -> None:
    for svc in services:
        shell.run(["systemctl", "enable", svc], check=False)
        shell.run(["systemctl", "start", svc], check=False)


def _active_services(backend) -> tuple[str, ...]:
    return registry.active_services(backend)


def _port_for(service: str) -> "int | None":
    suffix = service.rsplit("-", 1)[-1]
    if suffix == "reality":
        try:
            return int(config.vwn_conf_get("REALITY_PORT") or config.REALITY_PUBLIC_PORT)
        except ValueError:
            return config.REALITY_PUBLIC_PORT
    if suffix == "grpc":
        return config.XRAY_GRPC_PORT
    if suffix == "xhttp":
        return config.XRAY_XHTTP_PORT
    if suffix == "ws":
        return config.XRAY_WS_PORT
    return None


def _port_listening(port: int) -> bool:
    r = shell.run(["ss", "-tln"], capture=True, check=False, timeout=5)
    if r is None:
        return True
    out = getattr(r, "stdout", "") or ""
    if not out:
        return True
    return re.search(r":%d\b" % port, out) is not None


def _reality_tls_ok() -> bool:
    domain = config.vwn_conf_get("DOMAIN")
    if not domain:
        return True
    port = _port_for("reality") or config.REALITY_PUBLIC_PORT
    r = shell.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{port}",
         "-servername", domain, "-tls1_3", "-brief"],
        capture=True, check=False, timeout=10,
        stdin=subprocess.DEVNULL,
    )
    return True if r is None or r.returncode == 127 else r.returncode == 0


def _transport_ok() -> bool:
    """Проверить nginx→core для gRPC/XHTTP без полного VLESS-клиента."""
    if (config.vwn_conf_get("VLESS_DECRYPTION") or "none") != "none":
        return True
    domain = config.vwn_conf_get("DOMAIN") or ""
    if not domain:
        return True
    disabled = _disabled_protocols()
    port = 443 if "reality" in disabled else config.NGINX_LOOPBACK_PORT
    resolve = f"{domain}:{port}:127.0.0.1"

    def code(args: list[str]) -> str:
        r = shell.run(
            ["curl", "-sk", "-o", "/dev/null", "-m", "8", "-w", "%{http_code}",
             "--resolve", resolve, *args],
            capture=True, check=False, timeout=12,
        )
        if r is None or r.returncode == 127:
            return "200"
        return (r.stdout or "").strip()

    svc = config.vwn_conf_get("GRPC_SERVICE") or ""
    if "grpc" not in disabled and svc:
        c = code(["--http2", "-X", "POST", "-H", "content-type: application/grpc",
                  "--data-binary", "", f"https://{domain}:{port}/{svc}/Tun"])
        if c != "200":
            return False

    path = config.vwn_conf_get("XHTTP_PATH") or ""
    if "xhttp" not in disabled and path:
        c = code(["--http2", f"https://{domain}:{port}{path}/"])
        if c in ("", "000", "502", "503", "504"):
            return False
    return True


def _healthy(services: tuple[str, ...]) -> list[str]:
    time.sleep(2)
    failed = [svc for svc in services if not shell.service_active(svc)]
    if failed:
        return failed
    for svc in services:
        port = _port_for(svc)
        if port and not _port_listening(port):
            failed.append(svc)
    if not failed and "reality" not in _disabled_protocols():
        reality = [svc for svc in services if svc.endswith("-reality")]
        if reality and not _reality_tls_ok():
            failed.extend(reality)
    if not failed and not _transport_ok():
        failed.append("transport")
    return failed


def _disabled_protocols() -> set[str]:
    from vwn.modules.sub import get_disabled_protocols

    return get_disabled_protocols()


def _clear_pending() -> None:
    config.vwn_conf_del(_PENDING)
    config.vwn_conf_del(_FROM)


def _snapshot_keys() -> dict[str, "str | None"]:
    return {key: config.vwn_conf_get(key) for key in _KEY_NAMES}


def _keys_changed(before: dict[str, "str | None"]) -> bool:
    return any(config.vwn_conf_get(key) != value for key, value in before.items())


def _check_mptcp(target) -> None:
    value = (config.vwn_conf_get("MPTCP") or "").strip().lower()
    if target.name == "mihomo" and value in ("on", "true", "1", "yes"):
        raise RuntimeError("MPTCP=on: mihomo не поддерживает MPTCP inbound")


def _backup_core(old) -> None:
    if os.geteuid() != 0:
        return
    dest = os.path.join("/root", "vwn_backups",
                        time.strftime("%Y%m%d-%H%M%S") + "-" + old.name)
    try:
        os.makedirs(dest, exist_ok=True)
        for name in getattr(old, "config_files", ()):
            src = os.path.join(getattr(old, "config_dir", ""), name)
            if os.path.isfile(src):
                shutil.copy2(src, dest)
        conf = config.vwn_conf_path()
        if os.path.isfile(conf):
            shutil.copy2(conf, dest)
    except OSError:
        pass


def ensure_guard_unit() -> None:
    if os.geteuid() != 0:
        return
    path = os.path.join(config.SYSTEMD_DIR, "vwn-core-guard.service")
    unit = ("[Unit]\nDescription=VWN core switch recovery\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=oneshot\n"
            "ExecStart=/usr/local/bin/vwn core recover\n\n"
            "[Install]\nWantedBy=multi-user.target\n")
    try:
        os.makedirs(config.SYSTEMD_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(unit)
    except OSError:
        return
    _units_reload()
    shell.run(["systemctl", "enable", "vwn-core-guard.service"], check=False)


def _restore_old(old) -> None:
    config.vwn_conf_set("CORE", old.name)
    try:
        old.rebuild(refresh_ip=False)
    except Exception:
        pass
    _units_reload()
    _start_services(_active_services(old))
    shell.run(["systemctl", "restart", config.NGINX_SERVICE], check=False)


def recover_pending() -> None:
    """Завершить прерванный switch после падения/перезагрузки."""
    pending = config.vwn_conf_get(_PENDING)
    if not pending:
        return
    from_name = config.vwn_conf_get(_FROM) or config.CORE_DEFAULT
    try:
        target = registry.get_core(pending)
        old = registry.get_core(from_name)
    except ValueError:
        _clear_pending()
        return

    target_services = _active_services(target)
    if target_services and all(shell.service_active(svc) for svc in target_services):
        config.vwn_conf_set("CORE", target.name)
        _disable_services(_active_services(old))
        _clear_pending()
        return

    _stop_services(target_services)
    _restore_old(old)
    _clear_pending()


def switch_to(name: str) -> None:
    """Переключить активное ядро с откатом при неудачном старте."""
    target = registry.get_core(name)
    old = registry.get_core()
    if target.name == old.name:
        target.rebuild(refresh_ip=True)
        return

    _check_mptcp(target)
    if not target.available():
        target.install()
    keystore.migrate_from_xray_configs()
    keystore.repair_reality_pubkey()
    _backup_core(old)
    ensure_guard_unit()

    old_name = old.name
    config.vwn_conf_set(_PENDING, target.name)
    config.vwn_conf_set(_FROM, old_name)
    # CORE переключаем на время rebuild: apply_users внутри rebuild должен
    # попасть в target backend. После rebuild возвращаем old до health-gate.
    config.vwn_conf_set("CORE", target.name)
    before = _snapshot_keys()
    try:
        target.rebuild(refresh_ip=False)
        target.write_units(include_ws=True)
        _units_reload()
        if _keys_changed(before):
            raise RuntimeError("Ключи изменились при переключении ядра")
    except Exception:
        _restore_old(old)
        _clear_pending()
        raise
    config.vwn_conf_set("CORE", old_name)

    target_services = _active_services(target)
    _enable_services(target_services)
    _stop_services_only(_active_services(old))
    # nginx должен освободить 443 до старта mihomo-reality. При reality on
    # новый конфиг слушает 127.0.0.1:8443, при reality off — 443.
    shell.run(["systemctl", "restart", config.NGINX_SERVICE], check=False)
    _start_services(target_services)

    failed = _healthy(target_services)
    if failed:
        _stop_services(target_services)
        _restore_old(old)
        _clear_pending()
        raise RuntimeError(
            "Не удалось запустить %s: %s. Выполнен откат на %s."
            % (target.name, ", ".join(failed), old.name)
        )

    _disable_services(old.services)
    config.vwn_conf_set("CORE", target.name)
    _clear_pending()
