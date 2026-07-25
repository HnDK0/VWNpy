"""Privacy mode: disable logging across Xray, Nginx, journald, tmpfs."""

import os
import re
import time

from vwn.core import config, shell

_PRIVACY_FLAG = "PRIVACY_MODE"
_XRAY_LOGS = ["/var/log/xray/access.log", "/var/log/xray/error.log",
              "/var/log/xray/reality-error.log"]
_NGINX_LOG = "/var/log/nginx/access.log"
_TMPFS_MOUNT = "/etc/systemd/system/var-log-xray.mount"


def _xray_configs() -> list[str]:
    d = "/usr/local/etc/xray"
    return [os.path.join(d, f) for f in ["config.json", "xray-reality.json", "xhttp.json"]
            if os.path.isfile(os.path.join(d, f))]


def _set_xray_log_level(cfg: str, access: str, level: str) -> None:
    if not os.path.isfile(cfg):
        return
    import json
    with open(cfg) as f:
        c = json.load(f)
    c.setdefault("log", {})
    c["log"]["access"] = access
    c["log"]["loglevel"] = level
    with open(cfg, "w") as f:
        json.dump(c, f, indent=2, ensure_ascii=False)


def _xray_disable_log() -> None:
    for c in _xray_configs():
        _set_xray_log_level(c, "none", "none")


def _xray_restore_log() -> None:
    for c in _xray_configs():
        if not os.path.isfile(c):
            continue
        import json
        with open(c) as f:
            cfg = json.load(f)
        cfg.setdefault("log", {})
        cfg["log"].pop("access", None)
        cfg["log"]["loglevel"] = "warning"
        with open(c, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)


def _nginx_set_access_log(state: str) -> None:
    p = "/etc/nginx/nginx.conf"
    if not os.path.isfile(p):
        return
    with open(p) as f:
        t = f.read()
    if state == "off":
        t = re.sub(r'access_log\s+\S+', 'access_log off', t)
    else:
        t = re.sub(r'access_log\s+off', f'access_log {_NGINX_LOG}', t)
    with open(p, "w") as f:
        f.write(t)
    if shell.run(["nginx", "-t"], check=False).returncode == 0:
        shell.run(["systemctl", "reload", "nginx"], check=False)


def _systemd_output(svc: str, action: str) -> None:
    d = f"/etc/systemd/system/{svc}.service.d"
    f = f"{d}/no-journal.conf"
    if action == "disable":
        os.makedirs(d, exist_ok=True)
        with open(f, "w") as fp:
            fp.write("[Service]\nStandardOutput=null\nStandardError=null\n")
    else:
        if os.path.isfile(f):
            os.remove(f)
        if os.path.isdir(d) and not os.listdir(d):
            os.rmdir(d)


def _enable_tmpfs() -> None:
    os.makedirs("/var/log/xray", exist_ok=True)
    unit = (
        "[Unit]\nDescription=tmpfs for xray logs (privacy mode)\n"
        "Before=xray-reality.service\n\n"
        "[Mount]\nWhat=tmpfs\nWhere=/var/log/xray\nType=tmpfs\n"
        "Options=defaults,noatime,size=32m,mode=750\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    with open(_TMPFS_MOUNT, "w") as f:
        f.write(unit)
    shell.run(["systemctl", "daemon-reload"], check=False)
    shell.run(["systemctl", "enable", "--now", "var-log-xray.mount"], check=False)
    for f in _XRAY_LOGS:
        shell.run(["touch", f], check=False)
    shell.run(["chown", "-R", "xray:xray", "/var/log/xray"], check=False)


def _disable_tmpfs() -> None:
    shell.run(["systemctl", "disable", "--now", "var-log-xray.mount"], check=False)
    for f in [_TMPFS_MOUNT]:
        if os.path.isfile(f):
            os.remove(f)
    shell.run(["systemctl", "daemon-reload"], check=False)
    os.makedirs("/var/log/xray", exist_ok=True)
    for f in _XRAY_LOGS:
        shell.run(["touch", f], check=False)
    shell.run(["chown", "-R", "xray:xray", "/var/log/xray"], check=False)


def _shred_logs() -> None:
    for f in _XRAY_LOGS + [_NGINX_LOG, "/var/log/nginx/error.log"]:
        if os.path.isfile(f):
            shell.run(["shred", "-u", f], check=False)
            shell.run(["touch", f], check=False)
    shell.run(["journalctl", "--rotate"], check=False)
    shell.run(["journalctl", "--vacuum-time=1s"], check=False)


def _real_score() -> int:
    score = 0
    for cfg in _xray_configs():
        import json
        try:
            with open(cfg) as f:
                c = json.load(f)
            if c.get("log", {}).get("loglevel") == "none":
                score += 1
        except Exception:
            pass
    if os.path.isfile("/etc/nginx/nginx.conf"):
        with open("/etc/nginx/nginx.conf") as f:
            if re.search(r"access_log\s+off", f.read()):
                score += 1
    if os.path.isfile("/etc/systemd/system/xray-reality.service.d/no-journal.conf"):
        score += 1
    if shell.service_active("var-log-xray.mount"):
        score += 1
    return score


def status() -> dict:
    flag = config.vwn_conf_get(_PRIVACY_FLAG) == "1"
    real = _real_score() >= 3
    if flag != real:
        config.vwn_conf_set(_PRIVACY_FLAG, "1" if real else "0")
    return {"enabled": real, "score": _real_score()}


def enable() -> None:
    if status()["enabled"]:
        return
    _xray_disable_log()
    _nginx_set_access_log("off")
    for svc in ["xray-reality"]:
        _systemd_output(svc, "disable")
    shell.run(["systemctl", "daemon-reload"], check=False)
    shell.run(["systemctl", "restart", "xray-reality"], check=False)
    _enable_tmpfs()
    _shred_logs()
    config.vwn_conf_set(_PRIVACY_FLAG, "1")


def disable() -> None:
    if not status()["enabled"]:
        return
    _xray_restore_log()
    _nginx_set_access_log("on")
    for svc in ["xray-reality"]:
        _systemd_output(svc, "restore")
    shell.run(["systemctl", "daemon-reload"], check=False)
    shell.run(["systemctl", "stop", "xray-reality"], check=False)
    _disable_tmpfs()
    shell.run(["systemctl", "start", "xray-reality"], check=False)
    config.vwn_conf_set(_PRIVACY_FLAG, "0")


def shred() -> None:
    _shred_logs()
