"""Shared domain list helpers for tunnel Split-routing."""
import json
import os
from vwn.core import shell

from vwn.modules._outbound import _paths

XRAY_DIR = "/usr/local/etc/xray"


def _file(tag: str) -> str:
    return os.path.join(XRAY_DIR, f"{tag}_domains.txt")


def list_domains(tag: str) -> list[str]:
    p = _file(tag)
    if not os.path.isfile(p):
        return []
    return [l.strip() for l in open(p) if l.strip()]


def add_domain(tag: str, domain: str) -> None:
    p = _file(tag)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a") as f:
        f.write(domain + "\n")
    lines = sorted(set(l.strip() for l in open(p) if l.strip()))
    with open(p, "w") as f:
        f.write("\n".join(lines) + "\n")
    _apply(tag)


def remove_domain(tag: str, index: int) -> None:
    p = _file(tag)
    if not os.path.isfile(p):
        return
    lines = [l.strip() for l in open(p) if l.strip()]
    if 0 <= index < len(lines):
        lines.pop(index)
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n" if lines else "")
        _apply(tag)


def remove_file(tag: str) -> None:
    p = _file(tag)
    if os.path.isfile(p):
        os.remove(p)


def _apply(tag: str) -> None:
    domains = list_domains(tag)
    if not domains:
        from vwn.modules._outbound import remove_outbound
        remove_outbound(tag)
        return
    domains_json = [f"domain:{d}" for d in domains]
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = json.load(f)
        has_outbound = any(o.get("tag") == tag for o in cfg.get("outbounds", []))
        if not has_outbound:
            continue
        for r in cfg.setdefault("routing", {}).setdefault("rules", []):
            if r.get("outboundTag") == tag:
                r["domain"] = domains_json
                r.pop("port", None)
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        shell.run(["systemctl", "restart", svc], timeout=30, check=False)
