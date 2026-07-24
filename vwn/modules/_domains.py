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


def add_domain(tag: str, domain: str) -> bool:
    """Добавить домен в список. Возвращает False если туннель в Global."""
    rules = _read_routing_rules(tag)
    if _is_global(rules, tag):
        return False
    p = _file(tag)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a") as f:
        f.write(domain + "\n")
    lines = sorted(set(l.strip() for l in open(p) if l.strip()))
    with open(p, "w") as f:
        f.write("\n".join(lines) + "\n")
    _apply(tag)
    return True


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


def _read_routing_rules(tag: str) -> list:
    """Прочитать routing rules из всех конфигов."""
    all_rules: list = []
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = json.load(f)
        all_rules.extend(cfg.get("routing", {}).get("rules", []))
    return all_rules


def _is_global(rules: list, tag: str) -> bool:
    """Проверить, есть ли Global rule для tag (port: 0-65535)."""
    for r in rules:
        if (r.get("outboundTag") == tag
                and not r.get("inboundTag")
                and r.get("port") == "0-65535"):
            return True
    return False


def _apply(tag: str) -> None:
    domains = list_domains(tag)
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = json.load(f)
        has_outbound = any(o.get("tag") == tag for o in cfg.get("outbounds", []))
        if not has_outbound:
            continue
        if not domains:
            # Удаляем только Split routing rule, outbound оставляем
            cfg.setdefault("routing", {}).setdefault("rules", [])
            cfg["routing"]["rules"] = [
                r for r in cfg["routing"]["rules"]
                if not (r.get("outboundTag") == tag
                        and not r.get("inboundTag")
                        and "domain" in r)]
        else:
            domains_json = [f"domain:{d}" for d in domains]
            for r in cfg.setdefault("routing", {}).setdefault("rules", []):
                if (r.get("outboundTag") == tag
                        and not r.get("inboundTag")
                        and r.get("port") != "0-65535"):
                    r["domain"] = domains_json
                    r.pop("port", None)
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        shell.run(["systemctl", "restart", svc], timeout=30, check=False)
