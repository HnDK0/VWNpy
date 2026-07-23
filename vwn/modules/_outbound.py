"""Shared helpers for adding/removing tunnel outbounds to xray configs."""

import json
import os

from vwn.core import config


def _paths() -> list[str]:
    return [os.path.join(config.XRAY_DIR, p)
            for p in ("config.json", "xhttp.json", "xray-reality.json")]


def add_outbound(tag: str, protocol: str, port: int) -> None:
    import json as _j
    outbound = {"tag": tag, "protocol": protocol,
                "settings": {"servers": [{"address": "127.0.0.1", "port": port}]}}
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = _j.load(f)
        obs = cfg.setdefault("outbounds", [])
        if any(o.get("tag") == tag for o in obs):
            continue
        obs.insert(-1, outbound)
        with open(path, "w") as f:
            _j.dump(cfg, f, indent=2, ensure_ascii=False)


def remove_outbound(tag: str) -> None:
    import json as _j
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = _j.load(f)
        cfg["outbounds"] = [o for o in cfg.get("outbounds", [])
                            if o.get("tag") != tag]
        cfg.setdefault("routing", {}).setdefault("rules", [])
        cfg["routing"]["rules"] = [r for r in cfg["routing"]["rules"]
                                   if r.get("outboundTag") != tag]
        with open(path, "w") as f:
            _j.dump(cfg, f, indent=2, ensure_ascii=False)
