import json
import os
import time

from vwn.core import config, shell
from vwn.modules._outbound import add_outbound, remove_outbound

PORT = 40002
TAG = "psiphon"
BIN = "/usr/local/bin/psiphon-tunnel-core"
CONFIG = "/usr/local/etc/xray/psiphon.json"
SERVICE = "/etc/systemd/system/psiphon.service"
MODE_FILE = "/usr/local/etc/xray/psiphon_mode"
COUNTRY_FILE = "/usr/local/etc/xray/psiphon_country"
DATA_DIR = "/var/lib/psiphon"
LOG_DIR = "/var/log/psiphon"
USER = "psiphon"

SERVER_LIST_URL = ("https://s3.amazonaws.com/psiphon/web/"
                   "mjr4-p23r-puwl/server_list_compressed")
SERVER_LIST_KEY = ("MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEA"
                   "t7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax"
                   "3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdym"
                   "twzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvK"
                   "wRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RR"
                   "wLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZoK/"
                   "rvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVt"
                   "cTjjhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7Gs"
                   "tZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqco"
                   "dWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGj"
                   "VZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZY"
                   "sje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6"
                   "YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV"
                   "7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBs"
                   "oAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4e"
                   "r68iCID+rsCAQM=")


COUNTRIES = [
    ("AU", "Australia"), ("AT", "Austria"), ("BR", "Brazil"),
    ("BG", "Bulgaria"), ("CA", "Canada"), ("CZ", "Czech Republic"),
    ("EE", "Estonia"), ("FI", "Finland"), ("FR", "France"),
    ("DE", "Germany"), ("HU", "Hungary"), ("IN", "India"),
    ("IE", "Ireland"), ("IL", "Israel"), ("IT", "Italy"),
    ("JP", "Japan"), ("LV", "Latvia"), ("LT", "Lithuania"),
    ("MY", "Malaysia"), ("NL", "Netherlands"), ("NO", "Norway"),
    ("PL", "Poland"), ("RO", "Romania"), ("SG", "Singapore"),
    ("SK", "Slovakia"), ("ES", "Spain"), ("SE", "Sweden"),
    ("CH", "Switzerland"), ("UA", "Ukraine"),
    ("GB", "United Kingdom"), ("US", "United States"),
]


def _bin_url() -> str:
    arch = shell.run(["uname", "-m"], capture=True).stdout.strip()
    if arch != "x86_64":
        raise RuntimeError(
            f"Psiphon tunnel-core доступен только для x86_64, "
            f"ваша архитектура: {arch}"
        )
    return ("https://github.com/Psiphon-Labs/"
            "psiphon-tunnel-core-binaries/raw/master/linux/"
            "psiphon-tunnel-core-x86_64")


def _write_config(country: str = "", upstream: str = "") -> None:
    os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
    cfg = {
        "PropagationChannelId": "FFFFFFFFFFFFFFFF",
        "SponsorId": "FFFFFFFFFFFFFFFF",
        "LocalSocksProxyPort": PORT,
        "LocalHttpProxyPort": 0,
        "DisableLocalSocksProxy": False,
        "DisableLocalHTTPProxy": True,
        "EgressRegion": country,
        "DataRootDirectory": DATA_DIR,
        "RemoteServerListDownloadFilename": f"{DATA_DIR}/remote_server_list",
        "RemoteServerListUrl": SERVER_LIST_URL,
        "RemoteServerListSignaturePublicKey": SERVER_LIST_KEY,
        "ClientPlatform": "Android_4.0.4_com.example.exampleClientLibraryApp",
        "NetworkID": "default",
        "TunnelProtocol": "",
        "ConnectionWorkerPoolSize": 10,
        "LimitTunnelProtocols": [],
    }
    if upstream:
        cfg["UpstreamProxyURL"] = upstream
    with open(CONFIG, "w") as f:
        json.dump(cfg, f, indent=2)
    with open(COUNTRY_FILE, "w") as f:
        f.write(country + "\n")


def _setup_service() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    if shell.run(["id", USER], check=False, capture=True).returncode != 0:
        shell.run(["useradd", "-r", "-s", "/sbin/nologin", "-d", DATA_DIR, USER],
                  check=False)
    shell.run(["chown", "-R", f"{USER}:{USER}", DATA_DIR], check=False)
    shell.run(["chown", "-R", f"{USER}:{USER}", LOG_DIR], check=False)
    unit = f"""[Unit]
Description=Psiphon Tunnel Core
After=network.target

[Service]
Type=simple
User={USER}
ExecStart={BIN} -config {CONFIG}
Restart=on-failure
RestartSec=5
StandardOutput=append:{LOG_DIR}/psiphon.log
StandardError=append:{LOG_DIR}/psiphon.log

[Install]
WantedBy=multi-user.target
"""
    with open(SERVICE, "w") as f:
        f.write(unit)
    shell.run(["systemctl", "daemon-reload"], check=False)
    shell.run(["systemctl", "enable", "psiphon"], check=False)
    shell.run(["systemctl", "restart", "psiphon"], check=False)
    for _ in range(6):
        if shell.run(["sh", "-c", f"ss -tlnp | grep -q :{PORT}"], check=False).returncode == 0:
            break
        time.sleep(2)





def install(country: str = "", tunnel_mode: str = "plain") -> None:
    if not os.path.isfile(BIN):
        url = _bin_url()
        shell.run(["curl", "-fL", "-o", BIN, url], timeout=120)
        shell.run(["chmod", "+x", BIN])
    upstream = "socks5://127.0.0.1:40000" if tunnel_mode == "warp" else ""
    with open(MODE_FILE, "w") as f:
        f.write(tunnel_mode)
    _write_config(country, upstream)
    _setup_service()
    add_outbound(TAG, "socks", PORT)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        shell.run(["systemctl", "restart", svc], check=False)
    time.sleep(3)


def remove() -> None:
    shell.run(["systemctl", "stop", "psiphon"], check=False)
    shell.run(["systemctl", "disable", "psiphon"], check=False)
    for f in [SERVICE, BIN, CONFIG, MODE_FILE, COUNTRY_FILE]:
        if os.path.isfile(f):
            os.remove(f)
    for d in [DATA_DIR, LOG_DIR]:
        if os.path.isdir(d):
            shell.run(["rm", "-rf", d], check=False)
    shell.run(["systemctl", "daemon-reload"], check=False)
    remove_outbound(TAG)
    from vwn.modules._domains import remove_file as _rmd
    _rmd(TAG)
    for svc in ["xray-reality", "xray-ws", "xray-xhttp"]:
        shell.run(["systemctl", "restart", svc], check=False)


def add_domain(domain: str) -> bool:
    from vwn.modules._domains import add_domain as _ad
    return _ad(TAG, domain)


def remove_domain(index: int) -> None:
    from vwn.modules._domains import remove_domain as _rd
    _rd(TAG, index)


def list_domains() -> list[str]:
    from vwn.modules._domains import list_domains as _ld
    return _ld(TAG)


def reapply_routing() -> None:
    """Повторно применить routing rule для Psiphon (после rebuild_configs)."""
    from vwn.core import config as _cfg
    mode = _cfg.vwn_conf_get("PSIPHON_TUNNEL_MODE") or ""
    if not mode:
        return
    from vwn.modules._outbound import _paths
    from vwn.modules.tunnels import insert_before_catchall
    from vwn.modules._domains import list_domains as _ld
    has_outbound = False
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = json.load(f)
        if any(o.get("tag") == TAG for o in cfg.get("outbounds", [])):
            has_outbound = True
            break
    if not has_outbound:
        return
    domains = _ld(TAG) if mode == "Split" else []
    if mode == "Split" and not domains:
        domains = ["whoer.net"]
    if mode == "Global":
        rule = {"type": "field", "port": "0-65535", "outboundTag": TAG}
    else:
        domains_json = [f"domain:{d}" for d in domains]
        rule = {"type": "field", "domain": domains_json, "outboundTag": TAG}
    for path in _paths():
        if not os.path.isfile(path):
            continue
        with open(path) as f:
            cfg = json.load(f)
        rules = cfg.setdefault("routing", {}).setdefault("rules", [])
        rules = [r for r in rules
                 if not (r.get("outboundTag") == TAG and "inboundTag" not in r)]
        insert_before_catchall(rules, rule)
        cfg["routing"]["rules"] = rules
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)


def status() -> dict:
    active = shell.service_active("psiphon")
    country = ""
    if os.path.isfile(COUNTRY_FILE):
        country = open(COUNTRY_FILE).read().strip()
    mode = "plain"
    if os.path.isfile(MODE_FILE):
        mode = open(MODE_FILE).read().strip()
    return {"active": active, "country": country, "mode": mode, "port": PORT}
