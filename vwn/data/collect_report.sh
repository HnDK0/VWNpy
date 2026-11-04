#!/usr/bin/env bash
# VWNpy: сбор диагностики сервера (для разбора проблем gRPC / XHTTP / Reality).
# Секреты маскируются: UUID, ключи Reality, shortId, пути (показывается только
# длина и короткий хэш — по нему видно, совпадают ли пути в nginx и xray).
# Использование:  vwn report [файл]      или      bash collect_report.sh [файл]
set -u
export LC_ALL=C

OUT="${1:-/tmp/vwn-report-$(date +%Y%m%d-%H%M%S).txt}"
XD="${VWN_XRAY_DIR:-/usr/local/etc/xray}"
NGX_CONF="${VWN_NGX_CONF:-/etc/nginx/conf.d/xray.conf}"
XRAY_BIN="${VWN_XRAY_BIN:-/usr/local/bin/xray}"
LB_PORT="${VWN_LB_PORT:-8443}"
GRPC_PORT="${VWN_GRPC_PORT:-50001}"
XH_PORT="${VWN_XH_PORT:-50002}"
WS_PORT="${VWN_WS_PORT:-50003}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "нужен python3" >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ── Python-хелпер: маскирование и извлечение значений ───────────────
cat > "$TMP/h.py" <<'PYEOF'
import hashlib, json, re, sys

UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b")
KEEP_IP = ("127.", "0.0.0.0", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1")
SECRET_KEYS = {"id", "privateKey", "publicKey", "password", "shortIds", "email", "pbk", "sid",
               "decryption", "encryption"}


def tag(p):
    return "<path len=%d #%s>" % (len(p), hashlib.sha1(p.encode()).hexdigest()[:6])


def scrub(text):
    text = UUID.sub("<uuid>", text)

    def ip(m):
        s = m.group(0)
        return s if s.startswith(KEEP_IP) else m.group(1) + ".x.x"
    return IPV4.sub(ip, text)


def mask(o):
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if k in SECRET_KEYS:
                out[k] = "<hidden>"
            elif k in ("path", "serviceName") and isinstance(v, str):
                out[k] = tag(v)
            else:
                out[k] = mask(v)
        return out
    if isinstance(o, list):
        return [mask(x) for x in o]
    return o


def conf_get(path, key):
    import base64
    try:
        for line in open(path, encoding="utf-8"):
            line = line.rstrip("\n")
            if line.startswith(key + "="):
                v = line.split("=", 1)[1].strip()
                if v.startswith("@b64:"):
                    v = base64.b64decode(v[5:]).decode("utf-8", "replace")
                return v
    except OSError:
        pass
    return ""


def inbound_path(path, field, key="path"):
    try:
        ib = json.load(open(path, encoding="utf-8"))["inbounds"][0]
        return ib["streamSettings"].get(field, {}).get(key, "")
    except Exception:
        return ""


cmd = sys.argv[1]
if cmd == "scrub":
    sys.stdout.write(scrub(sys.stdin.read()))
elif cmd == "json":
    try:
        cfg = json.load(open(sys.argv[2], encoding="utf-8"))
        brief = {k: cfg[k] for k in ("dns", "inbounds", "policy") if k in cfg}
        brief["outbound_tags"] = [o.get("tag") for o in cfg.get("outbounds", [])]
        brief["routing_domainStrategy"] = cfg.get("routing", {}).get("domainStrategy")
        print(scrub(json.dumps(mask(brief), indent=1, ensure_ascii=False)))
    except Exception as e:
        print("не удалось прочитать %s: %s" % (sys.argv[2], e))
elif cmd == "nginx":
    xd = sys.argv[3]
    paths = {inbound_path(xd + "/grpc.json", "grpcSettings", "serviceName"),
              inbound_path(xd + "/xhttp.json", "xhttpSettings"),
              inbound_path(xd + "/ws.json", "wsSettings")} - {""}
    txt = open(sys.argv[2], encoding="utf-8", errors="replace").read()
    for p in sorted(paths, key=len, reverse=True):
        txt = txt.replace(p, tag(p))
    print(scrub(txt))
elif cmd == "conf":
    allow = ("DOMAIN", "REALITY_MODE", "REALITY_XHTTP_MODE", "XHTTP_MODE", "REALITY_DEST",
             "REALITY_PORT", "DISABLED_PROTOCOLS", "CDN_MODE", "DNS_V4_PRIMARY",
             "DNS_V4_FALLBACK", "DNS_V6_PRIMARY")
    try:
        for line in open(sys.argv[2], encoding="utf-8"):
            line = line.rstrip("\n")
            if "=" not in line or line.startswith("#"):
                continue
            k, v = line.split("=", 1)
            print("%s=%s" % (k, v if k in allow else "<set>" if v.strip() else "<empty>"))
    except OSError as e:
        print("нет vwn.conf: %s" % e)
elif cmd == "get":
    print(conf_get(sys.argv[2], sys.argv[3]))
elif cmd == "grpcsvc":
    print(inbound_path(sys.argv[2] + "/grpc.json", "grpcSettings", "serviceName"))
elif cmd == "xhpath":
    print(inbound_path(sys.argv[2] + "/xhttp.json", "xhttpSettings"))
elif cmd == "inconf":
    # совпадает ли путь xray с location в nginx
    p, f = sys.argv[2], sys.argv[3]
    ok = bool(p) and re.search(r"location\s+(=\s+|\^~\s+)?" + re.escape(p) + r"\s*\{",
                               open(f, encoding="utf-8", errors="replace").read()) is not None
    print("n/a" if not p else "yes" if ok else "no")
PYEOF
H() { python3 "$TMP/h.py" "$@"; }
scrub() { H scrub; }

sec() { printf '\n\n===== %s =====\n' "$1"; }
run() { # run <описание> <команда...>  — вывод маскируется, ошибки не роняют скрипт
    printf '\n$ %s\n' "$1"; shift
    timeout 20 "$@" 2>&1 | scrub
}
have() { command -v "$1" >/dev/null 2>&1; }

# Код ответа curl: «HTTP-код (exit=N)»
code() {
    local c rc
    c="$(timeout 15 curl -sk -o /dev/null -m 5 -w '%{http_code}' "$@" 2>/dev/null)"; rc=$?
    echo "${c:-000} (curl exit=$rc)"
}

DOMAIN="$(H get "$XD/vwn.conf" DOMAIN)"
GRPC_SVC="$(H grpcsvc "$XD")"
XH_PATH="$(H xhpath "$XD")"
WS_PATH="$(H inbound_path "$XD/ws.json" wsSettings 2>/dev/null || true)"
VE="$(H get "$XD/vwn.conf" VLESS_ENCRYPTION)"
GRPC_NGX="$(H inconf "${GRPC_SVC:+/$GRPC_SVC}" "$NGX_CONF")"
XH_NGX="$(H inconf "$XH_PATH" "$NGX_CONF")"

# gRPC-проба: POST application/grpc на /<service>/Tun; 200 = дошло до Xray
GRPC_HDRS=(-X POST -H 'content-type: application/grpc' --data-binary '')

{
echo "VWNpy report  $(date -u +%FT%TZ)"
echo "(секреты замаскированы; сверяйте пути по #хэшу)"

sec "Система"
run "os-release" sh -c '. /etc/os-release; echo "$PRETTY_NAME"'
run "uname -a" uname -a
run "virt" sh -c 'systemd-detect-virt 2>/dev/null || echo unknown'
run "cpu/mem" sh -c 'echo "cpus: $(nproc)"; free -m | head -2; cat /proc/loadavg'
run "disk /" sh -c 'df -h / | tail -1'
run "ulimit -n" sh -c 'ulimit -n'
run "time" sh -c 'timedatectl 2>/dev/null | grep -E "Local time|synchronized|NTP" || date'

sec "Ядро / TCP (важно для sockopt Xray)"
run "tcp congestion" sh -c 'echo "current:   $(cat /proc/sys/net/ipv4/tcp_congestion_control 2>&1)"
echo "available: $(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>&1)"
echo "fastopen:  $(cat /proc/sys/net/ipv4/tcp_fastopen 2>&1)"
echo "qdisc:     $(sysctl -n net.core.default_qdisc 2>&1)"'
run "lsmod bbr" sh -c 'lsmod 2>/dev/null | grep -i bbr || echo "модуль tcp_bbr не загружен"'
run "security modules" sh -c 'command -v getenforce >/dev/null && getenforce; command -v aa-status >/dev/null && aa-status 2>&1 | head -3; true'

sec "Версии"
run "vwn" sh -c 'vwn --version 2>&1 | head -1'
run "xray" sh -c "$XRAY_BIN version 2>&1 | head -2"
run "nginx -v" sh -c 'nginx -v 2>&1'
run "nginx модули" sh -c 'nginx -V 2>&1 | tr " " "\n" | grep -E "with-http_(ssl|v2|realip)|with-stream|without" | tr "\n" " "; echo'
run "nginx -t" sh -c 'nginx -t 2>&1'

sec "Сервисы"
for s in xray-reality xray-grpc xray-xhttp xray-ws nginx; do
    run "$s" sh -c "echo \"active=\$(systemctl is-active $s 2>&1) enabled=\$(systemctl is-enabled $s 2>&1)\"; systemctl show $s -p NRestarts -p Result -p ExecMainStatus 2>&1 | tr '\n' ' '; echo"
done
run "слушающие порты" sh -c 'ss -ltnpH 2>/dev/null | awk "{print \$4, \$6}"'

sec "Конфиг (маскированный)"
printf '\n--- vwn.conf ---\n'
H conf "$XD/vwn.conf"
for f in xray-reality.json grpc.json xhttp.json ws.json; do
    printf '\n--- %s ---\n' "$f"
    H json "$XD/$f"
done
printf '\n--- %s ---\n' "$NGX_CONF"
H nginx "$NGX_CONF" "$XD"
echo
echo "serviceName gRPC из xray есть в nginx location: $GRPC_NGX"
echo "путь XHTTP из xray есть в nginx location: $XH_NGX"

sec "Проверки цепочки gRPC (ожидается 200; без application/grpc — 404)"
G1=""; G2=""; G3=""; G4=""
if [ -n "$GRPC_SVC" ] && [ -n "$DOMAIN" ]; then
    G1="$(code --http2-prior-knowledge "${GRPC_HDRS[@]}" "http://127.0.0.1:$GRPC_PORT/$GRPC_SVC/Tun")"
    G2="$(code --http2 "${GRPC_HDRS[@]}" --resolve "$DOMAIN:$LB_PORT:127.0.0.1" "https://$DOMAIN:$LB_PORT/$GRPC_SVC/Tun")"
    G3="$(code --http2 "${GRPC_HDRS[@]}" --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN:443/$GRPC_SVC/Tun")"
    G4="$(code --http2 --resolve "$DOMAIN:$LB_PORT:127.0.0.1" "https://$DOMAIN:$LB_PORT/$GRPC_SVC/Tun")"
    echo "1) h2c напрямую в xray-grpc 127.0.0.1:$GRPC_PORT: $G1"
    echo "2) через nginx (h2)    127.0.0.1:$LB_PORT:      $G2"
    echo "3) через публичный :443 (Reality fallback):     $G3"
    echo "4) через nginx БЕЗ application/grpc (ждём 404): $G4"
else
    echo "нет GRPC_SERVICE (grpc.json) или DOMAIN — пропуск"
fi

X2=""
sec "Проверки цепочки XHTTP (502/504/000 = upstream недоступен)"
if [ -n "$XH_PATH" ] && [ -n "$DOMAIN" ]; then
    echo "1) h2c напрямую в xray-xhttp 127.0.0.1:$XH_PORT: $(code --http2-prior-knowledge "http://127.0.0.1:$XH_PORT$XH_PATH/")"
    X2="$(code --http2 --resolve "$DOMAIN:$LB_PORT:127.0.0.1" "https://$DOMAIN:$LB_PORT$XH_PATH/")"
    echo "2) через nginx (h2)    127.0.0.1:$LB_PORT:      $X2"
    echo "3) через публичный :443 (h2):                   $(code --http2 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN:443$XH_PATH/")"
else
    echo "нет XHTTP_PATH или DOMAIN — пропуск"
fi

sec "TLS nginx loopback"
if have openssl && [ -n "$DOMAIN" ]; then
    run "handshake (ALPN h2/http1.1)" sh -c "echo | timeout 8 openssl s_client -connect 127.0.0.1:$LB_PORT -servername '$DOMAIN' -alpn h2,http/1.1 2>/dev/null | grep -E 'Protocol|ALPN|Verify return|subject=|issuer='"
fi
run "сертификат" sh -c 'openssl x509 -in /etc/nginx/cert/cert.pem -noout -subject -issuer -dates 2>&1'

sec "Исходящая сеть и DNS (xray ходит наружу через них)"
if [ "${VWN_REPORT_SKIP_NET:-0}" = "1" ]; then
    echo "(пропущено: VWN_REPORT_SKIP_NET=1)"
else
    run "getent hosts" sh -c 'getent hosts cloudflare.com | head -1 || echo "системный DNS не отвечает"'
    run "TCP до DNS 1.1.1.1:53 / 9.9.9.9:53" sh -c 'for h in 1.1.1.1 9.9.9.9; do timeout 3 bash -c "</dev/tcp/$h/53" 2>/dev/null && echo "$h tcp/53 ok" || echo "$h tcp/53 FAIL"; done'
    if have dig; then
        run "UDP DNS 1.1.1.1" sh -c 'dig +time=2 +tries=1 @1.1.1.1 cloudflare.com +short | head -2 || true'
        run "UDP DNS 9.9.9.9" sh -c 'dig +time=2 +tries=1 @9.9.9.9 cloudflare.com +short | head -2 || true'
    else
        echo; echo "(dig не установлен — UDP DNS не проверен)"
    fi
    echo; echo "HTTPS наружу IPv4: $(code -4 https://cloudflare.com)"
    echo "HTTPS наружу IPv6: $(code -6 https://cloudflare.com)"
    run "resolv.conf" sh -c 'grep -v "^#" /etc/resolv.conf'
    run "резолвер 127.0.0.53" sh -c 'ss -lunH 2>/dev/null | grep -c "127.0.0.53:53" | sed "s/^/слушает (кол-во): /"'
fi

sec "Сеть / firewall"
run "ip addr" sh -c 'ip -br addr 2>&1'
run "MTU" sh -c "ip -o link | awk '{print \$2, \$4, \$5}'"
run "route" sh -c 'ip route show default 2>&1'
run "ufw" sh -c 'ufw status verbose 2>&1 | head -30'
run "iptables (INPUT/OUTPUT)" sh -c 'iptables -S 2>&1 | grep -E "^-P|DROP|REJECT" | head -20'

sec "Логи (последние строки)"
run "journal: xray-grpc/xhttp/reality/ws (warning+, 24ч)" sh -c 'journalctl -u xray-grpc -u xray-xhttp -u xray-reality -u xray-ws --since "24 hours ago" -p warning --no-pager -o short -n 40 2>&1 | cut -c1-220'
run "journal: nginx (24ч)" sh -c 'journalctl -u nginx --since "24 hours ago" --no-pager -o short -n 20 2>&1 | cut -c1-220'
run "/var/log/xray/error.log" sh -c 'tail -n 25 /var/log/xray/error.log 2>&1 | cut -c1-260'
run "/var/log/xray/reality-error.log" sh -c 'tail -n 15 /var/log/xray/reality-error.log 2>&1 | cut -c1-260'
run "/var/log/nginx/error.log" sh -c 'tail -n 25 /var/log/nginx/error.log 2>&1 | cut -c1-260'

sec "Автовыводы"
cc="$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)"
if grep -q '"tcpCongestion"' "$XD"/*.json 2>/dev/null && ! echo " $cc " | grep -q ' bbr '; then
    echo "! В конфиге Xray задан tcpCongestion=bbr, а BBR в ядре недоступен → Xray не сможет принять соединения. Лечится: vwn rebuild"
fi
[ "$GRPC_NGX" = "no" ] && echo "! serviceName gRPC из xray не найден среди location nginx → 404. Лечится: vwn rebuild"
[ "$XH_NGX" = "no" ] && echo "! Путь XHTTP в xray не найден среди location nginx → 404. Лечится: vwn rebuild"
grep -q 'grpc_pass' "$NGX_CONF" 2>/dev/null || echo "! В nginx нет grpc_pass (нужен и для gRPC, и для XHTTP: proxy_pass их ломает)"
if [ -f "$XD/config.json" ]; then echo "! Остались следы WebSocket (config.json) → выполните vwn rebuild (переход на gRPC)"; fi
grep -q '"mode": "stream-one"\|"mode": "stream-up"\|"mode": "packet-up"' "$XD/xhttp.json" 2>/dev/null && echo "! Серверный XHTTP закреплён на одном режиме — должен быть auto"
if ! ss -ltn 2>/dev/null | grep -q ":$GRPC_PORT "; then echo "! Порт xray-grpc $GRPC_PORT никто не слушает (сервис упал?)"; fi
if ! ss -ltn 2>/dev/null | grep -q ":$LB_PORT "; then echo "! Порт nginx loopback $LB_PORT никто не слушает"; fi
g1="${G1%% *}"; g2="${G2%% *}"; g3="${G3%% *}"; g4="${G4%% *}"
if [ -n "$g1" ]; then
    if [ -n "$VE" ] && [ "$VE" != "none" ]; then
        echo "gRPC: VLESS Encryption включён — probe без handshake невозможен (ожидаемо)"
    elif [ "$g1" != "200" ]; then
        echo "! gRPC: xray-grpc отвечает $g1 (не 200) → проблема в самом Xray (сервис/конфиг/serviceName), смотрите журнал xray-grpc"
    elif [ "$g2" != "200" ]; then
        echo "! gRPC: xray-grpc в порядке, но через nginx $g2 → проблема в nginx (location/grpc_pass/сертификат/http2), смотрите nginx error.log"
    elif [ "$g3" != "200" ]; then
        echo "! gRPC: nginx в порядке, но через :443 $g3 → проблема в Reality dest (nginx loopback) / SNI / порте 443"
    elif [ "$g4" != "404" ]; then
        echo "! gRPC: путь без application/grpc отвечает $g4 (ждём 404) → в location нет проверки \$content_type, путь виден сканерам"
    else
        echo "gRPC: цепочка на сервере исправна (200 на всех уровнях) → причина снаружи: клиент (alpn=h2/sni/serviceName/mode), CDN (нужен gRPC в Cloudflare) или провайдер"
    fi
fi
if [ -n "$VE" ] && [ "$VE" != "none" ]; then echo "XHTTP: VLESS Encryption включён — probe без handshake невозможен (ожидаемо)"; else case "${X2%% *}" in 502|503|504|000) echo "! XHTTP: через nginx ${X2%% *} → nginx не достучался до xray-xhttp (порт/сервис) или нет grpc_pass";; esac; fi
echo "(если строк с '!' нет — проблема не в конфигурации; смотрите блоки проверок и логи выше)"
} > "$OUT" 2>&1

chmod 600 "$OUT"
echo "Готово: $OUT ($(wc -l < "$OUT") строк)"
echo "Покажите содержимое:  cat $OUT"
