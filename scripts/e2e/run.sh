#!/usr/bin/env bash
set -uo pipefail
cd /e2e
mkdir -p bin work nginx

XRAY_VER=v26.10.31
MIHOMO_VER=v1.19.33
case "$(uname -m)" in
  x86_64) XRAY_ARCH=64; MIHOMO_ARCH=amd64-compatible ;;
  aarch64|arm64) XRAY_ARCH=arm64-v8a; MIHOMO_ARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac
if [ ! -x bin/xray ]; then
  curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-${XRAY_ARCH}.zip" -o xray.zip
  unzip -q xray.zip -d bin && chmod +x bin/xray && rm -f xray.zip
fi
if [ ! -x bin/mihomo ]; then
  curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-${MIHOMO_ARCH}-${MIHOMO_VER}.gz" | gunzip > bin/mihomo
  chmod +x bin/mihomo
fi

cleanup() {
  pkill -9 -x mihomo 2>/dev/null || true
  pkill -9 -x xray 2>/dev/null || true
  sleep 1
}
cleanup

X25519_OUT="$(bin/xray x25519)"
PRIV="$(awk -F': *' 'tolower($1) ~ /private/ {print $2; exit}' <<< "$X25519_OUT")"
PUB="$(awk -F': *' 'tolower($1) ~ /(public|password)/ {print $2; exit}' <<< "$X25519_OUT")"
UUID="$(cat /proc/sys/kernel/random/uuid)"
SHORT=abcd1234

VE_OUT="$(bin/xray vlessenc)"
DEC="$(printf '%s\n' "$VE_OUT" | grep -A2 'Authentication: ML-KEM-768' | grep '"decryption"' | head -1 | sed -E 's/.*"decryption": "([^"]+)".*/\1/')"
ENC="$(printf '%s\n' "$VE_OUT" | grep -A2 'Authentication: ML-KEM-768' | grep '"encryption"' | head -1 | sed -E 's/.*"encryption": "([^"]+)".*/\1/')"
[ -n "$DEC" ] && [ -n "$ENC" ] || { echo "VE parse failed"; exit 1; }

# CA + server cert (like Let's Encrypt: CA-signed, valid for test.local)
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=VWN Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout nginx/ca.key -out nginx/ca.pem >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=test.local" \
  -keyout nginx/server.key -out nginx/server.csr >/dev/null 2>&1
printf 'subjectAltName=DNS:test.local,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n' > nginx/server.ext
openssl x509 -req -in nginx/server.csr -CA nginx/ca.pem -CAkey nginx/ca.key \
  -CAcreateserial -days 2 -extfile nginx/server.ext -out nginx/server.pem >/dev/null 2>&1
CERT_HEX="$(openssl x509 -in nginx/server.pem -outform DER | openssl dgst -sha256 | awk '{print $2}')"
echo "CERT_SHA256_HEX=$CERT_HEX"

cp nginx/ca.pem /usr/local/share/ca-certificates/vwn-test-ca.crt
update-ca-certificates >/dev/null 2>&1
grep -q 'test.local' /etc/hosts || echo '127.0.0.1 test.local' >> /etc/hosts
mkdir -p work/files && echo ok > work/files/ping.txt

# production-style nginx 1.30 config
mkdir -p nginx
cat > nginx/nginx.conf <<'EOF'
worker_processes 1;
error_log /e2e/nginx/error.log info;
pid /e2e/nginx/nginx.pid;
events { worker_connections 1024; }
http {
  access_log /e2e/nginx/access.log;
  server {
    listen 8443 ssl;
    http2 on;
    server_name test.local;
    ssl_certificate /e2e/nginx/server.pem;
    ssl_certificate_key /e2e/nginx/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    keepalive_timeout 30m;
    client_header_timeout 5m;

    location ^~ /xhttp {
      if ($request_method !~ ^(GET|POST)$) { return 404; }
      client_max_body_size 0;
      client_body_buffer_size 0;
      client_body_timeout 1w;
      grpc_read_timeout 1w;
      grpc_send_timeout 1w;
      grpc_buffer_size 64k;
      send_timeout 1w;
      grpc_set_header Host $host;
      grpc_pass grpc://127.0.0.1:50002;
    }

    location ^~ /GunService {
      if ($content_type !~ "^application/grpc") { return 404; }
      client_max_body_size 0;
      grpc_read_timeout 1w;
      grpc_send_timeout 1w;
      grpc_buffer_size 64k;
      grpc_set_header Host $host;
      grpc_pass grpc://127.0.0.1:50001;
    }

    location ^~ /ws {
      if ($http_upgrade !~* "websocket") { return 404; }
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host $host;
      proxy_buffering off;
      proxy_read_timeout 1w;
      proxy_send_timeout 1w;
      proxy_pass http://127.0.0.1:50003;
    }

    location / { return 200 "stub\n"; }
  }
  server {
    listen 127.0.0.1:9000;
    location /files/ { root /e2e/work; }
    location /upload/ {
      dav_methods PUT;
      client_max_body_size 0;
      root /e2e/work;
    }
  }
}
EOF
nginx -t -c /e2e/nginx/nginx.conf
if ss -ltn | grep -q ':8443 '; then nginx -s stop 2>/dev/null || true; sleep 1; fi
nginx -c /e2e/nginx/nginx.conf

run_server() {
  local VE="$1"
  local DEC_LINE=""
  [ "$VE" = "on" ] && DEC_LINE="    decryption: \"${DEC}\""
  cat > work/transports-server.yaml <<EOF
log-level: info
mode: rule
ipv6: false
external-controller: ""
allow-lan: false
mixed-port: 0
socks-port: 0
redir-port: 0
tproxy-port: 0
dns:
  enable: true
  nameserver: [1.1.1.1, 9.9.9.9]
rules:
  - MATCH,DIRECT
listeners:
  - name: reality-in
    type: vless
    listen: 0.0.0.0
    port: 443
    users:
      - username: test
        uuid: ${UUID}
        flow: xtls-rprx-vision
    reality-config:
      dest: 127.0.0.1:8443
      proxy: DIRECT
      private-key: ${PRIV}
      short-id: [${SHORT}]
      server-names: [test.local]
  - name: grpc-in
    type: vless
    listen: 127.0.0.1
    port: 50001
    allow-insecure: true
    grpc-service-name: GunService
${DEC_LINE}
    users:
      - username: test
        uuid: ${UUID}
  - name: xhttp-in
    type: vless
    listen: 127.0.0.1
    port: 50002
    allow-insecure: true
    xhttp-config:
      path: /xhttp
      mode: auto
${DEC_LINE}
    users:
      - username: test
        uuid: ${UUID}
  - name: ws-in
    type: vless
    listen: 127.0.0.1
    port: 50003
    allow-insecure: true
    ws-path: /ws
${DEC_LINE}
    users:
      - username: test
        uuid: ${UUID}
EOF
  bin/mihomo -t -f /e2e/work/transports-server.yaml -d /e2e/work || return 1
  bin/mihomo -d /e2e/work -f /e2e/work/transports-server.yaml > work/transports-server.log 2>&1 &
  SRV=$!
  sleep 2
  ss -ltn | grep -E ':(443|50001|50002|50003)' || { echo "listeners missing"; tail -30 work/transports-server.log; return 1; }
}

run_client() {
  local NAME="$1" CFG="$2"
  echo "===== ${NAME} ====="
  bin/xray run -c "$CFG" > "work/client-${NAME}.log" 2>&1 &
  local PID=$!
  sleep 2
  if curl -fsS --max-time 20 --socks5-hostname 127.0.0.1:10808 http://127.0.0.1:9000/files/ping.txt | grep -q ok; then
    echo " ${NAME}-OK"
  else
    echo " ${NAME}-FAIL"
    tail -20 "work/client-${NAME}.log"
  fi
  kill -9 $PID 2>/dev/null || true; wait $PID 2>/dev/null || true
  sleep 1
}

run_upload() {
  local NAME="$1" CFG="$2"
  echo "===== ${NAME} stream-up 120MB ====="
  mkdir -p work/upload
  dd if=/dev/zero of=work/upload-src.bin bs=1M count=120 status=none
  bin/xray run -c "$CFG" > "work/client-${NAME}-upload.log" 2>&1 &
  local PID=$!
  sleep 2
  if curl -fsS --max-time 120 --socks5-hostname 127.0.0.1:10808 \
       -T work/upload-src.bin http://127.0.0.1:9000/upload/blob.bin; then
    local got
    got=$(stat -c%s work/upload/blob.bin 2>/dev/null || echo 0)
    if [ "$got" = "125829120" ]; then
      echo " ${NAME}-upload-OK"
    else
      echo " ${NAME}-upload-SIZE-FAIL ($got)"
    fi
  else
    echo " ${NAME}-upload-FAIL"
    tail -20 "work/client-${NAME}-upload.log"
  fi
  kill -9 $PID 2>/dev/null || true; wait $PID 2>/dev/null || true
  sleep 1
}

make_client() {
  local NAME="$1" NET="$2" EXTRA="$3" ENC_VALUE="$4" ALPN="$5"
  cat > "work/client-${NAME}.json" <<EOF
{
  "log": {"loglevel": "info"},
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": true}}],
  "outbounds": [{
    "protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": 443, "users": [{"id": "${UUID}", "encryption": "${ENC_VALUE}"}]}]},
    "streamSettings": {
      "network": "${NET}",
      "security": "tls",
      "tlsSettings": {"serverName": "test.local", "fingerprint": "chrome", "alpn": ["${ALPN}"], "pinnedPeerCertSha256": "${CERT_HEX}"},
      ${EXTRA}
    }
  }]
}
EOF
}

make_reality_client() {
  cat > work/client-reality.json <<EOF
{
  "log": {"loglevel": "info"},
  "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": true}}],
  "outbounds": [{
    "protocol": "vless",
    "settings": {"vnext": [{"address": "127.0.0.1", "port": 443, "users": [{"id": "${UUID}", "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
    "streamSettings": {"network": "tcp", "security": "reality",
      "realitySettings": {"serverName": "test.local", "fingerprint": "chrome", "publicKey": "${PUB}", "shortId": "${SHORT}", "spiderX": "/"}}
  }]
}
EOF
}

for VE in off on; do
  echo "########## VE=${VE} ##########"
  cleanup
  run_server "$VE" || { echo "server failed"; cleanup; continue; }
  ENC_EFF="none"; [ "$VE" = "on" ] && ENC_EFF="$ENC"

  make_reality_client
  run_client "reality" "work/client-reality.json"

  make_client "xhttp" "xhttp" '"xhttpSettings": {"path": "/xhttp", "host": "test.local", "mode": "auto"}' "$ENC_EFF" "h2"
  run_client "xhttp" "work/client-xhttp.json"
  run_upload "xhttp" "work/client-xhttp.json"

  make_client "grpc" "grpc" '"grpcSettings": {"serviceName": "GunService"}' "$ENC_EFF" "h2"
  run_client "grpc" "work/client-grpc.json"

  make_client "ws" "ws" '"wsSettings": {"path": "/ws", "headers": {"Host": "test.local"}}' "$ENC_EFF" "http/1.1"
  run_client "ws" "work/client-ws.json"

  echo "--- server errors ---"
  grep -a -iE 'error|fail|invalid|reject|panic|decrypt' work/transports-server.log | tail -20 || true
  kill -9 $SRV 2>/dev/null || true; wait $SRV 2>/dev/null || true
  sleep 1
done

cleanup
