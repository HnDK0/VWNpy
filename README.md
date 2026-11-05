# VWNpy v0.2.0

CLI-панель управления Xray-стеком на Linux (Debian/Ubuntu). Автоматическая установка, конфигурация и обслуживание VPN-сервера с тремя протоколами, многопользовательским режимом, туннелями и защитой.

## Установка в 1 строку

```bash
bash <(curl -sL https://github.com/HnDK0/VWNpy/raw/main/install.sh) --domain your.domain
```

Свежий сервер Debian/Ubuntu — больше ничего не нужно. Скрипт сам установит python3 и python3-venv, соберёт venv (на Debian 12 / Ubuntu 24.04 системный pip заблокирован PEP 668), поставит wheel туда и запустит установку.

Или локально из репозитория:

```bash
git clone https://github.com/HnDK0/VWNpy.git && cd VWNpy
sudo bash install.sh --domain your.domain --cert-method standalone --bbr --fail2ban
```

После установки сервисы запускаются автоматически. Подписка доступна по `https://your.domain/sub/<label>_<token>.txt`.

## Выбор ядра

Активное ядро хранится в `vwn.conf` (`CORE=xray|mihomo`). По умолчанию — Xray.

```bash
vwn core status
vwn core list
vwn core set mihomo     # staged switch с проверкой и откатом
vwn core set xray
vwn core update --version v1.19.33
vwn core rollback
```

- **Xray** — полный набор: Reality/XHTTP/gRPC/WS, VLESS Encryption, MPTCP (`sockopt.tcpMptcp`), блокировка BitTorrent.
- **mihomo** — те же Reality/XHTTP/gRPC/WS и VLESS Encryption; MPTCP только outbound, отдельного правила BitTorrent нет. Ограничения видны в `vwn core status`.
- Подписки не меняются: `vless://` и mihomo-YAML ядро-независимы.
- Конфиги ядра — генерируемые артефакты: Xray JSON / mihomo YAML. Источник истины — `vwn.conf` + `users.conf`.

## Протоколы

| Протокол | Порт | Transport | Сервис |
|----------|------|-----------|--------|
| VLESS + Reality | 443 (публичный) | TCP (Vision) / XHTTP (self-steal, SNI=домен) | `xray-reality` |
| VLESS + gRPC + TLS | 50001 (loopback) | gRPC (`gun` / `multi`, h2) | `xray-grpc` |
| VLESS + XHTTP | 50002 (loopback) | XHTTP | `xray-xhttp` |
| VLESS + WS + TLS | 50003 (loopback) | WebSocket | `xray-ws` |

```
Порт 443
  └─ Xray Reality (self-steal: SNI = домен, target = nginx 127.0.0.1:8443)
       ├─ прошедшие Reality (Vision) → xray-reality (VLESS)
       └─ остальное → nginx 127.0.0.1:8443 (настоящий сертификат домена)
            ├─ /sub/*            — подписки
            ├─ /<serviceName>/*  → xray-grpc :50001 (grpc_pass, h2c)
            ├─ /<xhttp-path>     → xray-xhttp :50002 (grpc_pass, h2c)
            └─ /<ws-path>        → xray-ws :50003 (WebSocket)
```

## Self-steal (Reality)

SNI Reality всегда равен домену сервера (`--domain`): зонд получает ваш реальный
сайт с сертификатом, совпадающим с SNI. Отдельный «домен-камуфляж»
(`--reality-dest`) больше не используется; смена домена выполняется через
`vwn` меню («Сменить домен») или `update_domain()` и требует перевыпущенного
SSL-сертификата.

## Прямой доступ и CDN

По умолчанию без CDN публикуется только XHTTP (прямой) и Reality-XHTTP.
WS и gRPC публикуются только при включённом CDN. CDN терминирует TLS и видит
внешний VLESS-поток, поэтому для скрытия содержимого включайте VLESS
Encryption (по умолчанию для XHTTP/gRPC/WS; Reality остаётся `none`).
`support-x25519mlkem768` у Reality остаётся отдельным PQ key exchange.

### CDN и `noGRPCHeader`

Для CDN XHTTP включается `noGRPCHeader=false`: Cloudflare пропускает
`stream-one` только как gRPC. Для direct XHTTP и Reality-XHTTP остаётся
`true`. Режимы direct/CDN настраиваются отдельно: `XHTTP_MODE` и
`XHTTP_CDN_MODE`. `stream-one` через CF работает только при
`noGRPCHeader=false` и включённом **Cloudflare Network → gRPC**. Если
проблемы — используйте `auto`/`packet-up` для CDN.

## VLESS Encryption

VLESS Encryption (`mlkem768x25519plus`) включена по умолчанию для
**XHTTP, gRPC и WS**. Для Reality она остаётся `none`: Reality уже даёт
TLS 1.3, и так же поступает X-Panel.

Существующие установки получают VE через `vwn rebuild`, если ключи ещё не
настроены. `VLESS_DECRYPTION=none` считается явным отключением и не
перезаписывается. Управление:

```bash
vwn vless-enc status
vwn vless-enc on [--force-new-keys]
vwn vless-enc off
```

`vwn vless-enc status` показывает раздельно: `XHTTP/gRPC/WS: on`,
`Reality: none`. `--force-new-keys` нужен только при потере
`VLESS_ENCRYPTION`. Включение — жёсткий переход для XHTTP/gRPC/WS: клиенты
должны поддерживать VE и переимпортировать подписку. Откат:
`vwn vless-enc off`, `vwn sub rebuild`, переимпорт. Если ядро не
поддерживает `xray vlessenc`, сначала `vwn update-xray`.

## Выключение Reality

Reality — публичный вход на 443. При выключении `vwn` переводит nginx с
`127.0.0.1:8443` на `0.0.0.0:443`, поэтому XHTTP/gRPC/WS и подписки
продолжают работать, а Reality-ссылка исчезает. При включении nginx
возвращается на loopback, а Xray Reality снова занимает 443.

```bash
vwn menu   # Reality → Отключить / Включить
```

Если nginx не может занять 443, операция завершится ошибкой проверки
`nginx -t`; сначала освободите порт.

## Переход с WebSocket на gRPC

На сервере со старой версией выполните `vwn rebuild`: сервис `xray-ws` и `config.json` удаляются, создаются `xray-grpc` и `grpc.json`, nginx и подписки пересобираются. Старые WS-ссылки перестанут работать — клиентам нужно обновить подписку.

## Системные требования

- Debian 12+ или Ubuntu 22.04 / 24.04
- Root-доступ
- Python 3 — устанавливается автоматически

## Аргументы установки

`vwn install` поддерживает флаги двух типов.

### Обязательные

| Флаг | Описание |
|------|----------|
| `--domain` | Ваш домен (A-запись на сервер) |

### Конфигурация

| Флаг | По умолчанию | Описание |
|------|-------------|----------|
| `--stub` | `https://httpbin.org/` | Сайт-заглушка для fallback |
| `--cert-method` | `standalone` | `standalone` / `cf` / `self` |
| `--cf-email` | — | Email Cloudflare (при `--cert-method cf`) |
| `--cf-key` | — | API Key Cloudflare (при `--cert-method cf`) |
| `--ssh-port` | `22` | Порт SSH |

### Туннели

| Флаг | Описание |
|------|----------|
| `--psiphon` | Установить Psiphon tunnel |
| `--psiphon-country` | Страна Psiphon (2 буквы: `DE`, `NL`, `US`) |
| `--psiphon-warp` | Psiphon поверх WARP (несовместимо с `--no-warp`) |
| `--no-warp` | Не устанавливать WARP |
| `--no-vless-enc` | Отключить VLESS Encryption при установке |


### Безопасность

| Флаг | Описание |
|------|----------|
| `--bbr` | Включить BBR |
| `--fail2ban` | Установить и настроить Fail2Ban |
| `--jail` | Включить WebJail (nginx) |
| `--ipv6` | Не отключать IPv6 |
| `--cpu-guard` | Включить CPU Guard (CPUWeight) |

### Примеры

```bash
# Минимальная установка
vwn install --domain vpn.example.com

# Полная: BBR + Fail2Ban + Cloudflare cert
vwn install --domain vpn.example.com --bbr --fail2ban --cert-method cf --cf-email user@example.com --cf-key 123abc

# С туннелями
vwn install --domain vpn.example.com --psiphon --psiphon-country DE
```

## CLI команды

```
vwn --version              Показать версию
vwn install [флаги...]     Установка стека
vwn status                 Диагностика (сервисы, сертификат, пользователи, подписки)
vwn menu                   TUI-меню (Rich)
vwn provision [--domain]   Перегенерация конфигов Xray
vwn rebuild               Пересобрать конфиги; на старой установке с WS — переход на gRPC
vwn qr [--type]            QR-код первого конфига (reality/grpc/xhttp)
vwn sub rebuild            Пересобрать подписки для всех пользователей
vwn backup                 Резервное копирование
vwn restore                Восстановление из бэкапа
vwn update                 Обновление VWNpy с git (git pull + pip install)
vwn update-xray            Обновление Xray-core до последней версии
vwn update-mihomo          Обновление mihomo до последней версии
vwn open-80                Открыть порт 80 в UFW (хук acme.sh)
vwn close-80               Закрыть порт 80 в UFW (хук acme.sh)
```

## Пользователи

Конфигурация: `/usr/local/etc/xray/users.conf` (формат `UUID|label|token`).

Каждый пользователь получает:
- Уникальный UUID для Reality, gRPC и XHTTP
- Token подписки
- `.txt` (base64) + `.html` (с QR и ссылками)
- Имя конфига с флагом страны (`🇲🇩 VL-gRPC | phone`)

Управление через `vwn menu` или напрямую через `vwn.modules.users`.

## Туннели

| Модуль | Методы |
|--------|--------|
| WARP | native (wgcf), amnezia (kernel/userspace), warp-svc |
| Psiphon | socks5 прокси |
| Tor | obfs4 / snowflake / meek_lite, мосты, страны |
| Relay | vless / vmess / trojan / socks URL |

Режимы туннелей: Global, Split (по доменам), OFF.

## Модули проекта

| Модуль | Назначение |
|--------|-----------|
| `vwn.cli` | Click-диспетчер |
| `vwn.install` | Установщик (4 фазы) |
| `vwn.core.config` | CRUD `/usr/local/etc/xray/vwn.conf` |
| `vwn.core.shell` | subprocess (без shell=True) |
| `vwn.core.system` | Пакеты, nginx, xray, DNS, swap |
| `vwn.core.cert` | SSL (self / standalone / Cloudflare) |
| `vwn.modules.xray` | Генерация конфигов + systemd units |
| `vwn.modules.users` | Multi-user CRUD |
| `vwn.modules.sub` | Подписки (VLESS URL, base64, HTML) |
| `vwn.modules.warp` | WARP tunnel |
| `vwn.modules.psiphon` | Psiphon tunnel |
| `vwn.modules.tor` | Tor tunnel |
| `vwn.modules.relay` | Relay tunnel |
| `vwn.modules.cdn` | CDN Cloudflare (scanner, watchdog) |
| `vwn.modules.security` | BBR, Fail2Ban, UFW, CPU Guard, IPv6 |
| `vwn.modules.privacy` | Privacy mode |
| `vwn.modules.diag` | Диагностика |
| `vwn.tui.menu` | Rich TUI (15 подменю) |

## Конфиги и пути

<details>
<summary>VWN / Xray — <code>/usr/local/etc/xray/</code></summary>

| Путь | Назначение |
|------|-----------|
| `/usr/local/etc/xray/vwn.conf` | главный конфиг VWN (ключ=значение, chmod 600) |
| `/usr/local/etc/xray/users.conf` | пользователи: `UUID\|label\|token` |
| `/usr/local/etc/xray/xray-reality.json` | конфиг Xray Reality (443) |
| `/usr/local/etc/xray/grpc.json` | конфиг Xray gRPC (50001) |
| `/usr/local/etc/xray/xhttp.json` | конфиг Xray XHTTP (50002) |
| `/usr/local/etc/xray/sub/` | подписки: `.txt` (base64) + `.html` (QR) |
| `/usr/local/etc/xray/connect_host` | хост подключения |
| `/usr/local/etc/xray/relay.json`, `relay.conf` | relay-туннель |
| `/usr/local/etc/xray/psiphon.json`, `psiphon_config.json`, `psiphon_country`, `psiphon_mode` | Psiphon |
| `/usr/local/etc/xray/tor_domains.txt` | домены Tor (split) |
| `/usr/local/etc/xray/.dns_configured` | маркер настройки DNS |

</details>

<details>
<summary>Nginx — <code>/etc/nginx/</code></summary>

| Путь | Назначение |
|------|-----------|
| `/etc/nginx/nginx.conf` | основной конфиг nginx |
| `/etc/nginx/conf.d/xray.conf` | loopback: gRPC / XHTTP / sub |
| `/etc/nginx/conf.d/sub_map.conf` | маппинг подписок |
| `/etc/nginx/cert/` | сертификаты TLS |

</details>

<details>
<summary>Systemd — <code>/etc/systemd/</code></summary>

| Путь | Назначение |
|------|-----------|
| `/etc/systemd/system/xray-reality.service` (+ `.d/cpuguard.conf`, `no-journal.conf`) | сервис Reality |
| `/etc/systemd/system/xray-grpc.service` | сервис gRPC |
| `/etc/systemd/system/xray-xhttp.service` | сервис XHTTP |
| `/etc/systemd/system/nginx.service` | nginx |
| `/etc/systemd/system/psiphon.service` | Psiphon |
| `/etc/systemd/system/vwn-cdn-watch.service` / `.timer` | CDN watchdog |
| `/etc/systemd/system/var-log-xray.mount` | монтирование логов Xray |
| `/etc/systemd/system/user.slice.d/cpuguard.conf` | CPU Guard для юзер-слайса |
| `/etc/systemd/resolved.conf.d/99-vwn-dns.conf` | DNS-резолвер |

</details>

<details>
<summary>Безопасность / система</summary>

| Путь | Назначение |
|------|-----------|
| `/etc/fail2ban/jail.local` | Fail2Ban jail |
| `/etc/fail2ban/filter.d/nginx-probe.conf` | фильтр nginx-probe |
| `/etc/sysctl.d/99-vwn-ipv6.conf` | отключение IPv6 |
| `/etc/sysctl.conf` | BBR и прочие sysctl |
| `/etc/ssh/sshd_config` | SSH (порт) |
| `/etc/logrotate.d/xray` | ротация логов Xray |
| `/etc/cron.d/acme-renew`, `clear-logs` | cron-задачи |
| `/etc/tor/torrc` | Tor |
| `/etc/vwn/warp-keys.env` | ключи WARP |
| `/root/vwn_backups/` | резервные копии |

</details>

## Тесты

```bash
pip install -e .
pytest                          # 184 локальных теста
```

## Сборка wheel

```bash
pip install build
python -m build
# → dist/vwnpy-0.2.0-py3-none-any.whl
```

## Лицензия

MIT
