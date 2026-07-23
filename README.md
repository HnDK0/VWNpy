# VWNpy v0.2.0

CLI-панель управления Xray-стеком на Linux (Debian/Ubuntu). Автоматическая установка, конфигурация и обслуживание VPN-сервера с тремя протоколами, многопользовательским режимом, туннелями и защитой.

## Установка в 1 строку

```bash
bash <(curl -sL https://github.com/HnDK0/VWNpy/raw/main/install.sh) --domain your.domain
```

Свежий сервер Debian/Ubuntu — больше ничего не нужно. Скрипт сам установит python3, скачает wheel из GitHub Releases и запустит установку.

Или локально из репозитория:

```bash
git clone https://github.com/HnDK0/VWNpy/VWNpy.git && cd VWNpy
sudo bash install.sh --domain your.domain --cert standalone --bbr --fail2ban
```

После установки сервисы запускаются автоматически. Подписка доступна по `https://your.domain/sub/<label>_<token>.txt`.

## Протоколы

| Протокол | Порт | Transport | Сервис |
|----------|------|-----------|--------|
| VLESS + Reality | 443 (публичный) | TCP + XHTTP fallback | `xray-reality` |
| VLESS + WS + TLS | 50001 (loopback) | WebSocket | `xray-ws` |
| VLESS + XHTTP | 50002 (loopback) | XHTTP | `xray-xhttp` |

```
Порт 443
  └─ Xray Reality
       └─ fallback → nginx 127.0.0.1:8443
            ├─ /sub/*        — подписки
            ├─ /v2/api/ws/*  → xray-ws :50001
            └─ /v2/api/xh/*  → xray-xhttp :50002
```

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
| `--lang` | `ru` | Язык (`ru` / `en`) |
| `--reality-dest` | `microsoft.com:443` | Fallback-домен Reality |
| `--reality-port` | `443` | Порт Reality |
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
vwn qr [--type]            QR-код первого конфига (reality/ws/xhttp)
vwn sub rebuild            Пересобрать подписки для всех пользователей
vwn backup                 Резервное копирование
vwn restore                Восстановление из бэкапа
vwn update                 Обновление модулей
vwn open-80                Открыть порт 80 в UFW (хук acme.sh)
vwn close-80               Закрыть порт 80 в UFW (хук acme.sh)
```

## Пользователи

Конфигурация: `/usr/local/etc/xray/users.conf` (формат `UUID|label|token`).

Каждый пользователь получает:
- Уникальный UUID для Reality, WS и XHTTP
- Token подписки
- `.txt` (base64) + `.html` (с QR и ссылками)
- Имя конфига с флагом страны (`🇲🇩 VL-WS | phone`)

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
