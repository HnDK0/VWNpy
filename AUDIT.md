# Аудит VWNpy

## Критические баги

### 1. Подписки — только WS, нет Reality/XHTTP

**Причина:** `cdn.py:apply_ip()` и `cdn.py:set_mode("off")` вызывали старый bash-скрипт
`source /usr/local/lib/vwn/core.sh && loadAllModules && rebuildAllSubFiles` для пересборки подписок.
Старый bash ищет Reality-конфиг по пути `/usr/local/etc/xray/reality.json`, а Python пишет его
в `/usr/local/etc/xray/xray-reality.json`. XHTTP старый bash ищет внутри `config.json` как
второй inbound, а Python пишет отдельно в `xhttp.json`. В результате bash-скрипт генерирует
только WS URL, перезаписывая корректные подписки от Python.

**Фикс:** Заменить вызов старого bash на `rebuild_all_sub_files()` из Python.

### 2. CDN — `_collect_candidates` фильтрует IP Cloudflare

**Причина:** В `cdn.py` функция `_collect_candidates` отфильтровывала IP через `not _is_cf_ip(ip)`,
хотя найденные IP и есть цель. Это блокировало `find_best()`.

**Фикс:** Убран фильтр `not _is_cf_ip`.

### 3. CDN — `init_sources` пишет CF_CIDRS в cdn_ranges.txt

**Причина:** Вместо хостинг-сетей (Hetnzer, DigitalOcean и т.д.) в `cdn_ranges.txt`
записывались диапазоны Cloudflare IP. `_generate_sample` генерировала IP из этих
диапазонов, но тут же их отфильтровывала через `_is_cf_ip`, возвращая пустой список.

**Фикс:** Убран блок записи CF_CIDRS. Файл поставляется с пакетом.

### 4. CDN — сканер не читает настройки из vwn.conf

**Причина:** `scan()` использовала хардкод `count=200, workers=40, timeout=3`.

**Фикс:** Читает `CDN_AUTOSCAN_COUNT`, `CDN_SCAN_PARALLEL`, `CDN_SCAN_TIMEOUT` из vwn.conf.

### 5. Reality mode "xhttp" — подписки генерировали tcp URL

**Причина:** `generate_reality_url()` всегда выдавала `&type=tcp&flow=xtls-rprx-vision`.
При `REALITY_MODE=xhttp` клиент должен получить `&type=xhttp&path=...&mode=...`.

**Фикс:** Добавлен параметр `mode` в `generate_reality_url()`. Когда режим `xhttp`,
генерируется URL с `type=xhttp` без `flow`. Обновлён `build_user_sub_file()` и `cli.py::url`.

### 6. sub.py — хардкод пути connect_host вместо константы

**Причина:** В `build_user_sub_file()` путь к файлу connect_host был захардкожен
как `/usr/local/etc/xray/connect_host` вместо использования `config.CONNECT_HOST_FILE`.

**Фикс:** Заменён на `config.CONNECT_HOST_FILE`.

### 7. Диагностика — вызывалась через subprocess

**Причина:** `menu.py choice 8` вызывала `_run_cmd("vwn status")` вместо прямого вызова
`run_full_diag()`. Это работало, но было неэффективно.

**Фикс:** Прямой import + вызов.

## SSH безопасность

- [x] SSH hardening: `PasswordAuthentication no`, `PermitRootLogin prohibit-password`
- [x] Добавлен `ssh_disable_password_auth()` в security.py
- [x] Добавлен пункт меню 15 в security_menu()
- [x] Диагностика показывает статус SSH

## UFW (брандмауэр)

- [x] `security.py:ufw_allow()` — синтаксис исправлен на `ufw allow 22/tcp` (было `22 tcp`)
- [x] `install.py:_setup_ufw()` — открывает ТОЛЬКО SSH порт (динамически) + 443
- [x] Порт 80 НЕ открыт постоянно — открывается только на время acme.sh standalone (cert.py)
- [x] SSH порт определяется динамически через `_parse_ssh_port()`
- [x] `cert.py` — `_acme_issue(standalone)` открывает 80 перед `--issue`, закрывает после

## Установка сертификата (acme.sh)

### Проблемы (исправлены):
- **DNS хостера глючит** — `curl https://get.acme.sh` падает с code 6 (DNS timeout)
- **ZeroSSL требует email** — новые версии acme.sh по умолчанию используют ZeroSSL, а не LE
- **cert.key не совпадал** — nginx ожидает `cert.key` и `chain.pem`, cert.py создавал `key.pem`

### Фиксы:
- [x] `cert.py:_ensure_acme()` — git clone fallback если curl get.acme.sh не работает
- [x] `cert.py:_ensure_acme()` — авто-установка git если его нет
- [x] `cert.py:_acme_issue()` — явный `--server letsencrypt` (обходим ZeroSSL)
- [x] `system.py:setup_system_dns()` — DNS: 8.8.8.8 primary, 1.1.1.1 fallback (было наоборот)
- [x] Пути сертификата: cert.pem / cert.key / chain.pem — соответствуют nginx конфигу

## Потерянный функционал из bash

### 1. Диагностика (`vwn status`)

Было в bash (модуль `diagnose.sh`):
- Все 6+ сервисов (xray-reality, xray-ws, xray-xhttp, nginx, warp, fail2ban)
- Туннели (Psiphon, Tor, Relay)
- SSL-сертификат с днями до истечения
- Конфиг (домен, reality dest/port, пользователи, IP)
- Подписки
- CDN (режим, IP, вотчер, кэш)
- Безопасность (BBR, Fail2Ban, WebJail, IPv6, CPU Guard)
- **Система** (uptime, disk, RAM)
- **Проверка сети** (ping до хостов, открытые порты)
- **Проверка соединений** (curl тесты через каждый протокол)
- **Статус GeoIP базы**
- **Статус DNS**
- **Проверка NGINX конфига** (nginx -t)
- **Проверка Xray конфигов** (xray test)

Текущий diag.py:
- [x] Сервисы
- [x] Туннели
- [x] SSL с днями
- [x] Конфиг
- [x] Подписки
- [x] CDN
- [x] Безопасность
- [x] Система (uptime, disk, RAM)
- [x] Проверка сети (DNS, порты)
- [x] Проверка соединений (internet, domain reachable)
- [x] GeoIP база
- [x] DNS
- [x] NGINX -t
- [x] Xray test

### 2. CDN меню

Было в bash:
- [x] Режимы (off/manual/auto_resolve/auto_scan)
- [~] Подменю «Авто — выбор списка» (стандартный/сканер/оба)
- [x] Подменю сканера (прогресс, настройки count/workers/timeout)
- [x] Просмотр/очистка found.txt
- [x] Редактирование cdn_ips.txt

### 3. Backup

- [x] Создание/восстановление/удаление через TUI
- [x] CLI команды (`vwn backup`, `vwn restore`)

### 4. Управление пользователями

- [x] CRUD
- [x] Подписки
- [ ] Показать QR код (встроенный qrencode)

## Замечания по архитектуре

### 1. Смешение Python и bash

`cdn.py` вызывает `rebuildAllSubFiles` через bash. Вся бизнес-логика должна быть
на Python, bash — только обёртка для systemd/shell.

**Фикс:** Все вызовы bash заменены на Python.

### 2. Пути конфигов

Python и bash используют разные пути для Reality-конфига:
- bash: `/usr/local/etc/xray/reality.json`  
- python: `/usr/local/etc/xray/xray-reality.json`

Это приводит к тому, что старый bash не видит Reality-конфиг.

### 3. Sub module

`build_user_sub_file()` использует `domain` как connect_host для WS/XHTTP.
При активном CDN должен использоваться CDN IP из `CONNECT_HOST_FILE`.

## Что ещё надо сделать

- [x] Переписать диагностику — добавлена проверка сети, xray test, nginx -t, GeoIP, DNS
- [x] `build_user_sub_file` — теперь читает `CONNECT_HOST_FILE` из config.py, WS/XHTTP идут на CDN IP
- [x] cleanup: удалён старый VWN bash-фреймворк из `/usr/local/lib/vwn/`
