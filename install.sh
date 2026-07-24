#!/usr/bin/env bash
# =================================================================
# install.sh — bootstrap VWNpy
# Работает двумя способами:
#   1. Локально:  sudo bash install.sh --domain vpn.example.com
#   2. Удалённо:  bash <(curl -sL https://cln.sh/...) --domain vpn.example.com
#
# Ставит python3 + pip, скачивает wheel из GitHub Releases,
# pip install, запускает vwn install.
# =================================================================
set -euo pipefail

REPO="https://github.com/HnDK0/VWNpy"

usage() {
  cat <<EOF
Установка VWNpy — Xray VPN stack

  bash <(curl -sL ${REPO}/raw/main/install.sh) --domain your.domain [флаги...]

Флаги:
  --domain   Домен (A-запись на этот сервер)        [обязательный]
  --stub     Сайт-заглушка fallback                  [https://httpbin.org/]
  --cert-method  standalone / cf / self              [standalone]
  --bbr      Включить BBR                            [выкл]
  --fail2ban Установить Fail2Ban                      [выкл]
  --help     Показать справку

Полный список флагов: ${REPO}
EOF
  exit 0
}

[[ "$EUID" -eq 0 ]] || { echo "Ошибка: запустите от имени root (sudo bash install.sh)"; exit 1; }
[[ "$#" -eq 0 || "$1" == "--help" || "$1" == "-h" ]] && usage

# 1. python3 + pip
if ! command -v python3 &>/dev/null; then
  echo ">>> Установка python3..."
  apt-get update -qq && apt-get install -y -qq python3 python3-pip
fi
if ! command -v pip3 &>/dev/null; then
  echo ">>> Установка pip3..."
  apt-get install -y -qq python3-pip
fi
python3 -m pip install --upgrade pip -q

# 2. Скачать и установить wheel (или из локальной папки)
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SRC_DIR/dist/"*.whl ]]; then
  WHL=$(ls "$SRC_DIR"/dist/*.whl | head -1)
  echo ">>> Установка из локального wheel: $WHL"
  python3 -m pip install --quiet --force-reinstall "$WHL"
elif [[ -f "$SRC_DIR/pyproject.toml" ]]; then
  echo ">>> Установка из исходников: $SRC_DIR"
  python3 -m pip install --quiet "$SRC_DIR"
else
  echo ">>> Скачивание wheel из GitHub Releases..."
  TMPDIR=$(mktemp -d)
  curl -sL "$REPO/releases/latest/download/vwnpy-wheel.zip" -o "$TMPDIR/wheel.zip"
  unzip -q "$TMPDIR/wheel.zip" -d "$TMPDIR/wheel"
  python3 -m pip install --quiet "$TMPDIR/wheel"/*.whl
  rm -rf "$TMPDIR"
fi

# 3. Запуск установки
exec python3 -m vwn install "$@"
