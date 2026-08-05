#!/usr/bin/env bash
# =================================================================
# install.sh — bootstrap VWNpy
# Работает двумя способами:
#   1. Локально:  sudo bash install.sh --domain vpn.example.com
#   2. Удалённо:  bash <(curl -sL https://cln.sh/...) --domain vpn.example.com
#
# Ставит python3 + python3-venv, скачивает wheel из GitHub Releases,
# ставит его в выделенный venv (PEP 668), запускает vwn install.
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

# 1. python3 + python3-venv (venv нужен из-за PEP 668 на Debian 12/Ubuntu 24.04)
if ! command -v python3 &>/dev/null; then
  apt-get update -qq
fi
if ! command -v python3 &>/dev/null; then
  echo ">>> Установка python3..."
  apt-get install -y -qq python3
fi
if ! dpkg -s python3-venv &>/dev/null; then
  echo ">>> Установка python3-venv..."
  apt-get install -y -qq python3-venv
fi

# 2. curl + unzip + nano (нужны для скачивания wheel и редактирования списков)
if ! command -v curl &>/dev/null || ! command -v unzip &>/dev/null || ! command -v nano &>/dev/null; then
  echo ">>> Установка curl, unzip, nano..."
  apt-get install -y -qq curl unzip nano
fi

# 3. Скачать и установить wheel (или из локальной папки) в выделенный venv
#    venv — из-за PEP 668 (Debian 12/Ubuntu 24.04) системный pip не работает.
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="/usr/local/lib/vwnpy/venv"

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q

if [[ -f "$SRC_DIR/dist/"*.whl ]]; then
  WHL=$(ls "$SRC_DIR"/dist/*.whl | head -1)
  echo ">>> Установка из локального wheel: $WHL"
  "$VENV_DIR/bin/pip" install --quiet --force-reinstall "$WHL"
elif [[ -f "$SRC_DIR/pyproject.toml" ]]; then
  echo ">>> Установка из исходников: $SRC_DIR"
  "$VENV_DIR/bin/pip" install --quiet "$SRC_DIR"
else
  echo ">>> Скачивание wheel из GitHub Releases..."
  TMPDIR=$(mktemp -d)
  curl -sL "$REPO/releases/latest/download/vwnpy-wheel.zip" -o "$TMPDIR/wheel.zip"
  unzip -q "$TMPDIR/wheel.zip" -d "$TMPDIR/wheel"
  "$VENV_DIR/bin/pip" install --quiet "$TMPDIR/wheel"/*.whl
  rm -rf "$TMPDIR"
fi

ln -sf "$VENV_DIR/bin/vwn" /usr/local/bin/vwn

# 4. Запуск установки
exec /usr/local/bin/vwn install "$@"
