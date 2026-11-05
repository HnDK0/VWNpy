#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d "$HOME/.vwn-e2e.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

docker build -t vwn-e2e "$ROOT/scripts/e2e"
cp "$ROOT/scripts/e2e/run.sh" "$TMP/run.sh"
docker run --rm -v "$TMP:/e2e" vwn-e2e bash /e2e/run.sh
