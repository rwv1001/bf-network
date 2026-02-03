#!/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NPM_DIR="$ROOT_DIR/npm"

mkdir -p "$NPM_DIR/data" "$NPM_DIR/letsencrypt"

cd "$NPM_DIR"
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose up -d
else
  echo "docker compose not found"
  exit 1
fi

echo "NPM directories created and containers started."
