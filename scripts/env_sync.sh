#!/usr/bin/env bash
# Bring .env up to date with .env.example without touching existing values:
#  1. append any key present in .env.example but missing from .env
#  2. fill each blank key named in the arguments with a random 32-hex-char value
set -euo pipefail

while IFS= read -r line; do
  key="${line%%=*}"
  if ! grep -q "^${key}=" .env; then
    echo "$line" >> .env
    echo "added ${key}"
  fi
done < <(grep -E '^[A-Z_]+=' .env.example)

for key in "$@"; do
  if grep -q "^${key}=$" .env; then
    value="$(openssl rand -hex 16)"
    sed -i '' "s|^${key}=$|${key}=${value}|" .env
    echo "generated ${key}"
  fi
done
