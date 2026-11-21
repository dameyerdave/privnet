#!/bin/bash
# Start a throw-away local privnet on http://127.0.0.1:8098 (fake WireGuard,
# DNS on 127.0.0.1:5398, unreachable ACME CA) with an empty database.
# Usage: tests/e2e/run-local.sh <work-dir>
set -euo pipefail
WORK=${1:?usage: run-local.sh <work-dir>}
mkdir -p "$WORK"
pkill -f "$WORK/privnet" 2>/dev/null || true
sleep 0.5
rm -f "$WORK"/ui.db "$WORK"/ui.db-wal "$WORK"/ui.db-shm
go build -o "$WORK/privnet" ./cmd/privnet
APP_SECRET=local-test-secret-123456 WG_ENDPOINT=83.228.201.62:51820 WG_MODE=fake \
DB_PATH="$WORK/ui.db" LISTEN_ADDR=127.0.0.1:8098 BASE_URL=http://127.0.0.1:8098 \
DNS_ZONE=ip.kizy.ch DNS_NAMESERVER=privnet-ns.kizy.ch DNS_PUBLIC_IP=179.237.118.172 DNS_LISTEN=127.0.0.1:5398 \
ACME_DIRECTORY=https://127.0.0.1:1/dir PROXY_LISTEN=127.0.0.1:8442 PROXY_HTTP_LISTEN= \
  nohup "$WORK/privnet" > "$WORK/privnet.log" 2>&1 &
sleep 1.5
echo "privnet running on http://127.0.0.1:8098 (log: $WORK/privnet.log)"
