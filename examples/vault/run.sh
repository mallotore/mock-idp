#!/usr/bin/env bash
# Logs in through a real Vault (dev mode) using the mock IdP. Needs only docker.
set -euo pipefail
cd "$(dirname "$0")/../.."

compose=(docker compose -f docker-compose.yml -f examples/vault/docker-compose.yml)
trap '"${compose[@]}" down -v' EXIT
"${compose[@]}" up --build --abort-on-container-exit --exit-code-from vault-check vault-check
