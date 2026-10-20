#!/usr/bin/env bash
# Optional: logs in through a real Vault (dev mode) using the mock IdP. Needs only docker.
set -euo pipefail
cd "$(dirname "$0")/.."

# Vault resolves the IdP through the compose network, so the issuer must be the service name.
export MOCK_IDP_ISSUER=http://mock-idp:8081
trap 'docker compose --profile vault down -v' EXIT
docker compose --profile vault up --build --abort-on-container-exit --exit-code-from vault-check vault-check
