#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

trap 'docker compose down -v' EXIT
docker compose up -d --build --wait mock-idp

base=http://127.0.0.1:8081
curl -fsS "$base/healthz" | grep ok >/dev/null
curl -fsS "$base/.well-known/openid-configuration" | grep '"issuer"' >/dev/null
curl -fsS "$base/jwks" | grep '"keys"' >/dev/null
login_page=$(curl -fsS "$base/authorize?redirect_uri=http://localhost/cb")
grep "Mock OIDC Login" <<<"$login_page" >/dev/null
grep "admin@example.com" <<<"$login_page" >/dev/null
echo "smoke test passed"
