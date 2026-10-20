#!/usr/bin/env bash
# Builds the real image, starts it and checks it answers. Catches packaging bugs unit tests cannot
# (missing templates, wrong paths, non-root permissions). Needs docker and curl.
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
grep "admin@example.com" <<<"$login_page" >/dev/null   # users.json mounted
echo "smoke test passed"
