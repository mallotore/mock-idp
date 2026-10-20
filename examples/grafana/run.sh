#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

compose=(docker compose -f docker-compose.yml -f examples/grafana/docker-compose.yml)
trap '"${compose[@]}" down -v' EXIT
"${compose[@]}" up --build --abort-on-container-exit --exit-code-from grafana-check grafana-check
