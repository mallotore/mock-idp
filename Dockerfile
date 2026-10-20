FROM python:3.15-alpine AS base
WORKDIR /app
# Dependencies are pinned in pyproject.toml.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# docker compose run --rm --build test
FROM base AS test
RUN pip install --no-cache-dir ".[test]"
COPY tests/ ./tests/
CMD ["pytest"]

# Optional check against a real Vault, see scripts/vault-check.sh
FROM base AS vault-check
RUN pip install --no-cache-dir requests==2.34.2
COPY vault_check/ ./vault_check/
CMD ["python", "vault_check/check.py"]

# Default target: the mock IdP itself.
FROM base AS runtime
RUN adduser -D idp && mkdir -p /data/keys && chown idp /data/keys
USER idp
ENV MOCK_IDP_HOST=0.0.0.0
ENV MOCK_IDP_KEY_DIR=/data/keys
# Unbuffered stdout so lines show up at once in `docker compose logs`.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8081
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD wget -qO- http://127.0.0.1:${MOCK_IDP_PORT:-8081}/healthz || exit 1
CMD ["python", "-m", "mock_idp"]
