FROM python:3.15-alpine AS base
WORKDIR /app
# Runtime dependencies, pinned to the versions the tests pass with.
RUN pip install --no-cache-dir Flask==3.1.3 PyJWT==2.15.1 cryptography==50.0.2
COPY mock_idp_server/ ./mock_idp_server/

# docker compose run --rm --build test
FROM base AS test
RUN pip install --no-cache-dir pytest==9.1.1 requests==2.34.2 Authlib==1.9.1 joserfc==1.7.7
COPY pytest.ini ./
COPY tests/ ./tests/
CMD ["pytest"]

# Optional check against a real Vault, see scripts/vault-check.sh
FROM base AS vault-check
RUN pip install --no-cache-dir requests==2.34.2
COPY vault_check/ ./vault_check/
CMD ["python", "vault_check/check.py"]

# Default target: the mock IdP itself.
FROM base AS runtime
RUN adduser -D idp && chown -R idp /app/mock_idp_server
USER idp
ENV MOCK_IDP_HOST=0.0.0.0
# Unbuffered stdout so lines show up at once in `docker compose logs`.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8081
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD wget -qO- http://127.0.0.1:${MOCK_IDP_PORT:-8081}/healthz || exit 1
CMD ["python", "mock_idp_server/app.py"]
