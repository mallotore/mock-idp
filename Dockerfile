FROM python:3.15-alpine AS base
WORKDIR /app
COPY scripts/requirements.py /usr/local/bin/
COPY pyproject.toml ./
RUN python -I /usr/local/bin/requirements.py pyproject.toml build runtime > /tmp/requirements.txt \
  && pip install --no-cache-dir -r /tmp/requirements.txt

FROM base AS test
RUN python -I /usr/local/bin/requirements.py pyproject.toml test > /tmp/requirements.txt \
  && pip install --no-cache-dir -r /tmp/requirements.txt
COPY README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
COPY tests/ ./tests/
CMD ["pytest"]

FROM base AS lint
RUN python -I /usr/local/bin/requirements.py pyproject.toml dev > /tmp/requirements.txt \
  && pip install --no-cache-dir -r /tmp/requirements.txt
COPY src/ ./src/
COPY tests/ ./tests/
COPY examples/ ./examples/
COPY scripts/ ./scripts/
CMD ["sh", "-c", "ruff check . && ruff format --check ."]

FROM base AS runtime
COPY README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps --no-build-isolation .
RUN adduser -D idp && mkdir -p /data/keys && chown idp /data/keys
USER idp
ENV MOCK_IDP_HOST=0.0.0.0
ENV MOCK_IDP_KEY_DIR=/data/keys
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 8081
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD wget -qO- http://127.0.0.1:${MOCK_IDP_PORT:-8081}/healthz || exit 1
CMD ["python", "-m", "mock_idp"]
