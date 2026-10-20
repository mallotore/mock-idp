import os
from pathlib import Path


def fail(message):
  raise SystemExit(f"mock-idp: invalid configuration: {message}")


def _int(name, default):
  raw = os.getenv(name, str(default))
  try:
    return int(raw)
  except ValueError:
    fail(f"{name} must be an integer, got {raw!r}")


APP_PORT = _int("MOCK_IDP_PORT", 8081)
# Local runs listen on loopback only; the Docker image sets 0.0.0.0 (compose publishes on 127.0.0.1).
HOST = os.getenv("MOCK_IDP_HOST", "127.0.0.1")

# URL the relying party (any OIDC application) uses to reach the IdP: discovery, token, jwks.
# It is also the `iss` claim, so it must match the discovery URL the client is given.
ISSUER = os.getenv("MOCK_IDP_ISSUER", f"http://127.0.0.1:{APP_PORT}").rstrip("/")
# URL the user's browser uses to reach /authorize. Differs from ISSUER inside docker networks.
PUBLIC_URL = os.getenv("MOCK_IDP_PUBLIC_URL", ISSUER).rstrip("/")

CLIENT_ID = os.getenv("MOCK_IDP_CLIENT_ID", "mock-idp-client")
CLIENT_SECRET = os.getenv("MOCK_IDP_CLIENT_SECRET", "mock-idp-secret")

CODE_TTL_SECONDS = _int("MOCK_IDP_CODE_TTL", 60)
TOKEN_TTL_SECONDS = _int("MOCK_IDP_TOKEN_TTL", 3600)
DEBUG = os.getenv("MOCK_IDP_DEBUG", "false").lower() == "true"
if DEBUG and HOST not in ("127.0.0.1", "localhost", "::1"):
  fail(f"MOCK_IDP_DEBUG exposes the Werkzeug debugger and needs a loopback MOCK_IDP_HOST, got {HOST!r}")

# Optional JSON file with predefined users (see config/users.json) and an optional user
# (by email) that is logged in automatically, skipping the login form.
USERS_FILE = os.getenv("MOCK_IDP_USERS_FILE") or None
AUTO_LOGIN = os.getenv("MOCK_IDP_AUTO_LOGIN") or None

KEY_DIR = Path(os.getenv("MOCK_IDP_KEY_DIR", "mock_idp_files")).resolve()
PRIVATE_KEY_PATH = KEY_DIR / "private.pem"
JWKS_PATH = KEY_DIR / "jwks.json"
KEY_ID = "mock-key-1"
