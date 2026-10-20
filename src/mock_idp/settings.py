import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class ConfigError(Exception):
  """A setting is invalid; the message names it."""


def _int(environ: Mapping[str, str], name: str, default: int) -> int:
  raw = environ.get(name, str(default))
  try:
    return int(raw)
  except ValueError:
    raise ConfigError(f"{name} must be an integer, got {raw!r}") from None


@dataclass(frozen=True)
class Settings:
  port: int = 8081
  # Local runs listen on loopback only; the Docker image sets 0.0.0.0 (compose publishes on 127.0.0.1).
  host: str = "127.0.0.1"
  # URL the relying party (any OIDC application) uses to reach the IdP: discovery, token, jwks.
  # It is also the `iss` claim, so it must match the discovery URL the client is given.
  issuer: str = "http://127.0.0.1:8081"
  # URL the user's browser uses to reach /authorize. Differs from the issuer inside docker networks.
  public_url: str = "http://127.0.0.1:8081"
  client_id: str = "mock-idp-client"
  client_secret: str = "mock-idp-secret"
  code_ttl_seconds: int = 60
  token_ttl_seconds: int = 3600
  debug: bool = False
  # Optional JSON file with predefined users (see config/users.json) and an optional user
  # (by email) that is logged in automatically, skipping the login form.
  users_file: str | None = None
  auto_login: str | None = None
  key_dir: Path = field(default_factory=lambda: Path("mock_idp_files").resolve())

  def __post_init__(self) -> None:
    if self.debug and self.host not in LOOPBACK_HOSTS:
      raise ConfigError(
        f"MOCK_IDP_DEBUG exposes the Werkzeug debugger and needs a loopback MOCK_IDP_HOST, got {self.host!r}"
      )

  @property
  def private_key_path(self) -> Path:
    return self.key_dir / "private.pem"

  @property
  def jwks_path(self) -> Path:
    return self.key_dir / "jwks.json"

  @classmethod
  def from_env(cls, environ: Mapping[str, str] = os.environ) -> "Settings":
    port = _int(environ, "MOCK_IDP_PORT", 8081)
    issuer = environ.get("MOCK_IDP_ISSUER", f"http://127.0.0.1:{port}").rstrip("/")
    return cls(
      port=port,
      host=environ.get("MOCK_IDP_HOST", "127.0.0.1"),
      issuer=issuer,
      public_url=environ.get("MOCK_IDP_PUBLIC_URL", issuer).rstrip("/"),
      client_id=environ.get("MOCK_IDP_CLIENT_ID", "mock-idp-client"),
      client_secret=environ.get("MOCK_IDP_CLIENT_SECRET", "mock-idp-secret"),
      code_ttl_seconds=_int(environ, "MOCK_IDP_CODE_TTL", 60),
      token_ttl_seconds=_int(environ, "MOCK_IDP_TOKEN_TTL", 3600),
      debug=environ.get("MOCK_IDP_DEBUG", "false").lower() == "true",
      users_file=environ.get("MOCK_IDP_USERS_FILE") or None,
      auto_login=environ.get("MOCK_IDP_AUTO_LOGIN") or None,
      key_dir=Path(environ.get("MOCK_IDP_KEY_DIR", "mock_idp_files")).resolve(),
    )
