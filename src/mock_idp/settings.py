import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class ConfigError(Exception):
  pass


def _int(environ: Mapping[str, str], name: str) -> int | None:
  raw = environ.get(name)
  if raw is None:
    return None
  try:
    return int(raw)
  except ValueError:
    raise ConfigError(f"{name} must be an integer, got {raw!r}") from None


@dataclass(frozen=True)
class Settings:
  port: int = 8081
  host: str = "127.0.0.1"
  issuer: str = ""
  public_url: str = ""
  client_id: str = "mock-idp-client"
  client_secret: str = "mock-idp-secret"
  code_ttl_seconds: int = 60
  token_ttl_seconds: int = 3600
  debug: bool = False
  users_file: str | None = None
  auto_login: str | None = None
  key_dir: Path = Path("mock_idp_files")

  def __post_init__(self) -> None:
    issuer = (self.issuer or f"http://127.0.0.1:{self.port}").rstrip("/")
    object.__setattr__(self, "issuer", issuer)
    object.__setattr__(self, "public_url", (self.public_url or issuer).rstrip("/"))
    object.__setattr__(self, "key_dir", Path(self.key_dir).resolve())
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
    debug = environ.get("MOCK_IDP_DEBUG")
    values: dict[str, Any] = {
      "port": _int(environ, "MOCK_IDP_PORT"),
      "host": environ.get("MOCK_IDP_HOST"),
      "issuer": environ.get("MOCK_IDP_ISSUER"),
      "public_url": environ.get("MOCK_IDP_PUBLIC_URL"),
      "client_id": environ.get("MOCK_IDP_CLIENT_ID"),
      "client_secret": environ.get("MOCK_IDP_CLIENT_SECRET"),
      "code_ttl_seconds": _int(environ, "MOCK_IDP_CODE_TTL"),
      "token_ttl_seconds": _int(environ, "MOCK_IDP_TOKEN_TTL"),
      "debug": None if debug is None else debug.lower() == "true",
      "users_file": environ.get("MOCK_IDP_USERS_FILE") or None,
      "auto_login": environ.get("MOCK_IDP_AUTO_LOGIN") or None,
      "key_dir": environ.get("MOCK_IDP_KEY_DIR"),
    }
    return cls(**{name: value for name, value in values.items() if value is not None})
