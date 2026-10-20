import logging
import os
from collections.abc import Mapping

from . import keys
from .app import create_app
from .settings import ConfigError, Settings
from .users import UsersFileError, validate_users_file


def main(environ: Mapping[str, str] = os.environ) -> None:
  logging.basicConfig(level=logging.INFO, format="%(message)s")
  try:
    settings = Settings.from_env(environ)
    validate_users_file(settings)
    keys.prepare(settings)
  except (ConfigError, UsersFileError, keys.KeysError) as e:
    raise SystemExit(f"mock-idp: invalid configuration: {e}") from None
  app = create_app(settings)
  print(f"Mock OIDC IdP server running http://{settings.host}:{settings.port} (issuer {settings.issuer})")
  app.run(host=settings.host, port=settings.port, debug=settings.debug)


if __name__ == "__main__":
  main()
