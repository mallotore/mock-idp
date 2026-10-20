import logging
from . import config
from .app import create_app

def main():
  logging.basicConfig(level=logging.INFO, format="%(message)s")
  app = create_app()
  print(f"Mock OIDC IdP server running http://{config.HOST}:{config.APP_PORT} (issuer {config.ISSUER})")
  app.run(host=config.HOST, port=config.APP_PORT, debug=config.DEBUG)

if __name__ == "__main__":
  main()
