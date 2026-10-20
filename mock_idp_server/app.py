#!/usr/bin/env python3
import logging
from flask import Flask
import config, prepare_mock_idp
from oidc import oidc_bp, validate_config

def create_app():
  validate_config()
  prepare_mock_idp.main()
  app = Flask(__name__)
  app.register_blueprint(oidc_bp)
  return app

if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO, format="%(message)s")
  app = create_app()
  print(f"Mock OIDC IdP server running http://{config.HOST}:{config.APP_PORT} (issuer {config.ISSUER})")
  app.run(host=config.HOST, port=config.APP_PORT, debug=config.DEBUG)
