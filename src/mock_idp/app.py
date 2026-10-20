from flask import Flask
from . import prepare_mock_idp
from .oidc import oidc_bp, validate_config

def create_app():
  validate_config()
  prepare_mock_idp.main()
  app = Flask(__name__)
  app.register_blueprint(oidc_bp)
  return app
