from flask import Flask
from . import keys
from .oidc import oidc_bp, validate_config

def create_app():
  validate_config()
  keys.main()
  app = Flask(__name__)
  app.register_blueprint(oidc_bp)
  return app
