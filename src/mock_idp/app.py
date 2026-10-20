from flask import Flask
from . import keys
from .errors import register_error_handlers
from .routes import oidc_bp
from .settings import Settings
from .users import load_users

def create_app(settings: Settings) -> Flask:
  load_users(settings)  # fails fast on a broken users file, before any key is created
  keys.prepare(settings)
  app = Flask(__name__)
  app.config["MOCK_IDP"] = settings
  register_error_handlers(app)
  app.register_blueprint(oidc_bp)
  return app
