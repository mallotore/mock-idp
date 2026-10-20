from flask import Flask
from .errors import register_error_handlers
from .routes import oidc_bp
from .settings import Settings

def create_app(settings: Settings) -> Flask:
  app = Flask(__name__)
  app.config["MOCK_IDP"] = settings
  register_error_handlers(app)
  app.register_blueprint(oidc_bp)
  return app
