from flask import Flask
from . import config, keys
from .errors import register_error_handlers
from .routes import oidc_bp
from .users import UsersFileError, load_users

def validate_config() -> None:
  """Fails fast at start-up instead of on the first request."""
  try:
    load_users()
  except UsersFileError as e:
    config.fail(str(e))

def create_app() -> Flask:
  validate_config()
  keys.main()
  app = Flask(__name__)
  register_error_handlers(app)
  app.register_blueprint(oidc_bp)
  return app
