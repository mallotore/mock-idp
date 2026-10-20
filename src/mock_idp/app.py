import time
from collections.abc import Callable

from flask import Flask

from .errors import register_error_handlers
from .routes import oidc_bp
from .settings import Settings
from .stores import State


def create_app(settings: Settings, now: Callable[[], float] = time.time) -> Flask:
  app = Flask(__name__)
  app.extensions["mock_idp"] = State(settings, now)
  register_error_handlers(app)
  app.register_blueprint(oidc_bp)
  return app
