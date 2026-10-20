import threading
from dataclasses import replace

import pytest
from werkzeug.serving import make_server

from mock_idp import keys
from mock_idp.app import create_app
from mock_idp.settings import Settings

from helpers import Clock


def pytest_collection_modifyitems(items):
  for item in items:
    kind = item.path.parent.name
    if kind in ("unit", "api", "e2e"):
      item.add_marker(getattr(pytest.mark, kind))


@pytest.fixture(scope="session")
def base_settings(tmp_path_factory):
  settings = Settings(key_dir=tmp_path_factory.mktemp("keys"))
  keys.prepare(settings)
  return settings


@pytest.fixture
def clock():
  return Clock()


@pytest.fixture
def make_app(base_settings, clock):
  return lambda **overrides: create_app(replace(base_settings, **overrides), now=clock.now)


@pytest.fixture
def app(make_app):
  return make_app()


@pytest.fixture
def client(app):
  return app.test_client()


class LateBoundApp:
  app = None

  def __call__(self, environ, start_response):
    return self.app(environ, start_response)


@pytest.fixture(scope="module")
def serve(base_settings):
  servers = []

  def start(**overrides):
    late_bound_app = LateBoundApp()
    server = make_server("127.0.0.1", 0, late_bound_app, threaded=True)
    base_url = f"http://127.0.0.1:{server.server_port}"
    settings = replace(base_settings, issuer=base_url, public_url=base_url, **overrides)
    late_bound_app.app = create_app(settings)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    servers.append((server, thread))
    return base_url

  yield start
  for server, thread in servers:
    server.shutdown()
    thread.join()


@pytest.fixture(scope="module")
def live_server(serve):
  return serve()
