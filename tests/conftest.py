import threading
from dataclasses import replace

import pytest
from werkzeug.serving import make_server

from mock_idp import keys
from mock_idp.app import create_app
from mock_idp.settings import Settings
from helpers import reset_state


def pytest_collection_modifyitems(items):
  """Marks every test with unit, api or e2e after the directory it lives in."""
  for item in items:
    kind = item.path.parent.name
    if kind in ("unit", "api", "e2e"):
      item.add_marker(getattr(pytest.mark, kind))


@pytest.fixture(scope="session")
def base_settings(tmp_path_factory):
  """Default settings with a throwaway key directory, so tests never touch the real one."""
  settings = Settings(key_dir=tmp_path_factory.mktemp("keys"))
  keys.prepare(settings)
  return settings


@pytest.fixture(autouse=True)
def clean_state():
  reset_state()


@pytest.fixture
def make_app(base_settings):
  """make_app(token_ttl_seconds=1) builds an app with some settings overridden."""
  return lambda **overrides: create_app(replace(base_settings, **overrides))


@pytest.fixture
def client(make_app):
  return make_app().test_client()


@pytest.fixture(scope="module")
def serve(base_settings):
  """serve(**overrides) serves a real app over HTTP on a random local port and returns its base URL."""
  servers = []

  def start(**overrides):
    # The issuer contains the port, which is only known once the socket is bound: bind first, build the app after.
    holder = {}
    server = make_server("127.0.0.1", 0, lambda environ, start_response: holder["app"](environ, start_response),
                         threaded=True)
    base_url = f"http://127.0.0.1:{server.server_port}"
    settings = replace(base_settings, issuer=base_url, public_url=base_url, **overrides)
    holder["app"] = create_app(settings)
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
  """The real app served over HTTP; yields its base URL."""
  return serve()
