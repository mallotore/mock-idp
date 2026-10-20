import threading

import pytest
from werkzeug.serving import make_server

from mock_idp import keys
from mock_idp.app import create_app
from helpers import override_config, reset_state


def pytest_collection_modifyitems(items):
  """Marks every test with unit, api or e2e after the directory it lives in."""
  for item in items:
    kind = item.path.parent.name
    if kind in ("unit", "api", "e2e"):
      item.add_marker(getattr(pytest.mark, kind))


@pytest.fixture(scope="session", autouse=True)
def signing_keys(tmp_path_factory):
  """Generate a throwaway RSA key pair so tests never touch the real key dir."""
  key_dir = tmp_path_factory.mktemp("keys")
  patch = pytest.MonkeyPatch()
  override_config(patch, KEY_DIR=key_dir, PRIVATE_KEY_PATH=key_dir / "private.pem", JWKS_PATH=key_dir / "jwks.json")
  keys.main()
  yield
  patch.undo()


@pytest.fixture
def set_config(monkeypatch):
  """Overrides settings for one test: set_config(TOKEN_TTL_SECONDS=1)."""
  return lambda **overrides: override_config(monkeypatch, **overrides)


@pytest.fixture(autouse=True)
def clean_state(set_config):
  reset_state()
  set_config(USERS_FILE=None, AUTO_LOGIN=None)


@pytest.fixture
def client():
  return create_app().test_client()


@pytest.fixture(scope="module")
def live_server():
  """The real app served over HTTP on a random local port; yields its base URL."""
  server = make_server("127.0.0.1", 0, create_app(), threaded=True)
  base_url = f"http://127.0.0.1:{server.server_port}"
  patch = pytest.MonkeyPatch()
  override_config(patch, ISSUER=base_url, PUBLIC_URL=base_url)
  thread = threading.Thread(target=server.serve_forever, daemon=True)
  thread.start()
  yield base_url
  server.shutdown()
  thread.join()
  patch.undo()
