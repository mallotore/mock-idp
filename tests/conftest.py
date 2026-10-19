import threading

import pytest
from werkzeug.serving import make_server

import config, oidc, prepare_mock_idp
from app import create_app


@pytest.fixture(scope="session", autouse=True)
def keys(tmp_path_factory):
  """Generate a throwaway RSA key pair so tests never touch the real key dir."""
  key_dir = tmp_path_factory.mktemp("keys")
  patch = pytest.MonkeyPatch()
  patch.setattr(config, "KEY_DIR", key_dir)
  patch.setattr(config, "PRIVATE_KEY_PATH", key_dir / "private.pem")
  patch.setattr(config, "JWKS_PATH", key_dir / "jwks.json")
  prepare_mock_idp.main()
  yield
  patch.undo()


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
  oidc.store.clear()
  oidc.tokens.clear()
  oidc.next_user = None
  monkeypatch.setattr(config, "USERS_FILE", None)
  monkeypatch.setattr(config, "AUTO_LOGIN", None)


@pytest.fixture
def client():
  return create_app().test_client()


@pytest.fixture(scope="module")
def live_server():
  """The real app served over HTTP on a random local port; yields its base URL."""
  server = make_server("127.0.0.1", 0, create_app(), threaded=True)
  base_url = f"http://127.0.0.1:{server.server_port}"
  patch = pytest.MonkeyPatch()
  patch.setattr(config, "ISSUER", base_url)
  patch.setattr(config, "PUBLIC_URL", base_url)
  thread = threading.Thread(target=server.serve_forever, daemon=True)
  thread.start()
  yield base_url
  server.shutdown()
  thread.join()
  patch.undo()
