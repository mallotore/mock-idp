import json

import jwt
import pytest

from mock_idp import keys
from mock_idp.settings import Settings
from helpers import KEY_ID


@pytest.fixture
def settings(tmp_path):
  return Settings(key_dir=tmp_path / "nested" / "keys")


@pytest.fixture
def key_dir(settings):
  return settings.key_dir


def test_creates_key_dir_private_key_and_jwks(settings, key_dir):
  keys.prepare(settings)
  assert (key_dir / "private.pem").exists()
  key = json.loads((key_dir / "jwks.json").read_text())["keys"][0]
  assert key["kid"] == KEY_ID and key["alg"] == "RS256" and key["use"] == "sig"


def test_jwks_public_key_matches_the_private_key(settings, key_dir):
  keys.prepare(settings)
  token = jwt.encode({"a": 1}, (key_dir / "private.pem").read_bytes(), algorithm="RS256")
  public = jwt.PyJWK(json.loads((key_dir / "jwks.json").read_text())["keys"][0]).key
  assert jwt.decode(token, public, algorithms=["RS256"]) == {"a": 1}


def test_second_run_reuses_the_existing_key(settings, key_dir):
  keys.prepare(settings)
  first = (key_dir / "private.pem").read_bytes()
  jwks = (key_dir / "jwks.json").read_text()
  keys.prepare(settings)
  assert (key_dir / "private.pem").read_bytes() == first
  assert (key_dir / "jwks.json").read_text() == jwks


def test_private_key_is_owner_only_and_leaves_no_temp_file(settings, key_dir):
  keys.prepare(settings)
  assert (key_dir / "private.pem").stat().st_mode & 0o777 == 0o600
  assert not list(key_dir.glob("*.tmp"))
