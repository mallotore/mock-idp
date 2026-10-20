import json

import jwt
import pytest
from joserfc.jwk import RSAKey

from mock_idp import keys
from mock_idp.settings import Settings


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
  assert key["alg"] == "RS256" and key["use"] == "sig"


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


def test_a_stale_world_readable_temp_file_does_not_leak_its_mode(settings, key_dir):
  key_dir.mkdir(parents=True)
  (key_dir / "private.tmp").write_text("stale")
  (key_dir / "private.tmp").chmod(0o644)
  keys.prepare(settings)
  assert (key_dir / "private.pem").stat().st_mode & 0o777 == 0o600


def test_a_failed_write_leaves_no_temp_file(settings, key_dir, monkeypatch):
  def fail(*args):
    raise OSError("disk full")

  monkeypatch.setattr(keys.os, "replace", fail)
  with pytest.raises(keys.KeysError, match="disk full"):
    keys.prepare(settings)
  assert not list(key_dir.glob("*"))


def test_jwks_document_has_one_rsa_signing_key(settings):
  keys.prepare(settings)
  [key] = json.loads(settings.jwks_path.read_text())["keys"]
  assert set(key) == {"kty", "use", "alg", "kid", "n", "e"}
  assert (key["kty"], key["use"], key["alg"]) == ("RSA", "sig", "RS256")
  assert key["e"] == "AQAB" and "=" not in key["n"]


def test_a_private_key_that_is_not_rsa_is_rejected(settings):
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import ec

  settings.key_dir.mkdir(parents=True)
  key = ec.generate_private_key(ec.SECP256R1())
  settings.private_key_path.write_bytes(
    key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
  )
  with pytest.raises(keys.KeysError, match="not an RSA private key"):
    keys.prepare(settings)


def test_a_private_key_that_is_not_pem_is_rejected(settings):
  settings.key_dir.mkdir(parents=True)
  settings.private_key_path.write_text("garbage")
  with pytest.raises(keys.KeysError, match="MOCK_IDP_KEY_DIR"):
    keys.prepare(settings)


def test_the_key_id_is_the_rfc_7638_thumbprint(settings):
  keys.prepare(settings)
  [key] = json.loads(settings.jwks_path.read_text())["keys"]
  assert key["kid"] == RSAKey.import_key({"kty": "RSA", "n": key["n"], "e": key["e"]}).thumbprint()
  assert key["kid"] == keys.key_id(keys.load_private_key(settings))


def test_a_new_key_gets_a_new_key_id(tmp_path):
  first, second = Settings(key_dir=tmp_path / "a"), Settings(key_dir=tmp_path / "b")
  keys.prepare(first)
  keys.prepare(second)
  [first_key], [second_key] = (json.loads(s.jwks_path.read_text())["keys"] for s in (first, second))
  assert first_key["kid"] != second_key["kid"]
