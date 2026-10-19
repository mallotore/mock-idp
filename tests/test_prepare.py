import json
import subprocess, sys
from pathlib import Path

import jwt
import pytest

import config, prepare_mock_idp

SERVER_DIR = Path(config.__file__).parent


@pytest.fixture
def key_dir(tmp_path, monkeypatch):
  monkeypatch.setattr(config, "KEY_DIR", tmp_path / "nested" / "keys")
  monkeypatch.setattr(config, "PRIVATE_KEY_PATH", config.KEY_DIR / "private.pem")
  monkeypatch.setattr(config, "JWKS_PATH", config.KEY_DIR / "jwks.json")
  return config.KEY_DIR


def test_creates_key_dir_private_key_and_jwks(key_dir):
  prepare_mock_idp.main()
  assert (key_dir / "private.pem").exists()
  key = json.loads((key_dir / "jwks.json").read_text())["keys"][0]
  assert key["kid"] == config.KEY_ID and key["alg"] == "RS256" and key["use"] == "sig"


def test_jwks_public_key_matches_the_private_key(key_dir):
  prepare_mock_idp.main()
  token = jwt.encode({"a": 1}, (key_dir / "private.pem").read_bytes(), algorithm="RS256")
  public = jwt.PyJWK(json.loads((key_dir / "jwks.json").read_text())["keys"][0]).key
  assert jwt.decode(token, public, algorithms=["RS256"]) == {"a": 1}


def test_second_run_reuses_the_existing_key(key_dir):
  prepare_mock_idp.main()
  first = (key_dir / "private.pem").read_bytes()
  jwks = (key_dir / "jwks.json").read_text()
  prepare_mock_idp.main()
  assert (key_dir / "private.pem").read_bytes() == first
  assert (key_dir / "jwks.json").read_text() == jwks


def run_config(**env):
  return subprocess.run([sys.executable, "-c", "import config"], cwd=SERVER_DIR, capture_output=True,
                        text=True, env={"PATH": "/usr/bin:/bin", **env})


@pytest.mark.parametrize("name", ["MOCK_IDP_PORT", "MOCK_IDP_CODE_TTL", "MOCK_IDP_TOKEN_TTL"])
def test_non_numeric_settings_fail_with_a_clear_message(name):
  result = run_config(**{name: "abc"})
  assert result.returncode != 0
  assert f"{name} must be an integer" in result.stderr
  assert "Traceback" not in result.stderr


def test_valid_settings_import_cleanly():
  assert run_config(MOCK_IDP_PORT="9999").returncode == 0


def test_bad_users_file_fails_before_any_key_is_created(tmp_path):
  result = subprocess.run([sys.executable, "app.py"], cwd=SERVER_DIR, capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "MOCK_IDP_USERS_FILE": str(tmp_path / "missing.json"),
                               "MOCK_IDP_KEY_DIR": str(tmp_path / "keys")})
  assert result.returncode != 0
  assert "cannot read users file" in result.stderr
  assert "ready to be used" not in result.stdout
  assert not (tmp_path / "keys").exists()


def test_private_key_is_owner_only_and_leaves_no_temp_file(key_dir):
  prepare_mock_idp.main()
  assert (key_dir / "private.pem").stat().st_mode & 0o777 == 0o600
  assert not list(key_dir.glob("*.tmp"))


def test_key_dir_is_made_absolute(tmp_path):
  result = subprocess.run([sys.executable, "-c", "import config; print(config.JWKS_PATH.is_absolute())"],
                          cwd=SERVER_DIR, capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "MOCK_IDP_KEY_DIR": "relative/keys"})
  assert result.stdout.strip() == "True"


def test_create_app_generates_the_keys(tmp_path):
  keys = tmp_path / "keys"
  result = subprocess.run([sys.executable, "-c", "from app import create_app; create_app()"],
                          cwd=SERVER_DIR, capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "MOCK_IDP_KEY_DIR": str(keys)})
  assert result.returncode == 0, result.stderr
  assert (keys / "private.pem").exists() and (keys / "jwks.json").exists()


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5"])
def test_debug_is_refused_on_non_loopback_hosts(host):
  result = run_config(MOCK_IDP_DEBUG="true", MOCK_IDP_HOST=host)
  assert result.returncode != 0
  assert "MOCK_IDP_DEBUG" in result.stderr and "Traceback" not in result.stderr


def test_debug_is_allowed_on_loopback():
  assert run_config(MOCK_IDP_DEBUG="true").returncode == 0
