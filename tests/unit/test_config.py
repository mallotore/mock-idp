import subprocess, sys

import pytest


def run_config(**env):
  return subprocess.run([sys.executable, "-c", "from mock_idp import config"], capture_output=True,
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
  result = subprocess.run([sys.executable, "-m", "mock_idp"], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "MOCK_IDP_USERS_FILE": str(tmp_path / "missing.json"),
                               "MOCK_IDP_KEY_DIR": str(tmp_path / "keys")})
  assert result.returncode != 0
  assert "cannot read users file" in result.stderr
  assert "ready to be used" not in result.stdout
  assert not (tmp_path / "keys").exists()


def test_key_dir_is_made_absolute(tmp_path):
  result = subprocess.run([sys.executable, "-c", "from mock_idp import config; print(config.JWKS_PATH.is_absolute())"],
                          capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "MOCK_IDP_KEY_DIR": "relative/keys"})
  assert result.stdout.strip() == "True"


def test_default_key_dir_is_mock_idp_files_in_the_working_directory(tmp_path):
  result = subprocess.run([sys.executable, "-c", "from mock_idp import config; print(config.KEY_DIR)"],
                          cwd=tmp_path, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
  assert result.stdout.strip() == str(tmp_path.resolve() / "mock_idp_files")


def test_create_app_generates_the_keys(tmp_path):
  keys = tmp_path / "keys"
  result = subprocess.run([sys.executable, "-c", "from mock_idp.app import create_app; create_app()"],
                          capture_output=True, text=True,
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
