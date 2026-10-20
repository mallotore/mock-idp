from dataclasses import replace
from pathlib import Path

import pytest

from mock_idp.settings import ConfigError, Settings


def test_defaults():
  settings = Settings.from_env({})
  assert (settings.port, settings.host) == (8081, "127.0.0.1")
  assert settings.issuer == settings.public_url == "http://127.0.0.1:8081"
  assert (settings.client_id, settings.client_secret) == ("mock-idp-client", "mock-idp-secret")
  assert (settings.code_ttl_seconds, settings.token_ttl_seconds) == (60, 3600)
  assert settings.debug is False
  assert settings.users_file is None and settings.auto_login is None


def test_every_variable_is_read():
  settings = Settings.from_env(
    {
      "MOCK_IDP_PORT": "9000",
      "MOCK_IDP_HOST": "0.0.0.0",
      "MOCK_IDP_ISSUER": "http://idp:9000",
      "MOCK_IDP_PUBLIC_URL": "http://localhost:9000",
      "MOCK_IDP_CLIENT_ID": "id",
      "MOCK_IDP_CLIENT_SECRET": "secret",
      "MOCK_IDP_CODE_TTL": "5",
      "MOCK_IDP_TOKEN_TTL": "10",
      "MOCK_IDP_USERS_FILE": "/u.json",
      "MOCK_IDP_AUTO_LOGIN": "a@b.c",
      "MOCK_IDP_KEY_DIR": "/keys",
    }
  )
  assert settings == Settings(
    port=9000,
    host="0.0.0.0",
    issuer="http://idp:9000",
    public_url="http://localhost:9000",
    client_id="id",
    client_secret="secret",
    code_ttl_seconds=5,
    token_ttl_seconds=10,
    users_file="/u.json",
    auto_login="a@b.c",
    key_dir=Path("/keys"),
  )


def test_issuer_default_follows_the_port():
  assert Settings.from_env({"MOCK_IDP_PORT": "9999"}).issuer == "http://127.0.0.1:9999"
  assert Settings(port=9999).issuer == Settings(port=9999).public_url == "http://127.0.0.1:9999"


def test_constructor_and_environment_share_the_defaults():
  assert Settings() == Settings.from_env({})


def test_constructor_normalizes_like_the_environment():
  settings = Settings(issuer="http://idp:8081/", key_dir=Path("relative/keys"))
  assert settings.issuer == settings.public_url == "http://idp:8081"
  assert settings.key_dir.is_absolute()
  assert replace(settings, issuer="http://other/").issuer == "http://other"


@pytest.mark.parametrize("name", ["MOCK_IDP_PORT", "MOCK_IDP_CODE_TTL", "MOCK_IDP_TOKEN_TTL"])
def test_non_numeric_settings_fail_with_a_clear_message(name):
  with pytest.raises(ConfigError, match=f"{name} must be an integer, got 'abc'"):
    Settings.from_env({name: "abc"})


def test_issuer_trailing_slash_is_stripped():
  assert Settings.from_env({"MOCK_IDP_ISSUER": "http://idp:8081/"}).issuer == "http://idp:8081"


def test_public_url_defaults_to_the_issuer():
  settings = Settings.from_env({"MOCK_IDP_ISSUER": "http://idp:8081/"})
  assert settings.public_url == "http://idp:8081"
  assert Settings.from_env({"MOCK_IDP_PUBLIC_URL": "http://localhost:1/"}).public_url == "http://localhost:1"


def test_key_dir_is_made_absolute():
  settings = Settings.from_env({"MOCK_IDP_KEY_DIR": "relative/keys"})
  assert settings.key_dir.is_absolute()
  assert settings.jwks_path == settings.key_dir / "jwks.json"
  assert settings.private_key_path == settings.key_dir / "private.pem"


def test_default_key_dir_is_mock_idp_files_in_the_working_directory(tmp_path, monkeypatch):
  monkeypatch.chdir(tmp_path)
  assert Settings.from_env({}).key_dir == tmp_path.resolve() / "mock_idp_files"


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5"])
def test_debug_is_refused_on_non_loopback_hosts(host):
  with pytest.raises(ConfigError, match="MOCK_IDP_DEBUG"):
    Settings.from_env({"MOCK_IDP_DEBUG": "true", "MOCK_IDP_HOST": host})


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_debug_is_allowed_on_loopback(host):
  assert Settings.from_env({"MOCK_IDP_DEBUG": "TRUE", "MOCK_IDP_HOST": host}).debug is True


def test_empty_users_file_and_auto_login_mean_unset():
  settings = Settings.from_env({"MOCK_IDP_USERS_FILE": "", "MOCK_IDP_AUTO_LOGIN": ""})
  assert settings.users_file is None and settings.auto_login is None
