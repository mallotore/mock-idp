import pytest

from mock_idp.app import create_app
from helpers import authorize, code_from, decode, exchange


@pytest.fixture
def users_file(tmp_path, set_config):
  path = tmp_path / "users.json"
  path.write_text('{"users": [{"email": "admin@example.com", "groups": ["admins"], "name": "Ada"},'
                  ' {"email": "guest@example.com"}]}')
  set_config(USERS_FILE=str(path))
  return path


def test_users_file_populates_login_page(client, users_file):
  html = authorize(client).get_data(as_text=True)
  assert "admin@example.com" in html and "guest@example.com" in html


def test_login_page_embeds_saved_users_with_groups_and_claims(client, users_file):
  html = authorize(client).get_data(as_text=True)
  assert '"groups": ["admins"]' in html and '"claims": {"name": "Ada"}' in html


def test_auto_login_uses_user_from_file(client, users_file, set_config):
  set_config(AUTO_LOGIN="admin@example.com")
  response = authorize(client)
  assert response.status_code == 302
  claims = decode(client, exchange(client, code_from(response)))
  assert claims["groups"] == ["admins"] and claims["name"] == "Ada"


def test_auto_login_for_email_not_in_file_has_no_groups(client, set_config):
  set_config(AUTO_LOGIN="ci@example.com")
  claims = decode(client, exchange(client, code_from(authorize(client))))
  assert claims["email"] == "ci@example.com" and claims["groups"] == []


def test_set_user_wins_over_auto_login(client, set_config):
  set_config(AUTO_LOGIN="ci@example.com")
  client.post("/set-user", json={"email": "manual@example.com"})
  assert decode(client, exchange(client, code_from(authorize(client))))["email"] == "manual@example.com"


@pytest.mark.parametrize("content", ["not json", '{"users": "x"}', '[{"groups": []}]'])
def test_invalid_users_file_fails_fast(tmp_path, set_config, content):
  path = tmp_path / "users.json"
  path.write_text(content)
  set_config(USERS_FILE=str(path))
  with pytest.raises(SystemExit) as error:
    create_app()
  assert "invalid configuration" in str(error.value)


def test_users_file_broken_while_running_returns_a_clear_error(client, users_file):
  assert authorize(client).status_code == 200
  users_file.write_text("{ broken")
  response = authorize(client)
  assert response.status_code == 500
  assert response.get_json()["error"] == "invalid_users_file"
  assert "cannot read users file" in response.get_json()["error_description"]
  users_file.write_text('[{"email": "a@b.c"}]')
  assert authorize(client).status_code == 200


def test_missing_users_file_fails_fast(set_config):
  set_config(USERS_FILE="/does/not/exist.json")
  with pytest.raises(SystemExit):
    create_app()
