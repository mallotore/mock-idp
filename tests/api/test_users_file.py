import pytest

from helpers import authorize, code_from, decode, exchange


@pytest.fixture
def users_file(tmp_path):
  path = tmp_path / "users.json"
  path.write_text('{"users": [{"email": "admin@example.com", "groups": ["admins"], "name": "Ada"},'
                  ' {"email": "guest@example.com"}]}')
  return path


def test_users_file_populates_login_page(make_app, users_file):
  html = authorize(make_app(users_file=str(users_file)).test_client()).get_data(as_text=True)
  assert "admin@example.com" in html and "guest@example.com" in html


def test_login_page_embeds_saved_users_with_groups_and_claims(make_app, users_file):
  html = authorize(make_app(users_file=str(users_file)).test_client()).get_data(as_text=True)
  assert '"groups": ["admins"]' in html and '"claims": {"name": "Ada"}' in html


def test_auto_login_uses_user_from_file(make_app, users_file):
  client = make_app(users_file=str(users_file), auto_login="admin@example.com").test_client()
  response = authorize(client)
  assert response.status_code == 302
  claims = decode(client, exchange(client, code_from(response)))
  assert claims["groups"] == ["admins"] and claims["name"] == "Ada"


def test_auto_login_for_email_not_in_file_has_no_groups(make_app):
  client = make_app(auto_login="ci@example.com").test_client()
  claims = decode(client, exchange(client, code_from(authorize(client))))
  assert claims["email"] == "ci@example.com" and claims["groups"] == []


def test_set_user_wins_over_auto_login(make_app):
  client = make_app(auto_login="ci@example.com").test_client()
  client.post("/set-user", json={"email": "manual@example.com"})
  assert decode(client, exchange(client, code_from(authorize(client))))["email"] == "manual@example.com"


def test_users_file_broken_while_running_returns_a_clear_error(make_app, users_file):
  client = make_app(users_file=str(users_file)).test_client()
  assert authorize(client).status_code == 200
  users_file.write_text("{ broken")
  response = authorize(client)
  assert response.status_code == 500
  assert response.get_json()["error"] == "invalid_users_file"
  assert "cannot read users file" in response.get_json()["error_description"]
  users_file.write_text('[{"email": "a@b.c"}]')
  assert authorize(client).status_code == 200
