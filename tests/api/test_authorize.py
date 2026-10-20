from helpers import authorize


def test_authorize_shows_login_form_with_hidden_fields(client):
  response = authorize(client)
  html = response.get_data(as_text=True)
  assert response.status_code == 200
  assert 'name="state" value="st"' in html
  assert 'name="nonce" value="nn"' in html


def test_authorize_requires_redirect_uri(client):
  assert client.get("/authorize").status_code == 400


def test_authorize_rejects_unknown_client(client):
  assert authorize(client, client_id="someone-else").status_code == 400


def test_login_page_has_banner_and_no_none_strings(client):
  html = authorize(client, state=None, nonce=None).get_data(as_text=True)
  assert "NOT FOR PRODUCTION" in html
  assert "None" not in html


def test_authorize_rejects_unknown_challenge_method(client):
  assert authorize(client, code_challenge="x", code_challenge_method="S512").status_code == 400


def test_authorize_rejects_empty_challenge_method(client):
  assert authorize(client, code_challenge="x", code_challenge_method="").status_code == 400


def test_authorize_rejects_unsupported_response_type(client):
  response = authorize(client, response_type="token")
  assert response.status_code == 400
  assert response.get_json()["error"] == "unsupported_response_type"


def test_authorize_requires_openid_scope(client):
  response = authorize(client, scope="email profile")
  assert response.status_code == 400
  assert response.get_json()["error"] == "invalid_scope"


def test_authorize_accepts_code_response_type_and_openid_scope(client):
  assert authorize(client, response_type="code", scope="openid email").status_code == 200


def test_authorize_ignores_challenge_method_without_a_challenge(client):
  assert authorize(client, code_challenge_method="foo").status_code == 200
