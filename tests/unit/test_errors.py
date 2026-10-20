import pytest
from flask import Flask

from mock_idp.errors import OAuthError, register_error_handlers
from mock_idp.users import UsersFileError


@pytest.fixture
def client():
  app = Flask(__name__)
  register_error_handlers(app)

  @app.route("/oauth")
  def oauth():
    raise OAuthError("invalid_grant", "code expired")

  @app.route("/bare")
  def bare():
    raise OAuthError("unsupported_grant_type")

  @app.route("/headers")
  def headers():
    raise OAuthError("invalid_token", status=401, headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})

  @app.route("/users")
  def users():
    raise UsersFileError("cannot read users file x")

  return app.test_client()


def test_error_with_description(client):
  response = client.get("/oauth")
  assert response.status_code == 400
  assert response.get_json() == {"error": "invalid_grant", "error_description": "code expired"}


def test_error_without_description_omits_the_field(client):
  assert client.get("/bare").get_json() == {"error": "unsupported_grant_type"}


def test_error_with_status_and_extra_headers(client):
  response = client.get("/headers")
  assert response.status_code == 401
  assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'


def test_users_file_error_is_a_500_with_the_reason(client):
  response = client.get("/users")
  assert response.status_code == 500
  assert response.get_json() == {"error": "invalid_users_file", "error_description": "cannot read users file x"}
