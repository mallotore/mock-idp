import jwt
import pytest

from helpers import authorize, code_from, decode, exchange, peek_next_user


def test_set_user_skips_login_form_once(client):
  response = client.post("/set-user", json={"email": "bot@example.com", "groups": ["ci"]})
  assert response.get_json()["user"] == {"email": "bot@example.com", "groups": ["ci"], "claims": {}}

  first = authorize(client)
  assert first.status_code == 302
  token = exchange(client, code_from(first)).get_json()["id_token"]
  claims = jwt.decode(token, options={"verify_signature": False})
  assert claims["email"] == "bot@example.com" and claims["groups"] == ["ci"]

  # The seeded identity is consumed: the next login shows the form again.
  assert authorize(client).status_code == 200


def test_set_user_accepts_comma_separated_groups(client):
  client.post("/set-user", json={"email": "a@b.c", "groups": "x, y"})
  assert peek_next_user()["groups"] == ["x", "y"]


def test_set_user_requires_email(client):
  assert client.post("/set-user", json={"groups": []}).status_code == 400


def test_set_user_claims_and_sub_override(client):
  client.post("/set-user", json={"email": "a@b.c", "claims": {"sub": "user-123", "name": "A"}})
  claims = decode(client, exchange(client, code_from(authorize(client))))
  assert claims["sub"] == "user-123" and claims["name"] == "A"


def test_set_user_rejects_non_object_claims(client):
  assert client.post("/set-user", json={"email": "a@b.c", "claims": ["x"]}).status_code == 400


@pytest.mark.parametrize("body", ["[]", '"x"', "5", "not json"])
def test_set_user_rejects_bodies_that_are_not_a_json_object(client, body):
  response = client.post("/set-user", data=body, content_type="application/json")
  assert response.status_code == 400


def test_set_user_rejects_non_string_email(client):
  assert client.post("/set-user", json={"email": 5}).status_code == 400


def test_set_user_tolerates_non_string_groups(client):
  response = client.post("/set-user", json={"email": "a@b.c", "groups": 5})
  assert response.status_code == 200
  assert response.get_json()["user"]["groups"] == ["5"]


def test_set_user_requires_a_json_content_type(client):
  """A cross-site page can only send simple content types without a preflight."""
  response = client.post("/set-user", data='{"email": "evil@example.com"}', content_type="text/plain")
  assert response.status_code == 400
  assert peek_next_user() is None
