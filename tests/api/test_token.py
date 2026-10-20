import base64
import shutil

import jwt
import pytest

from helpers import (
  CLIENT_ID,
  CLIENT_SECRET,
  KEY_ID,
  REDIRECT,
  code_from,
  decode,
  exchange,
  expire_codes,
  login,
  stored_codes,
)


def test_id_token_contains_identity_groups_and_nonce(client):
  response = exchange(client, login(client))
  token = response.get_json()["id_token"]
  claims = decode(client, response)
  assert claims["email"] == claims["sub"] == "jane@example.com"
  assert claims["groups"] == ["admins", "devs"]
  assert claims["nonce"] == "nn"
  assert jwt.get_unverified_header(token)["kid"] == KEY_ID


def test_token_without_nonce_omits_claim(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT})
  token = exchange(client, code_from(response)).get_json()["id_token"]
  assert "nonce" not in jwt.decode(token, options={"verify_signature": False})


def test_code_is_single_use(client):
  code = login(client)
  assert exchange(client, code).status_code == 200
  second = exchange(client, code)
  assert second.status_code == 400
  assert second.get_json()["error"] == "invalid_grant"


def test_expired_code_is_rejected(client, clock):
  code = login(client)
  expire_codes(clock)
  assert exchange(client, code).status_code == 400


def test_unknown_code_is_rejected(client):
  assert exchange(client, "code-nope").status_code == 400


def test_redirect_uri_must_match_authorization_request(client):
  assert exchange(client, login(client), redirect_uri="http://evil.example/cb").status_code == 400


@pytest.mark.parametrize("overrides", [{"client_secret": "wrong"}, {"client_id": "wrong"}, {"client_secret": None}])
def test_token_rejects_bad_client_credentials(client, overrides):
  assert exchange(client, login(client), **overrides).status_code == 401


def test_token_accepts_basic_auth(client):
  basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
  response = client.post(
    "/token",
    data={"grant_type": "authorization_code", "code": login(client)},
    headers={"Authorization": f"Basic {basic}"},
  )
  assert response.status_code == 200


@pytest.mark.parametrize("body", [[1], "x", 5])
def test_token_rejects_non_object_json_body(client, body):
  response = client.post("/token", json=body)
  assert response.status_code in (400, 401)
  assert response.is_json


def test_token_rejects_other_grant_types(client):
  assert exchange(client, login(client), grant_type="password").status_code == 400


def test_wrong_client_secret_does_not_consume_the_code(client):
  code = login(client)
  assert exchange(client, code, client_secret="nope").status_code == 401
  assert exchange(client, code).status_code == 200


def test_basic_auth_credentials_are_form_urldecoded(make_app):
  client = make_app(client_secret="s3cr+t/%").test_client()
  encoded = base64.b64encode(f"{CLIENT_ID}:s3cr%2Bt%2F%25".encode()).decode()
  code = login(client)
  response = client.post("/token", data={"code": code}, headers={"Authorization": f"Basic {encoded}"})
  assert response.status_code == 200


@pytest.mark.parametrize(
  "field, value",
  [
    ("code", [1]),
    ("code", {"a": 1}),
    ("code_verifier", 5),
    ("redirect_uri", ["x"]),
    ("grant_type", ["authorization_code"]),
  ],
)
def test_token_rejects_non_string_json_values(client, field, value):
  body = {
    "grant_type": "authorization_code",
    "code": "code-x",
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    field: value,
  }
  response = client.post("/token", json=body)
  assert response.status_code == 400
  assert response.get_json()["error"] == "invalid_request"


def test_token_accepts_client_credentials_in_a_json_body(client):
  body = {
    "grant_type": "authorization_code",
    "code": login(client),
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
  }
  assert client.post("/token", json=body).status_code == 200


def test_token_responses_are_not_cacheable(client):
  success = exchange(client, login(client))
  failure = exchange(client, "code-nope")
  assert success.status_code == 200 and failure.status_code == 400
  for response in (success, failure):
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


@pytest.mark.parametrize("secret", ["é", "wrong-é"])
def test_non_ascii_client_secret_is_a_mismatch_not_an_error(client, secret):
  assert exchange(client, login(client), client_secret=secret).status_code == 401


def test_malformed_basic_auth_header_is_rejected(client):
  response = client.post("/token", data={"code": login(client)}, headers={"Authorization": "Basic !!!not-base64"})
  assert response.status_code == 401


def test_an_unreadable_signing_key_fails_before_the_code_is_used(make_app, base_settings, tmp_path):
  client = make_app(key_dir=tmp_path).test_client()
  code = login(client)
  assert exchange(client, code).status_code == 500
  assert code in stored_codes(client)
  shutil.copy(base_settings.private_key_path, tmp_path / "private.pem")
  assert exchange(client, code).status_code == 200
