import re
from urllib.parse import parse_qs, urlparse

from helpers import CLIENT_ID, ISSUER, REDIRECT, authorize, code_from, decode, exchange, stored_codes, stored_pkce


def test_login_redirects_with_code_and_state(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "state": "st"})
  query = parse_qs(urlparse(response.headers["Location"]).query)
  assert response.status_code == 302
  assert response.headers["Location"].startswith(REDIRECT)
  assert query["state"] == ["st"]
  assert query["code"][0].startswith("code-")


def test_login_requires_email(client):
  assert client.post("/login", data={"redirect_uri": REDIRECT}).status_code == 400


def test_extra_claims_from_login_form_reach_id_token_and_userinfo(client):
  response = client.post(
    "/login",
    data={
      "email": "jane@example.com",
      "redirect_uri": REDIRECT,
      "claims": '{"name": "Jane Doe", "iss": "evil", "tier": 3}',
    },
  )
  tokens = exchange(client, code_from(response))
  claims = decode(client, tokens)
  assert claims["name"] == "Jane Doe" and claims["tier"] == 3
  assert claims["iss"] == ISSUER

  info = client.get("/userinfo", headers={"Authorization": f"Bearer {tokens.get_json()['access_token']}"})
  assert info.get_json() == {
    "sub": "jane@example.com",
    "email": "jane@example.com",
    "groups": [],
    "name": "Jane Doe",
    "tier": 3,
  }


def test_login_rejects_claims_that_are_not_a_json_object(client):
  for claims in ("not json", "[1]"):
    response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "claims": claims})
    assert response.status_code == 400


def test_login_rejects_unknown_challenge_method(client):
  response = client.post(
    "/login",
    data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc", "code_challenge_method": "S512"},
  )
  assert response.status_code == 400
  assert not stored_codes(client)


def test_login_defaults_challenge_method_to_plain(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc"})
  assert response.status_code == 302
  assert stored_pkce(client) == {"challenge": "abc", "method": "plain"}


def test_login_form_without_challenge_method_completes_with_plain_pkce(client):
  html = authorize(client, code_challenge="plain-secret").get_data(as_text=True)
  fields = dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', html))
  assert "code_challenge_method" not in fields
  response = client.post("/login", data={**fields, "email": "a@b.c"})
  assert response.status_code == 302
  data = {
    "grant_type": "authorization_code",
    "code": code_from(response),
    "client_id": CLIENT_ID,
    "code_verifier": "plain-secret",
  }
  assert client.post("/token", data=data).status_code == 200


def test_login_rejects_empty_challenge_method(client):
  response = client.post(
    "/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc", "code_challenge_method": ""}
  )
  assert response.status_code == 400


def test_login_does_not_revalidate_the_authorize_parameters(client):
  response = client.post(
    "/login",
    data={
      "email": "a@b.c",
      "redirect_uri": REDIRECT,
      "client_id": "someone-else",
      "response_type": "token",
      "scope": "email",
    },
  )
  assert response.status_code == 302
