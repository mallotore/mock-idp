import pytest

from helpers import CLIENT_ID, REDIRECT, authorize, code_from, login, s256


def test_pkce_s256_public_client(client):
  verifier = "v" * 50
  response = authorize(client, code_challenge=s256(verifier), code_challenge_method="S256")
  html = response.get_data(as_text=True)
  assert f'name="code_challenge" value="{s256(verifier)}"' in html
  login_response = client.post(
    "/login",
    data={
      "email": "a@b.c",
      "redirect_uri": REDIRECT,
      "code_challenge": s256(verifier),
      "code_challenge_method": "S256",
    },
  )
  code = code_from(login_response)
  public = {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": verifier}
  assert client.post("/token", data=public).status_code == 200


@pytest.mark.parametrize("verifier", ["wrong-verifier", None])
def test_pkce_rejects_wrong_or_missing_verifier(client, verifier):
  challenge = s256("v" * 50)
  code = code_from(
    client.post(
      "/login",
      data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": challenge, "code_challenge_method": "S256"},
    )
  )
  data = {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": verifier}
  response = client.post("/token", data={k: v for k, v in data.items() if v})
  assert response.status_code == 400 and response.get_json()["error"] == "invalid_grant"


def test_pkce_plain_method(client):
  code = code_from(
    client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "plain-secret"})
  )
  data = {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": "plain-secret"}
  assert client.post("/token", data=data).status_code == 200


def test_pkce_plain_rejects_non_ascii_verifier(client):
  code = code_from(client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc"}))
  data = {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": "é"}
  response = client.post("/token", data=data)
  assert response.status_code == 400
  assert response.get_json()["error"] == "invalid_grant"


def test_public_client_without_pkce_is_rejected(client):
  data = {"grant_type": "authorization_code", "code": login(client), "client_id": CLIENT_ID}
  assert client.post("/token", data=data).status_code == 401
