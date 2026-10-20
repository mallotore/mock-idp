"""The full login over real HTTP, the way a browser and a relying party would do it."""

import re
from urllib.parse import parse_qs, urlparse

import jwt
import requests

from helpers import CLIENT_ID, CLIENT_SECRET, REDIRECT, s256


def discovery(base):
  return requests.get(f"{base}/.well-known/openid-configuration").json()


def hidden_fields(html):
  """What a browser would submit back: the form's hidden inputs."""
  return dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', html))


def query_of(response):
  assert response.status_code == 302, response.text
  return parse_qs(urlparse(response.headers["Location"]).query)


def browser_login(base, email="jane@example.com", groups="devs", claims="", **authorize_params):
  """GET /authorize, fill the form, POST /login. Returns the redirect's query (code, state)."""
  params = {"client_id": CLIENT_ID, "redirect_uri": REDIRECT, "state": "xyz", "nonce": "n-1", **authorize_params}
  page = requests.get(discovery(base)["authorization_endpoint"], params=params)
  assert page.status_code == 200 and "Mock OIDC Login" in page.text
  form = {**hidden_fields(page.text), "email": email, "groups": groups, "claims": claims}
  return query_of(requests.post(f"{base}/login", data=form, allow_redirects=False))


def token_request(base, code, **extra):
  data = {
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": REDIRECT,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    **extra,
  }
  return requests.post(discovery(base)["token_endpoint"], data=data)


def verified_claims(base, id_token):
  """Verifies the signature using only what discovery advertises."""
  key = jwt.PyJWKClient(discovery(base)["jwks_uri"]).get_signing_key_from_jwt(id_token)
  return jwt.decode(id_token, key.key, algorithms=["RS256"], audience=CLIENT_ID, issuer=discovery(base)["issuer"])


def test_browser_login_returns_a_verifiable_id_token(live_server):
  query = browser_login(live_server, groups="admins, devs", claims='{"name": "Jane"}')
  assert query["state"] == ["xyz"]

  response = token_request(live_server, query["code"][0])
  assert response.status_code == 200
  claims = verified_claims(live_server, response.json()["id_token"])
  assert claims["email"] == "jane@example.com"
  assert claims["groups"] == ["admins", "devs"]
  assert claims["name"] == "Jane"
  assert claims["nonce"] == "n-1"


def test_kid_in_token_matches_kid_in_jwks(live_server):
  query = browser_login(live_server)
  id_token = token_request(live_server, query["code"][0]).json()["id_token"]
  jwks = requests.get(discovery(live_server)["jwks_uri"]).json()
  assert jwt.get_unverified_header(id_token)["kid"] in [key["kid"] for key in jwks["keys"]]


def test_set_user_skips_the_form_and_is_consumed_once(live_server):
  requests.post(f"{live_server}/set-user", json={"email": "bot@example.com", "groups": ["ci"]}).raise_for_status()
  authorize_url = discovery(live_server)["authorization_endpoint"]
  params = {"client_id": CLIENT_ID, "redirect_uri": REDIRECT, "state": "s", "nonce": "n"}

  query = query_of(requests.get(authorize_url, params=params, allow_redirects=False))
  claims = verified_claims(live_server, token_request(live_server, query["code"][0]).json()["id_token"])
  assert claims["email"] == "bot@example.com" and claims["groups"] == ["ci"]

  assert requests.get(authorize_url, params=params, allow_redirects=False).status_code == 200


def test_authorization_code_cannot_be_reused(live_server):
  code = browser_login(live_server)["code"][0]
  assert token_request(live_server, code).status_code == 200
  assert token_request(live_server, code).status_code == 400


def test_userinfo_with_the_access_token(live_server):
  code = browser_login(live_server, claims='{"name": "Jane"}')["code"][0]
  access_token = token_request(live_server, code).json()["access_token"]
  info = requests.get(discovery(live_server)["userinfo_endpoint"], headers={"Authorization": f"Bearer {access_token}"})
  assert info.json()["name"] == "Jane" and info.json()["sub"] == "jane@example.com"


def test_pkce_flow_through_the_login_form(live_server):
  verifier = "a-long-random-verifier-" + "x" * 30
  challenge = s256(verifier)
  query = browser_login(live_server, code_challenge=challenge, code_challenge_method="S256")
  code = query["code"][0]

  wrong = requests.post(
    f"{live_server}/token",
    data={"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": "wrong"},
  )
  assert wrong.status_code == 400

  code = browser_login(live_server, code_challenge=challenge, code_challenge_method="S256")["code"][0]
  right = requests.post(
    f"{live_server}/token",
    data={"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": verifier},
  )
  assert right.status_code == 200 and "id_token" in right.json()
