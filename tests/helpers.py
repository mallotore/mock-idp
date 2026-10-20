import time
from dataclasses import asdict
from urllib.parse import parse_qs, urlparse

import jwt

from mock_idp import stores
from mock_idp.settings import Settings
from mock_idp.users import build_user

REDIRECT = "http://localhost:8250/oidc/callback"
DEFAULTS = Settings()
ISSUER = DEFAULTS.issuer
CLIENT_ID = DEFAULTS.client_id
CLIENT_SECRET = DEFAULTS.client_secret


class Clock:
  def __init__(self, start=None):
    self.value = time.time() if start is None else start

  def now(self):
    return self.value

  def advance(self, seconds):
    self.value += seconds


def state_of(client_or_app):
  app = getattr(client_or_app, "application", client_or_app)
  return app.extensions["mock_idp"]


def stored_codes(client):
  return state_of(client).codes.snapshot()


def stored_pkce(client):
  [entry] = stored_codes(client).values()
  return asdict(entry.pkce)


def peek_next_user(client):
  user = state_of(client).next_user.peek()
  return asdict(user) if user else None


def fill_store(client, count):
  state = state_of(client)
  user = build_user("filler@example.com")
  for i in range(count):
    state.codes.put(f"filler-{i}", stores.AuthCode(user, None, REDIRECT, None, state.now() + 3600))


def expire_codes(clock):
  clock.advance(DEFAULTS.code_ttl_seconds + 1)


def expire_access_tokens(clock):
  clock.advance(DEFAULTS.token_ttl_seconds + 1)


def code_from(response):
  return parse_qs(urlparse(response.headers["Location"]).query)["code"][0]


def authorize(client, **params):
  query = {"redirect_uri": REDIRECT, "state": "st", "nonce": "nn", "client_id": CLIENT_ID, **params}
  return client.get("/authorize", query_string=query)


def exchange(client, code, **overrides):
  data = {
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": REDIRECT,
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    **overrides,
  }
  return client.post("/token", data={k: v for k, v in data.items() if v is not None})


def login(client, email="jane@example.com", groups="admins,devs"):
  response = client.post(
    "/login", data={"email": email, "groups": groups, "redirect_uri": REDIRECT, "state": "st", "nonce": "nn"}
  )
  assert response.status_code == 302
  return code_from(response)


def signing_key(client):
  jwks = client.get("/jwks").get_json()
  return jwt.PyJWK(jwks["keys"][0]).key


def decode(client, response):
  return jwt.decode(
    response.get_json()["id_token"], signing_key(client), algorithms=["RS256"], audience=CLIENT_ID, issuer=ISSUER
  )
