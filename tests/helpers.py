"""Shared test helpers.

Everything the tests need from the application's internals (settings, stored codes and tokens, the clock)
goes through this module, so a refactor of those internals only touches one place.
"""
import base64, hashlib, time
from dataclasses import asdict
from urllib.parse import urlparse, parse_qs

import jwt

from mock_idp import keys, stores
from mock_idp.settings import Settings
from mock_idp.users import build_user

REDIRECT = "http://localhost:8250/oidc/callback"
DEFAULTS = Settings()
ISSUER = DEFAULTS.issuer
CLIENT_ID = DEFAULTS.client_id
CLIENT_SECRET = DEFAULTS.client_secret
KEY_ID = keys.KEY_ID


# --- settings and state -------------------------------------------------------------------------

def reset_state():
  stores.codes.clear()
  stores.tokens.clear()
  stores.next_user = None


def stored_codes():
  """Authorization codes that were issued and not redeemed yet."""
  return dict(stores.codes)


def fill_store(count):
  """Adds `count` unexpired authorization codes."""
  expires_at = time.time() + 3600
  user = build_user("filler@example.com")
  for i in range(count):
    stores.codes[f"filler-{i}"] = stores.AuthCode(user, None, REDIRECT, None, expires_at)


def stored_pkce():
  """The PKCE parameters saved with the only stored code."""
  [entry] = stores.codes.values()
  return asdict(entry.pkce)


def peek_next_user():
  """The identity seeded by /set-user, without consuming it."""
  return asdict(stores.next_user) if stores.next_user else None


def expire_code(code):
  stores.codes[code].expires_at = time.time() - 1


def expire_access_token(token):
  stores.tokens[token].expires_at = time.time() - 1


def set_clock(patch, now):
  """Makes the application see `now()` as the current time."""
  patch.setattr(stores.time, "time", now)


# --- requests -----------------------------------------------------------------------------------

def s256(verifier):
  return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def code_from(response):
  return parse_qs(urlparse(response.headers["Location"]).query)["code"][0]


def authorize(client, **params):
  query = {"redirect_uri": REDIRECT, "state": "st", "nonce": "nn", "client_id": CLIENT_ID, **params}
  return client.get("/authorize", query_string=query)


def exchange(client, code, **overrides):
  data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
          "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, **overrides}
  return client.post("/token", data={k: v for k, v in data.items() if v is not None})


def login(client, email="jane@example.com", groups="admins,devs"):
  response = client.post("/login", data={"email": email, "groups": groups,
                                         "redirect_uri": REDIRECT, "state": "st", "nonce": "nn"})
  assert response.status_code == 302
  return code_from(response)


def signing_key(client):
  jwks = client.get("/jwks").get_json()
  return jwt.PyJWK(jwks["keys"][0]).key


def decode(client, response):
  return jwt.decode(response.get_json()["id_token"], signing_key(client), algorithms=["RS256"],
                    audience=CLIENT_ID, issuer=ISSUER)
