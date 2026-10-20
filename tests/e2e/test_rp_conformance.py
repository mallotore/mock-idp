"""An independent OIDC client library (Authlib) acting as the relying party.

If the mock deviates from the spec in a way a real client cares about, these fail even when our own
hand-written requests in test_flow.py would still pass.
"""
from urllib.parse import urlparse, parse_qs

import pytest
import requests
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc6749.errors import MismatchingStateException
from joserfc import jwt
from joserfc.jwk import KeySet

from helpers import CLIENT_ID, CLIENT_SECRET, REDIRECT


@pytest.fixture(autouse=True)
def allow_http(monkeypatch):
  monkeypatch.setenv("AUTHLIB_INSECURE_TRANSPORT", "1")


class RelyingParty:
  def __init__(self, base, auth_method="client_secret_basic", secret=CLIENT_SECRET):
    self.base = base
    self.doc = requests.get(f"{base}/.well-known/openid-configuration").json()
    self.session = OAuth2Session(CLIENT_ID, secret, scope="openid email", redirect_uri=REDIRECT,
                                 token_endpoint_auth_method=auth_method)
    self.nonce = "rp-nonce-1"

  def authorization_url(self, **kwargs):
    url, self.state = self.session.create_authorization_url(self.doc["authorization_endpoint"],
                                                            nonce=self.nonce, **kwargs)
    return url

  def log_in_as(self, email="jane@example.com", groups=("devs",), **kwargs):
    """Seeds the identity (the "user" at the browser) and follows /authorize to the callback URL."""
    requests.post(f"{self.base}/set-user", json={"email": email, "groups": list(groups)}).raise_for_status()
    response = requests.get(self.authorization_url(**kwargs), allow_redirects=False)
    assert response.status_code == 302, response.text
    return response.headers["Location"]

  def fetch_token(self, callback_url, **kwargs):
    return self.session.fetch_token(self.doc["token_endpoint"], authorization_response=callback_url,
                                    state=self.state, **kwargs)

  def validate_id_token(self, id_token, aud=CLIENT_ID):
    """Signature through the advertised JWKS, then iss/aud/nonce/exp the way an OIDC client must."""
    keys = KeySet.import_key_set(requests.get(self.doc["jwks_uri"]).json())
    token = jwt.decode(id_token, keys, algorithms=["RS256"])
    jwt.JWTClaimsRegistry(
      iss={"essential": True, "value": self.doc["issuer"]},
      aud={"essential": True, "value": aud},
      nonce={"essential": True, "value": self.nonce},
      exp={"essential": True},
    ).validate(token.claims)
    return token.claims


@pytest.mark.parametrize("auth_method", ["client_secret_basic", "client_secret_post"])
def test_authorization_code_flow(live_server, auth_method):
  rp = RelyingParty(live_server, auth_method)
  token = rp.fetch_token(rp.log_in_as(groups=("admins", "devs")))

  claims = rp.validate_id_token(token["id_token"])
  assert claims["email"] == "jane@example.com" and claims["groups"] == ["admins", "devs"]
  assert token["token_type"].lower() == "bearer"


def test_discovery_is_complete_enough_for_a_client(live_server):
  doc = RelyingParty(live_server).doc
  for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint",
                "response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"):
    assert field in doc
  assert doc["issuer"] == live_server


def test_pkce_with_s256(live_server):
  rp = RelyingParty(live_server)
  verifier = "v" * 64
  callback = rp.log_in_as(code_verifier=verifier)
  token = rp.fetch_token(callback, code_verifier=verifier)
  rp.validate_id_token(token["id_token"])


def test_userinfo_with_authlib_token(live_server):
  rp = RelyingParty(live_server)
  token = rp.fetch_token(rp.log_in_as())
  rp.session.token = token
  info = rp.session.get(rp.doc["userinfo_endpoint"])
  assert info.json()["email"] == "jane@example.com"


def test_client_detects_state_mismatch(live_server):
  rp = RelyingParty(live_server)
  callback = rp.log_in_as()
  tampered = callback.replace(parse_qs(urlparse(callback).query)["state"][0], "forged")
  with pytest.raises(MismatchingStateException):
    rp.fetch_token(tampered)


def test_client_rejects_token_with_a_different_nonce(live_server):
  rp = RelyingParty(live_server)
  token = rp.fetch_token(rp.log_in_as())
  rp.nonce = "a-different-nonce"
  with pytest.raises(Exception, match="nonce"):
    rp.validate_id_token(token["id_token"])


def test_client_rejects_token_for_a_different_audience(live_server):
  rp = RelyingParty(live_server)
  token = rp.fetch_token(rp.log_in_as())
  with pytest.raises(Exception, match="aud"):
    rp.validate_id_token(token["id_token"], aud="another-client")


def test_client_rejects_expired_token(serve):
  rp = RelyingParty(serve(token_ttl_seconds=-10))
  token = rp.fetch_token(rp.log_in_as())
  with pytest.raises(Exception, match="expired|exp"):
    rp.validate_id_token(token["id_token"])


def test_wrong_client_secret_is_rejected(live_server):
  rp = RelyingParty(live_server, secret="wrong")
  with pytest.raises(Exception):
    rp.fetch_token(rp.log_in_as())
