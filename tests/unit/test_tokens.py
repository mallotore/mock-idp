import json

import jwt
import pytest

from mock_idp import keys
from mock_idp.errors import OAuthError
from mock_idp.stores import AuthCode, State
from mock_idp.tokens import build_id_token, issue_tokens, redeem_code, secret_matches
from mock_idp.users import User, build_user
from helpers import KEY_ID, REDIRECT


@pytest.fixture
def settings(base_settings):
  return base_settings


def decode(settings, token):
  public = jwt.PyJWK(json.loads(settings.jwks_path.read_text())["keys"][0]).key
  return jwt.decode(token, public, algorithms=["RS256"], audience=settings.client_id, issuer=settings.issuer,
                    options={"verify_exp": False, "verify_iat": False})


def test_id_token_has_the_registered_claims(settings, clock):
  token = build_id_token(build_user("a@b.c", ["g"]), None, settings, clock.now)
  claims = decode(settings, token)
  assert claims["iss"] == settings.issuer and claims["aud"] == settings.client_id
  assert claims["iat"] == int(clock.now()) and claims["exp"] == int(clock.now()) + settings.token_ttl_seconds
  assert claims["sub"] == claims["email"] == "a@b.c" and claims["groups"] == ["g"]


def test_nonce_is_present_only_when_given(settings, clock):
  user = build_user("a@b.c")
  assert decode(settings, build_id_token(user, "n-1", settings, clock.now))["nonce"] == "n-1"
  assert "nonce" not in decode(settings, build_id_token(user, None, settings, clock.now))


def test_extra_claims_cannot_override_reserved_ones(settings, clock):
  user = build_user("a@b.c", claims={"iss": "evil", "aud": "evil", "exp": 1, "iat": 1, "nonce": "evil", "tier": 3})
  claims = decode(settings, build_id_token(user, None, settings, clock.now))
  assert claims["iss"] == settings.issuer and claims["aud"] == settings.client_id
  assert claims["exp"] > 1 and "nonce" not in claims and claims["tier"] == 3


def test_sub_can_be_overridden(settings, clock):
  claims = decode(settings, build_id_token(build_user("a@b.c", claims={"sub": "user-1"}), None, settings, clock.now))
  assert claims["sub"] == "user-1" and claims["email"] == "a@b.c"


def test_the_key_id_is_in_the_header(settings, clock):
  token = build_id_token(build_user("a@b.c"), None, settings, clock.now)
  assert jwt.get_unverified_header(token)["kid"] == KEY_ID == keys.KEY_ID


def test_issue_tokens_registers_an_access_token_that_expires(settings, clock):
  state = State(settings, clock.now)
  entry = AuthCode(User("a@b.c"), "n", REDIRECT, None, clock.now() + 60)
  response = issue_tokens(entry, state)
  assert response["token_type"] == "Bearer" and response["expires_in"] == settings.token_ttl_seconds
  assert state.tokens.get(response["access_token"]).user.email == "a@b.c"
  clock.advance(settings.token_ttl_seconds + 1)
  assert state.tokens.get(response["access_token"]) is None


def test_redeem_code_consumes_it_and_checks_redirect_uri(settings, clock):
  state = State(settings, clock.now)
  code = state.issue_code(User("a@b.c"), None, REDIRECT, None)
  with pytest.raises(OAuthError, match="invalid_grant"):
    redeem_code({"code": code, "redirect_uri": "http://evil/cb"}, state)
  with pytest.raises(OAuthError, match="invalid_grant"):  # the failed attempt consumed it
    redeem_code({"code": code}, state)


def test_secret_comparison(settings):
  assert secret_matches(settings.client_secret, settings)
  for wrong in ("wrong", "é", None):
    assert not secret_matches(wrong, settings)
