import hmac, secrets, time
from collections.abc import Mapping
from typing import Any
import jwt
from . import config, stores
from .errors import INVALID_CLIENT, INVALID_GRANT, OAuthError
from .parsing import client_credentials
from .pkce import pkce_matches
from .stores import AccessToken, AuthCode
from .users import User, identity_claims

def secret_matches(given: Any) -> bool:
  if not isinstance(given, str):
    return False
  return hmac.compare_digest(given.encode(), config.CLIENT_SECRET.encode())

def authenticate_client(data: Mapping[str, Any]) -> None:
  """Checks the client without consuming the code, so a failed attempt leaves it redeemable."""
  client_id, client_secret = client_credentials()
  if client_id != config.CLIENT_ID:
    raise OAuthError(INVALID_CLIENT, status=401)
  if client_secret is None:
    # Public clients are only accepted when they protect the code with PKCE.
    entry = stores.codes.get(data.get("code"))
    if not (entry and entry.pkce):
      raise OAuthError(INVALID_CLIENT, status=401)
  elif not secret_matches(client_secret):
    raise OAuthError(INVALID_CLIENT, status=401)

def redeem_code(data: Mapping[str, Any]) -> AuthCode:
  """Codes are single use and short lived. pop() is atomic, so of several concurrent requests only one gets it."""
  entry = stores.codes.pop(data.get("code"), None)
  if not entry or time.time() > entry.expires_at:
    raise OAuthError(INVALID_GRANT, "code not found or expired")
  if data.get("redirect_uri") not in (None, entry.redirect_uri):
    raise OAuthError(INVALID_GRANT, "redirect_uri mismatch")
  if entry.pkce and not pkce_matches(entry.pkce, data.get("code_verifier")):
    raise OAuthError(INVALID_GRANT, "code_verifier mismatch")
  return entry

def build_id_token(user: User, nonce: str | None) -> str:
  now = int(time.time())
  payload = {
    **identity_claims(user),
    "iss": config.ISSUER,
    "aud": config.CLIENT_ID,
    "exp": now + config.TOKEN_TTL_SECONDS,
    "iat": now,
  }
  if nonce:
    payload["nonce"] = nonce
  return jwt.encode(payload, config.PRIVATE_KEY_PATH.read_bytes(), algorithm="RS256", headers={"kid": config.KEY_ID})

def issue_tokens(entry: AuthCode) -> dict[str, Any]:
  access_token = secrets.token_urlsafe(24)
  stores.tokens[access_token] = AccessToken(entry.user, time.time() + config.TOKEN_TTL_SECONDS)
  return {
    "access_token": access_token,
    "id_token": build_id_token(entry.user, entry.nonce),
    "token_type": "Bearer",
    "expires_in": config.TOKEN_TTL_SECONDS,
  }
