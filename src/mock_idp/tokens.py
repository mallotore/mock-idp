import hmac, secrets, time
from collections.abc import Mapping
from typing import Any
import jwt
from . import stores
from .keys import KEY_ID
from .settings import Settings
from .errors import INVALID_CLIENT, INVALID_GRANT, OAuthError
from .parsing import client_credentials
from .pkce import pkce_matches
from .stores import AccessToken, AuthCode
from .users import User, identity_claims

def secret_matches(given: Any, settings: Settings) -> bool:
  if not isinstance(given, str):
    return False
  return hmac.compare_digest(given.encode(), settings.client_secret.encode())

def authenticate_client(data: Mapping[str, Any], settings: Settings) -> None:
  """Checks the client without consuming the code, so a failed attempt leaves it redeemable."""
  client_id, client_secret = client_credentials()
  if client_id != settings.client_id:
    raise OAuthError(INVALID_CLIENT, status=401)
  if client_secret is None:
    # Public clients are only accepted when they protect the code with PKCE.
    entry = stores.codes.get(data.get("code"))
    if not (entry and entry.pkce):
      raise OAuthError(INVALID_CLIENT, status=401)
  elif not secret_matches(client_secret, settings):
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

def build_id_token(user: User, nonce: str | None, settings: Settings) -> str:
  now = int(time.time())
  payload = {
    **identity_claims(user),
    "iss": settings.issuer,
    "aud": settings.client_id,
    "exp": now + settings.token_ttl_seconds,
    "iat": now,
  }
  if nonce:
    payload["nonce"] = nonce
  return jwt.encode(payload, settings.private_key_path.read_bytes(), algorithm="RS256",
                    headers={"kid": KEY_ID})

def issue_tokens(entry: AuthCode, settings: Settings) -> dict[str, Any]:
  access_token = secrets.token_urlsafe(24)
  stores.tokens[access_token] = AccessToken(entry.user, time.time() + settings.token_ttl_seconds)
  return {
    "access_token": access_token,
    "id_token": build_id_token(entry.user, entry.nonce, settings),
    "token_type": "Bearer",
    "expires_in": settings.token_ttl_seconds,
  }
