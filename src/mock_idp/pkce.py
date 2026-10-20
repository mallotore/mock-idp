import base64
import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .errors import INVALID_REQUEST, OAuthError

S256, PLAIN = "S256", "plain"
PKCE_METHODS = (S256, PLAIN)


@dataclass
class Pkce:
  challenge: str
  method: str


def parse_pkce(params: Mapping[str, Any]) -> Pkce | None:
  challenge = params.get("code_challenge")
  if not challenge:
    return None
  method = params.get("code_challenge_method")
  if method == "" or method not in (None, *PKCE_METHODS):
    raise OAuthError(INVALID_REQUEST, "unsupported code_challenge_method")
  return Pkce(challenge, method or PLAIN)


def s256(verifier: str) -> str:
  return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def pkce_matches(pkce: Pkce, verifier: str | None) -> bool:
  if not verifier:
    return False
  if pkce.method == S256:
    verifier = s256(verifier)
  return hmac.compare_digest(verifier.encode(), pkce.challenge.encode())
