import base64
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus

from flask import request

from .errors import (
  INVALID_REQUEST,
  INVALID_SCOPE,
  UNAUTHORIZED_CLIENT,
  UNSUPPORTED_GRANT_TYPE,
  UNSUPPORTED_RESPONSE_TYPE,
  OAuthError,
)
from .pkce import Pkce, parse_pkce
from .settings import Settings


def request_data() -> Mapping[str, Any]:
  if request.form:
    return request.form
  data = request.get_json(silent=True)
  return data if isinstance(data, dict) else {}


def authorization(scheme: str) -> str | None:
  name, _, value = request.headers.get("Authorization", "").partition(" ")
  return value.strip() if name.lower() == scheme.lower() else None


def client_credentials(data: Mapping[str, Any]) -> tuple[Any, Any]:
  client_id, secret = data.get("client_id"), data.get("client_secret")
  basic = authorization("Basic")
  if basic is not None:
    try:
      basic_id, _, basic_secret = base64.b64decode(basic).decode().partition(":")
    except ValueError:
      return None, None
    client_id, secret = unquote_plus(basic_id), unquote_plus(basic_secret)
  return client_id, None if secret == "" else secret


@dataclass
class AuthorizeRequest:
  redirect_uri: str
  state: str | None
  nonce: str | None
  pkce: Pkce | None


def parse_authorize_request(args: Mapping[str, str], settings: Settings) -> AuthorizeRequest:
  if args.get("response_type", "code") != "code":
    raise OAuthError(UNSUPPORTED_RESPONSE_TYPE)
  if "openid" not in args.get("scope", "openid").split():
    raise OAuthError(INVALID_SCOPE, "openid scope required")
  redirect_uri = args.get("redirect_uri")
  if not redirect_uri:
    raise OAuthError(INVALID_REQUEST, "redirect_uri required")
  if args.get("client_id") not in (None, settings.client_id):
    raise OAuthError(UNAUTHORIZED_CLIENT)
  return AuthorizeRequest(
    redirect_uri,
    args.get("state"),
    args.get("nonce"),
    parse_pkce(args),
  )


def reject_non_string_parameters(data: Mapping[str, Any]) -> None:
  for name in ("grant_type", "code", "code_verifier", "redirect_uri"):
    if not isinstance(data.get(name, ""), str):
      raise OAuthError(INVALID_REQUEST, f"{name} must be a string")


def require_authorization_code_grant(data: Mapping[str, Any]) -> None:
  reject_non_string_parameters(data)
  if data.get("grant_type", "authorization_code") != "authorization_code":
    raise OAuthError(UNSUPPORTED_GRANT_TYPE)
