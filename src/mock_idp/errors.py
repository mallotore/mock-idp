from flask import Flask, Response, jsonify

from .users import UsersFileError

# OAuth error codes (RFC 6749 section 5.2, plus this server's invalid_users_file).
INVALID_REQUEST = "invalid_request"
INVALID_GRANT = "invalid_grant"
INVALID_CLIENT = "invalid_client"
INVALID_SCOPE = "invalid_scope"
INVALID_TOKEN = "invalid_token"
INVALID_USERS_FILE = "invalid_users_file"
UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
UNAUTHORIZED_CLIENT = "unauthorized_client"


class OAuthError(Exception):
  """An error answered as JSON: {"error": ..., "error_description": ...} (description omitted when empty)."""

  def __init__(self, error: str, description: str = "", status: int = 400, headers: dict[str, str] | None = None):
    super().__init__(error)
    self.error, self.description, self.status, self.headers = error, description, status, headers or {}


def oauth_error(error: OAuthError) -> Response:
  body = {"error": error.error}
  if error.description:
    body["error_description"] = error.description
  return jsonify(body), error.status, error.headers


def users_file_error(error: UsersFileError) -> Response:
  """A users file broken while the server runs is reported to the caller, not by dropping the request."""
  return oauth_error(OAuthError(INVALID_USERS_FILE, str(error), status=500))


def register_error_handlers(app: Flask) -> None:
  app.register_error_handler(OAuthError, oauth_error)
  app.register_error_handler(UsersFileError, users_file_error)
