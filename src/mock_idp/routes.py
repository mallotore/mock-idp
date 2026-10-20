import json, logging, time
from dataclasses import asdict
from urllib.parse import urlencode
from flask import Blueprint, Response, jsonify, redirect, render_template, request, send_file
from . import config, stores
from .errors import INVALID_TOKEN, OAuthError
from .parsing import parse_authorize_request, request_data, require_authorization_code_grant
from .pkce import PKCE_METHODS, Pkce, parse_pkce
from .tokens import authenticate_client, issue_tokens, redeem_code
from .users import User, auto_login_user, build_user, identity_claims, load_users

oidc_bp = Blueprint("oidc", __name__)
logger = logging.getLogger(__name__)

def redirect_with_code(redirect_uri: str, state: str | None, nonce: str | None, user: User,
                       pkce: Pkce | None) -> Response:
  code = stores.issue_code(user, nonce, redirect_uri, pkce)
  params = {"code": code}
  if state:
    params["state"] = state
  logger.info("Issued auth code %s for user=%s", code, user.email)
  separator = "&" if "?" in redirect_uri else "?"
  return redirect(f"{redirect_uri}{separator}{urlencode(params)}", code=302)

@oidc_bp.after_request
def no_store_token_responses(response: Response) -> Response:
  """RFC 6749 section 5.1: token responses must not be cached."""
  if request.path == "/token":
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
  return response

@oidc_bp.route("/healthz")
def healthz() -> Response:
  return jsonify({"status": "ok"})

@oidc_bp.route("/.well-known/openid-configuration")
def well_known() -> Response:
  return jsonify({
    "issuer": config.ISSUER,
    "authorization_endpoint": f"{config.PUBLIC_URL}/authorize",
    "token_endpoint": f"{config.ISSUER}/token",
    "userinfo_endpoint": f"{config.ISSUER}/userinfo",
    "jwks_uri": f"{config.ISSUER}/jwks",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
    "code_challenge_methods_supported": list(PKCE_METHODS),
    "scopes_supported": ["openid", "email", "profile"],
    "claims_supported": ["sub", "email", "groups"],
  })

@oidc_bp.route("/set-user", methods=["POST"])
def set_user() -> Response:
  """Pre-seeds the identity of the next login so tests can skip the login form.

  Body: {"email": "...", "groups": ["a", "b"], "claims": {"name": "Jane"}}
  """
  # No force=True: requiring a JSON Content-Type makes browsers preflight cross-site requests.
  data = request.get_json(silent=True)
  if not isinstance(data, dict):
    raise OAuthError("body must be a JSON object")
  email = data.get("email")
  if not email:
    raise OAuthError("email required")
  if not isinstance(email, str):
    raise OAuthError("email must be a string")
  if not isinstance(data.get("claims", {}), dict):
    raise OAuthError("claims must be an object")

  user = build_user(email, data.get("groups"), data.get("claims"))
  stores.set_next_user(user)
  return jsonify({"status": "ok", "user": asdict(user)})

@oidc_bp.route("/authorize")
def authorize() -> Response | str:
  req = parse_authorize_request(request.args)
  user = stores.take_next_user() or auto_login_user()
  if user:
    return redirect_with_code(req.redirect_uri, req.state, req.nonce, user, req.pkce)
  return render_template("login.html", users=load_users(), redirect_uri=req.redirect_uri, state=req.state,
                         nonce=req.nonce, code_challenge=req.code_challenge,
                         code_challenge_method=req.code_challenge_method)

@oidc_bp.route("/login", methods=["POST"])
def login() -> Response:
  form = request.form
  email = form.get("email")
  redirect_uri = form.get("redirect_uri")

  if not email:
    raise OAuthError("Email is required")
  if not redirect_uri:
    raise OAuthError("redirect_uri required")
  try:
    claims = json.loads(form.get("claims") or "{}")
    if not isinstance(claims, dict):
      raise ValueError("not an object")
  except ValueError:
    raise OAuthError("claims must be a JSON object")

  pkce = parse_pkce(form)
  user = build_user(email, form.get("groups"), claims)
  return redirect_with_code(redirect_uri, form.get("state"), form.get("nonce"), user, pkce)

@oidc_bp.route("/token", methods=["POST"])
def token() -> Response:
  data = request_data()
  require_authorization_code_grant(data)
  authenticate_client(data)
  entry = redeem_code(data)
  return jsonify(issue_tokens(entry))

@oidc_bp.route("/userinfo", methods=["GET", "POST"])
def userinfo() -> Response:
  auth = request.headers.get("Authorization", "")
  entry = stores.tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
  if not entry or time.time() > entry.expires_at:
    raise OAuthError(INVALID_TOKEN, status=401, headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
  return jsonify(identity_claims(entry.user))

@oidc_bp.route("/jwks")
def jwks() -> Response:
  return send_file(str(config.JWKS_PATH), mimetype="application/json")
