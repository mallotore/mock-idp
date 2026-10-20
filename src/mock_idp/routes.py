import json
import logging
from dataclasses import asdict
from urllib.parse import urlencode

from flask import Blueprint, Response, current_app, jsonify, redirect, render_template, request, send_file
from werkzeug.wrappers import Response as RedirectResponse

from .errors import INVALID_TOKEN, OAuthError
from .parsing import authorization, parse_authorize_request, request_data, require_authorization_code_grant
from .pkce import PKCE_METHODS, Pkce, parse_pkce
from .settings import Settings
from .stores import State
from .tokens import authenticate_client, issue_tokens, redeem_code
from .users import User, auto_login_user, build_user, identity_claims, load_users

oidc_bp = Blueprint("oidc", __name__)
logger = logging.getLogger(__name__)


def app_state() -> State:
  return current_app.extensions["mock_idp"]


def settings() -> Settings:
  return app_state().settings


def redirect_with_code(
  redirect_uri: str, state: str | None, nonce: str | None, user: User, pkce: Pkce | None
) -> RedirectResponse:
  code = app_state().issue_code(user, nonce, redirect_uri, pkce)
  params = {"code": code}
  if state:
    params["state"] = state
  logger.info("Issued auth code %s for user=%s", code, user.email)
  separator = "&" if "?" in redirect_uri else "?"
  return redirect(f"{redirect_uri}{separator}{urlencode(params)}", code=302)


@oidc_bp.after_request
def no_store_token_responses(response: Response) -> Response:
  if request.path == "/token":
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
  return response


@oidc_bp.route("/healthz")
def healthz() -> Response:
  return jsonify({"status": "ok"})


@oidc_bp.route("/.well-known/openid-configuration")
def well_known() -> Response:
  s = settings()
  return jsonify(
    {
      "issuer": s.issuer,
      "authorization_endpoint": f"{s.public_url}/authorize",
      "token_endpoint": f"{s.issuer}/token",
      "userinfo_endpoint": f"{s.issuer}/userinfo",
      "jwks_uri": f"{s.issuer}/jwks",
      "response_types_supported": ["code"],
      "subject_types_supported": ["public"],
      "id_token_signing_alg_values_supported": ["RS256"],
      "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
      "code_challenge_methods_supported": list(PKCE_METHODS),
      "scopes_supported": ["openid", "email", "profile"],
      "claims_supported": ["sub", "email", "groups"],
    }
  )


@oidc_bp.route("/set-user", methods=["POST"])
def set_user() -> Response:
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
  app_state().next_user.set(user)
  return jsonify({"status": "ok", "user": asdict(user)})


@oidc_bp.route("/authorize")
def authorize() -> Response | RedirectResponse | str:
  req = parse_authorize_request(request.args, settings())
  user = app_state().next_user.take() or auto_login_user(settings())
  if user:
    return redirect_with_code(req.redirect_uri, req.state, req.nonce, user, req.pkce)
  return render_template(
    "login.html",
    users=load_users(settings()),
    redirect_uri=req.redirect_uri,
    state=req.state,
    nonce=req.nonce,
    pkce=req.pkce,
  )


@oidc_bp.route("/login", methods=["POST"])
def login() -> RedirectResponse:
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
  state = app_state()
  authenticate_client(data, state)
  signing_key = state.signing_key()
  entry = redeem_code(data, state)
  return jsonify(issue_tokens(entry, signing_key, state))


@oidc_bp.route("/userinfo", methods=["GET", "POST"])
def userinfo() -> Response:
  entry = app_state().tokens.get(authorization("Bearer"))
  if not entry:
    raise OAuthError(INVALID_TOKEN, status=401, headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
  return jsonify(identity_claims(entry.user))


@oidc_bp.route("/jwks")
def jwks() -> Response:
  return send_file(str(settings().jwks_path), mimetype="application/json")
