import base64, hashlib, hmac, json, secrets, time, uuid, jwt
from pathlib import Path
from urllib.parse import urlencode, unquote_plus
from flask import Blueprint, request, jsonify, redirect, render_template, send_file
import config

oidc_bp = Blueprint("oidc", __name__)

class UsersFileError(Exception):
  """The users file is unreadable or malformed."""

# Claims a user can never override through `claims` or the users file.
RESERVED_CLAIMS = {"iss", "aud", "exp", "iat", "nonce"}

store = {}   # authorization code -> {user, nonce, redirect_uri, pkce, expires_at}
tokens = {}  # access token -> {user, expires_at}
# Identity used by the next /authorize call, set through POST /set-user (consumed once).
next_user = None

def parse_groups(raw):
  if isinstance(raw, list):
    return [str(g).strip() for g in raw if str(g).strip()]
  return [g.strip() for g in str(raw or "").split(",") if g.strip()]

def build_user(email, groups=None, claims=None):
  extra = {k: v for k, v in (claims or {}).items() if k not in RESERVED_CLAIMS}
  return {"email": email, "groups": parse_groups(groups), "claims": extra}

def identity_claims(user):
  """Claims describing the user, shared by the ID token and /userinfo."""
  return {"sub": user["email"], "email": user["email"], "groups": user["groups"], **user["claims"]}

def load_users():
  """Reads the users file on every call so it can be edited without restarting."""
  if not config.USERS_FILE:
    return []
  try:
    raw = json.loads(Path(config.USERS_FILE).read_text())
  except (OSError, ValueError) as e:
    raise UsersFileError(f"cannot read users file {config.USERS_FILE}: {e}") from None
  entries = raw.get("users") if isinstance(raw, dict) else raw
  if not isinstance(entries, list):
    raise UsersFileError(f"{config.USERS_FILE} must be a list of users or {{\"users\": [...]}}")
  users = []
  for entry in entries:
    if not isinstance(entry, dict) or not entry.get("email"):
      raise UsersFileError(f"every user in {config.USERS_FILE} needs an 'email'")
    extra = {k: v for k, v in entry.items() if k not in ("email", "groups")}
    users.append(build_user(entry["email"], entry.get("groups"), extra))
  return users

def auto_login_user():
  if not config.AUTO_LOGIN:
    return None
  return next((u for u in load_users() if u["email"] == config.AUTO_LOGIN), build_user(config.AUTO_LOGIN))

def validate_config():
  """Fails fast at start-up instead of on the first request."""
  try:
    load_users()
  except UsersFileError as e:
    config.fail(str(e))

@oidc_bp.app_errorhandler(UsersFileError)
def users_file_error(error):
  """A users file broken while the server runs is reported to the caller, not by dropping the request."""
  return jsonify({"error": "invalid_users_file", "error_description": str(error)}), 500

def purge_expired():
  now = time.time()
  for registry in (store, tokens):
    for key in [k for k, v in registry.items() if v["expires_at"] < now]:
      del registry[key]

def client_credentials():
  """Returns (client_id, client_secret) from HTTP Basic auth or the request body."""
  auth = request.headers.get("Authorization", "")
  if auth.startswith("Basic "):
    try:
      client_id, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
      return unquote_plus(client_id), unquote_plus(secret)
    except Exception:
      return None, None
  data = request.form if request.form else request.get_json(silent=True) or {}
  return data.get("client_id"), data.get("client_secret")

def parse_pkce(challenge, method):
  """Returns (pkce, error); pkce is None when the request carries no challenge."""
  method = method or "plain"
  if not challenge:
    return None, None
  if method not in ("S256", "plain"):
    return None, "unsupported code_challenge_method"
  return {"challenge": challenge, "method": method}, None

def pkce_matches(pkce, verifier):
  if not verifier:
    return False
  if pkce["method"] == "S256":
    digest = hashlib.sha256(verifier.encode()).digest()
    verifier = base64.urlsafe_b64encode(digest).decode().rstrip("=")
  return hmac.compare_digest(verifier, pkce["challenge"])

@oidc_bp.route("/healthz")
def healthz():
  return jsonify({"status": "ok"})

@oidc_bp.route("/.well-known/openid-configuration")
def well_known():
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
    "code_challenge_methods_supported": ["S256", "plain"],
    "scopes_supported": ["openid", "email", "profile"],
    "claims_supported": ["sub", "email", "groups"],
  })

@oidc_bp.route("/set-user", methods=["POST"])
def set_user():
  """Pre-seeds the identity of the next login so tests can skip the login form.

  Body: {"email": "...", "groups": ["a", "b"], "claims": {"name": "Jane"}}
  """
  global next_user
  # No force=True: requiring a JSON Content-Type makes browsers preflight cross-site requests.
  data = request.get_json(silent=True)
  if not isinstance(data, dict):
    return jsonify({"error": "body must be a JSON object"}), 400
  email = data.get("email")
  if not email:
    return jsonify({"error": "email required"}), 400
  if not isinstance(email, str):
    return jsonify({"error": "email must be a string"}), 400
  if not isinstance(data.get("claims", {}), dict):
    return jsonify({"error": "claims must be an object"}), 400

  next_user = build_user(email, data.get("groups"), data.get("claims"))
  return jsonify({"status": "ok", "user": next_user})

@oidc_bp.route("/authorize")
def authorize():
  args = request.args
  if args.get("response_type", "code") != "code":
    return jsonify({"error": "unsupported_response_type"}), 400
  if "openid" not in args.get("scope", "openid").split():
    return jsonify({"error": "invalid_scope", "error_description": "openid scope required"}), 400
  redirect_uri = args.get("redirect_uri")
  if not redirect_uri:
    return jsonify({"error": "invalid_request", "error_description": "redirect_uri required"}), 400
  if args.get("client_id") not in (None, config.CLIENT_ID):
    return jsonify({"error": "unauthorized_client"}), 400

  challenge = args.get("code_challenge")
  method = args.get("code_challenge_method", "plain")
  pkce, pkce_error = parse_pkce(challenge, method)
  if pkce_error:
    return jsonify({"error": "invalid_request", "error_description": pkce_error}), 400

  global next_user
  user, next_user = next_user, None
  user = user or auto_login_user()
  if user:
    return issue_code_and_redirect(redirect_uri, args.get("state"), args.get("nonce"), user, pkce)

  return render_template("login.html", users=load_users(), redirect_uri=redirect_uri, state=args.get("state"),
                         nonce=args.get("nonce"), code_challenge=challenge, code_challenge_method=method)

@oidc_bp.route("/login", methods=["POST"])
def login():
  form = request.form
  email = form.get("email")
  redirect_uri = form.get("redirect_uri")

  if not email:
    return jsonify({"error": "Email is required"}), 400
  if not redirect_uri:
    return jsonify({"error": "redirect_uri required"}), 400
  try:
    claims = json.loads(form.get("claims") or "{}")
    if not isinstance(claims, dict):
      raise ValueError("not an object")
  except ValueError:
    return jsonify({"error": "claims must be a JSON object"}), 400

  challenge = form.get("code_challenge")
  pkce, pkce_error = parse_pkce(challenge, form.get("code_challenge_method"))
  if pkce_error:
    return jsonify({"error": "invalid_request", "error_description": pkce_error}), 400
  user = build_user(email, form.get("groups"), claims)
  return issue_code_and_redirect(redirect_uri, form.get("state"), form.get("nonce"), user, pkce)

@oidc_bp.route("/token", methods=["POST"])
def token():
  data = request.form if request.form else request.get_json(silent=True) or {}

  if data.get("grant_type", "authorization_code") != "authorization_code":
    return jsonify({"error": "unsupported_grant_type"}), 400

  entry = store.get(data.get("code"))
  client_id, client_secret = client_credentials()
  if client_id != config.CLIENT_ID:
    return jsonify({"error": "invalid_client"}), 401
  if client_secret is None:
    # Public clients are only accepted when they protect the code with PKCE.
    if not (entry and entry["pkce"]):
      return jsonify({"error": "invalid_client"}), 401
  elif client_secret != config.CLIENT_SECRET:
    return jsonify({"error": "invalid_client"}), 401

  # Codes are single use and short lived. pop() is atomic, so of several concurrent requests
  # only one gets the entry; a failed client authentication above leaves the code intact.
  entry = store.pop(data.get("code"), None)
  if not entry or time.time() > entry["expires_at"]:
    return jsonify({"error": "invalid_grant", "error_description": "code not found or expired"}), 400
  if data.get("redirect_uri") not in (None, entry["redirect_uri"]):
    return jsonify({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}), 400
  if entry["pkce"] and not pkce_matches(entry["pkce"], data.get("code_verifier")):
    return jsonify({"error": "invalid_grant", "error_description": "code_verifier mismatch"}), 400

  user = entry["user"]
  now = int(time.time())
  payload = {
    **identity_claims(user),
    "iss": config.ISSUER,
    "aud": config.CLIENT_ID,
    "exp": now + config.TOKEN_TTL_SECONDS,
    "iat": now,
  }
  if entry["nonce"]:
    payload["nonce"] = entry["nonce"]

  id_token = jwt.encode(payload, config.PRIVATE_KEY_PATH.read_bytes(), algorithm="RS256",
                        headers={"kid": config.KEY_ID})
  access_token = secrets.token_urlsafe(24)
  tokens[access_token] = {"user": user, "expires_at": time.time() + config.TOKEN_TTL_SECONDS}

  return jsonify({
    "access_token": access_token,
    "id_token": id_token,
    "token_type": "Bearer",
    "expires_in": config.TOKEN_TTL_SECONDS,
  })

@oidc_bp.route("/userinfo", methods=["GET", "POST"])
def userinfo():
  auth = request.headers.get("Authorization", "")
  entry = tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
  if not entry or time.time() > entry["expires_at"]:
    return jsonify({"error": "invalid_token"}), 401, {"WWW-Authenticate": 'Bearer error="invalid_token"'}
  return jsonify(identity_claims(entry["user"]))

@oidc_bp.route("/jwks")
def jwks():
  return send_file(str(config.JWKS_PATH), mimetype="application/json")

def issue_code_and_redirect(redirect_uri, state, nonce, user, pkce=None):
  purge_expired()
  code = f"code-{uuid.uuid4().hex}"
  store[code] = {
    "nonce": nonce,
    "user": user,
    "redirect_uri": redirect_uri,
    "pkce": pkce,
    "expires_at": time.time() + config.CODE_TTL_SECONDS,
  }

  params = {"code": code}
  if state:
    params["state"] = state

  print(f"Issued auth code {code} for user={user}")
  separator = "&" if "?" in redirect_uri else "?"
  return redirect(f"{redirect_uri}{separator}{urlencode(params)}", code=302)
