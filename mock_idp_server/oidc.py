import base64, hashlib, hmac, json, secrets, time, uuid, jwt
from pathlib import Path
from urllib.parse import urlencode, unquote_plus
from flask import Blueprint, request, jsonify, redirect, render_template, send_file
import config

oidc_bp = Blueprint("oidc", __name__)

class UsersFileError(Exception):
  """The users file is unreadable or malformed."""

class OAuthError(Exception):
  """An error answered as JSON: {"error": ..., "error_description": ...} (description omitted when empty)."""
  def __init__(self, error, description="", status=400, headers=None):
    super().__init__(error)
    self.error, self.description, self.status, self.headers = error, description, status, headers or {}

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
  return oauth_error(OAuthError("invalid_users_file", str(error), status=500))

@oidc_bp.app_errorhandler(OAuthError)
def oauth_error(error):
  body = {"error": error.error}
  if error.description:
    body["error_description"] = error.description
  return jsonify(body), error.status, error.headers

def purge_expired():
  now = time.time()
  for registry in (store, tokens):
    # Snapshot first: other request threads may insert while this one iterates.
    for key, value in list(registry.items()):
      if value["expires_at"] < now:
        registry.pop(key, None)

def request_data():
  """Form fields, or a JSON object for clients that post JSON."""
  if request.form:
    return request.form
  data = request.get_json(silent=True)
  return data if isinstance(data, dict) else {}

def client_credentials():
  """Returns (client_id, client_secret) from HTTP Basic auth or the request body."""
  auth = request.headers.get("Authorization", "")
  if auth.startswith("Basic "):
    try:
      client_id, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
      return unquote_plus(client_id), unquote_plus(secret)
    except Exception:
      return None, None
  data = request_data()
  return data.get("client_id"), data.get("client_secret")

def parse_pkce(params):
  """Returns (pkce, error) from /authorize query args or /login form fields; pkce is None without a challenge."""
  challenge = params.get("code_challenge")
  if not challenge:
    return None, None
  method = params.get("code_challenge_method") or "plain"
  if method not in ("S256", "plain"):
    return None, "unsupported code_challenge_method"
  return {"challenge": challenge, "method": method}, None

def pkce_matches(pkce, verifier):
  if not verifier:
    return False
  if pkce["method"] == "S256":
    digest = hashlib.sha256(verifier.encode()).digest()
    verifier = base64.urlsafe_b64encode(digest).decode().rstrip("=")
  return hmac.compare_digest(verifier.encode(), pkce["challenge"].encode())

@oidc_bp.after_request
def no_store_token_responses(response):
  """RFC 6749 section 5.1: token responses must not be cached."""
  if request.path == "/token":
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
  return response

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
    raise OAuthError("body must be a JSON object")
  email = data.get("email")
  if not email:
    raise OAuthError("email required")
  if not isinstance(email, str):
    raise OAuthError("email must be a string")
  if not isinstance(data.get("claims", {}), dict):
    raise OAuthError("claims must be an object")

  next_user = build_user(email, data.get("groups"), data.get("claims"))
  return jsonify({"status": "ok", "user": next_user})

@oidc_bp.route("/authorize")
def authorize():
  args = request.args
  if args.get("response_type", "code") != "code":
    raise OAuthError("unsupported_response_type")
  if "openid" not in args.get("scope", "openid").split():
    raise OAuthError("invalid_scope", "openid scope required")
  redirect_uri = args.get("redirect_uri")
  if not redirect_uri:
    raise OAuthError("invalid_request", "redirect_uri required")
  if args.get("client_id") not in (None, config.CLIENT_ID):
    raise OAuthError("unauthorized_client")

  pkce, pkce_error = parse_pkce(args)
  if args.get("code_challenge_method") == "":
    pkce_error = "unsupported code_challenge_method"
  if pkce_error:
    raise OAuthError("invalid_request", pkce_error)

  global next_user
  user, next_user = next_user, None
  user = user or auto_login_user()
  if user:
    return issue_code_and_redirect(redirect_uri, args.get("state"), args.get("nonce"), user, pkce)

  return render_template("login.html", users=load_users(), redirect_uri=redirect_uri, state=args.get("state"),
                         nonce=args.get("nonce"), code_challenge=args.get("code_challenge"),
                         code_challenge_method=args.get("code_challenge_method"))

@oidc_bp.route("/login", methods=["POST"])
def login():
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

  pkce, pkce_error = parse_pkce(form)
  if pkce_error:
    raise OAuthError("invalid_request", pkce_error)
  user = build_user(email, form.get("groups"), claims)
  return issue_code_and_redirect(redirect_uri, form.get("state"), form.get("nonce"), user, pkce)

def require_authorization_code_grant(data):
  # JSON clients can send any type; form fields are always strings.
  for name in ("grant_type", "code", "code_verifier", "redirect_uri"):
    if not isinstance(data.get(name, ""), str):
      raise OAuthError("invalid_request", f"{name} must be a string")
  if data.get("grant_type", "authorization_code") != "authorization_code":
    raise OAuthError("unsupported_grant_type")

def authenticate_client(data):
  """Checks the client without consuming the code, so a failed attempt leaves it redeemable."""
  client_id, client_secret = client_credentials()
  if client_id != config.CLIENT_ID:
    raise OAuthError("invalid_client", status=401)
  if client_secret is None:
    # Public clients are only accepted when they protect the code with PKCE.
    entry = store.get(data.get("code"))
    if not (entry and entry["pkce"]):
      raise OAuthError("invalid_client", status=401)
  elif client_secret != config.CLIENT_SECRET:
    raise OAuthError("invalid_client", status=401)

def redeem_code(data):
  """Codes are single use and short lived. pop() is atomic, so of several concurrent requests only one gets it."""
  entry = store.pop(data.get("code"), None)
  if not entry or time.time() > entry["expires_at"]:
    raise OAuthError("invalid_grant", "code not found or expired")
  if data.get("redirect_uri") not in (None, entry["redirect_uri"]):
    raise OAuthError("invalid_grant", "redirect_uri mismatch")
  if entry["pkce"] and not pkce_matches(entry["pkce"], data.get("code_verifier")):
    raise OAuthError("invalid_grant", "code_verifier mismatch")
  return entry

def build_id_token(user, nonce):
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

def issue_tokens(entry):
  access_token = secrets.token_urlsafe(24)
  tokens[access_token] = {"user": entry["user"], "expires_at": time.time() + config.TOKEN_TTL_SECONDS}
  return {
    "access_token": access_token,
    "id_token": build_id_token(entry["user"], entry["nonce"]),
    "token_type": "Bearer",
    "expires_in": config.TOKEN_TTL_SECONDS,
  }

@oidc_bp.route("/token", methods=["POST"])
def token():
  data = request_data()
  require_authorization_code_grant(data)
  authenticate_client(data)
  entry = redeem_code(data)
  return jsonify(issue_tokens(entry))

@oidc_bp.route("/userinfo", methods=["GET", "POST"])
def userinfo():
  auth = request.headers.get("Authorization", "")
  entry = tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
  if not entry or time.time() > entry["expires_at"]:
    raise OAuthError("invalid_token", status=401, headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
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
