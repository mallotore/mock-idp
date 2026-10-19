import base64, hashlib, time
from urllib.parse import urlparse, parse_qs

import jwt
import pytest
import config
import oidc
from app import create_app
from config import ISSUER, CLIENT_ID, CLIENT_SECRET

REDIRECT = "http://localhost:8250/oidc/callback"


def authorize(client, **params):
  query = {"redirect_uri": REDIRECT, "state": "st", "nonce": "nn", "client_id": CLIENT_ID, **params}
  return client.get("/authorize", query_string=query)


def code_from(response):
  return parse_qs(urlparse(response.headers["Location"]).query)["code"][0]


def exchange(client, code, **overrides):
  data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
          "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, **overrides}
  return client.post("/token", data={k: v for k, v in data.items() if v is not None})


def login(client, email="jane@example.com", groups="admins,devs"):
  response = client.post("/login", data={"email": email, "groups": groups,
                                         "redirect_uri": REDIRECT, "state": "st", "nonce": "nn"})
  assert response.status_code == 302
  return code_from(response)


def signing_key(client):
  jwks = client.get("/jwks").get_json()
  return jwt.PyJWK(jwks["keys"][0]).key


def decode(client, response):
  return jwt.decode(response.get_json()["id_token"], signing_key(client), algorithms=["RS256"],
                    audience=CLIENT_ID, issuer=ISSUER)


def test_discovery_document(client):
  doc = client.get("/.well-known/openid-configuration").get_json()
  assert doc["issuer"] == ISSUER
  assert doc["token_endpoint"] == f"{ISSUER}/token"
  assert doc["jwks_uri"] == f"{ISSUER}/jwks"
  assert doc["authorization_endpoint"].endswith("/authorize")


def test_authorize_shows_login_form_with_hidden_fields(client):
  response = authorize(client)
  html = response.get_data(as_text=True)
  assert response.status_code == 200
  assert 'name="state" value="st"' in html
  assert 'name="nonce" value="nn"' in html


def test_authorize_requires_redirect_uri(client):
  assert client.get("/authorize").status_code == 400


def test_authorize_rejects_unknown_client(client):
  assert authorize(client, client_id="someone-else").status_code == 400


def test_login_redirects_with_code_and_state(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "state": "st"})
  query = parse_qs(urlparse(response.headers["Location"]).query)
  assert response.status_code == 302
  assert response.headers["Location"].startswith(REDIRECT)
  assert query["state"] == ["st"]
  assert query["code"][0].startswith("code-")


def test_login_requires_email(client):
  assert client.post("/login", data={"redirect_uri": REDIRECT}).status_code == 400


def test_id_token_contains_identity_groups_and_nonce(client):
  response = exchange(client, login(client))
  token = response.get_json()["id_token"]
  claims = decode(client, response)
  assert claims["email"] == claims["sub"] == "jane@example.com"
  assert claims["groups"] == ["admins", "devs"]
  assert claims["nonce"] == "nn"
  assert jwt.get_unverified_header(token)["kid"] == "mock-key-1"


def test_token_without_nonce_omits_claim(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT})
  token = exchange(client, code_from(response)).get_json()["id_token"]
  assert "nonce" not in jwt.decode(token, options={"verify_signature": False})


def test_code_is_single_use(client):
  code = login(client)
  assert exchange(client, code).status_code == 200
  second = exchange(client, code)
  assert second.status_code == 400
  assert second.get_json()["error"] == "invalid_grant"


def test_expired_code_is_rejected(client):
  code = login(client)
  oidc.store[code]["expires_at"] = time.time() - 1
  assert exchange(client, code).status_code == 400


def test_unknown_code_is_rejected(client):
  assert exchange(client, "code-nope").status_code == 400


def test_redirect_uri_must_match_authorization_request(client):
  assert exchange(client, login(client), redirect_uri="http://evil.example/cb").status_code == 400


@pytest.mark.parametrize("overrides", [{"client_secret": "wrong"}, {"client_id": "wrong"}, {"client_secret": None}])
def test_token_rejects_bad_client_credentials(client, overrides):
  assert exchange(client, login(client), **overrides).status_code == 401


def test_token_accepts_basic_auth(client):
  basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
  response = client.post("/token", data={"grant_type": "authorization_code", "code": login(client)},
                         headers={"Authorization": f"Basic {basic}"})
  assert response.status_code == 200


@pytest.mark.parametrize("body", [[1], "x", 5])
def test_token_rejects_non_object_json_body(client, body):
  response = client.post("/token", json=body)
  assert response.status_code in (400, 401)
  assert response.is_json


def test_token_rejects_other_grant_types(client):
  assert exchange(client, login(client), grant_type="password").status_code == 400


def test_set_user_skips_login_form_once(client):
  response = client.post("/set-user", json={"email": "bot@example.com", "groups": ["ci"]})
  assert response.get_json()["user"] == {"email": "bot@example.com", "groups": ["ci"], "claims": {}}

  first = authorize(client)
  assert first.status_code == 302
  token = exchange(client, code_from(first)).get_json()["id_token"]
  claims = jwt.decode(token, options={"verify_signature": False})
  assert claims["email"] == "bot@example.com" and claims["groups"] == ["ci"]

  # The seeded identity is consumed: the next login shows the form again.
  assert authorize(client).status_code == 200


def test_set_user_accepts_comma_separated_groups(client):
  client.post("/set-user", json={"email": "a@b.c", "groups": "x, y"})
  assert oidc.next_user["groups"] == ["x", "y"]


def test_set_user_requires_email(client):
  assert client.post("/set-user", json={"groups": []}).status_code == 400


def test_healthz(client):
  assert client.get("/healthz").get_json() == {"status": "ok"}


def test_discovery_advertises_userinfo_and_pkce(client):
  doc = client.get("/.well-known/openid-configuration").get_json()
  assert doc["userinfo_endpoint"] == f"{ISSUER}/userinfo"
  assert "S256" in doc["code_challenge_methods_supported"]


def test_login_page_has_banner_and_no_none_strings(client):
  html = authorize(client, state=None, nonce=None).get_data(as_text=True)
  assert "NOT FOR PRODUCTION" in html
  assert "None" not in html


def test_extra_claims_from_login_form_reach_id_token_and_userinfo(client):
  response = client.post("/login", data={"email": "jane@example.com", "redirect_uri": REDIRECT,
                                         "claims": '{"name": "Jane Doe", "iss": "evil", "tier": 3}'})
  tokens = exchange(client, code_from(response))
  claims = decode(client, tokens)
  assert claims["name"] == "Jane Doe" and claims["tier"] == 3
  assert claims["iss"] == ISSUER  # reserved claims cannot be overridden

  info = client.get("/userinfo", headers={"Authorization": f"Bearer {tokens.get_json()['access_token']}"})
  assert info.get_json() == {"sub": "jane@example.com", "email": "jane@example.com", "groups": [],
                             "name": "Jane Doe", "tier": 3}


def test_login_rejects_claims_that_are_not_a_json_object(client):
  for claims in ("not json", "[1]"):
    response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "claims": claims})
    assert response.status_code == 400


def test_set_user_claims_and_sub_override(client):
  client.post("/set-user", json={"email": "a@b.c", "claims": {"sub": "user-123", "name": "A"}})
  claims = decode(client, exchange(client, code_from(authorize(client))))
  assert claims["sub"] == "user-123" and claims["name"] == "A"


def test_set_user_rejects_non_object_claims(client):
  assert client.post("/set-user", json={"email": "a@b.c", "claims": ["x"]}).status_code == 400


def test_userinfo_requires_a_valid_bearer_token(client):
  assert client.get("/userinfo").status_code == 401
  assert client.get("/userinfo", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_access_token_lives_for_the_full_ttl(client, monkeypatch):
  monkeypatch.setattr(config, "TOKEN_TTL_SECONDS", 1)
  clock = [1000.9]
  monkeypatch.setattr(oidc.time, "time", lambda: clock[0])
  access_token = exchange(client, login(client)).get_json()["access_token"]
  auth = {"Authorization": f"Bearer {access_token}"}
  clock[0] = 1001.8
  assert client.get("/userinfo", headers=auth).status_code == 200
  clock[0] = 1001.95
  assert client.get("/userinfo", headers=auth).status_code == 401


def test_userinfo_rejects_expired_token(client):
  access_token = exchange(client, login(client)).get_json()["access_token"]
  oidc.tokens[access_token]["expires_at"] = time.time() - 1
  assert client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"}).status_code == 401


def s256(verifier):
  return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


def test_pkce_s256_public_client(client):
  verifier = "v" * 50
  response = authorize(client, code_challenge=s256(verifier), code_challenge_method="S256")
  # The login form carries the challenge through to /login.
  html = response.get_data(as_text=True)
  assert f'name="code_challenge" value="{s256(verifier)}"' in html
  login_response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT,
                                               "code_challenge": s256(verifier), "code_challenge_method": "S256"})
  code = code_from(login_response)
  public = {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": verifier}
  assert client.post("/token", data=public).status_code == 200


@pytest.mark.parametrize("verifier", ["wrong-verifier", None])
def test_pkce_rejects_wrong_or_missing_verifier(client, verifier):
  challenge = s256("v" * 50)
  code = code_from(client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT,
                                               "code_challenge": challenge, "code_challenge_method": "S256"}))
  data = {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": verifier}
  response = client.post("/token", data={k: v for k, v in data.items() if v})
  assert response.status_code == 400 and response.get_json()["error"] == "invalid_grant"


def test_pkce_plain_method(client):
  code = code_from(client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT,
                                               "code_challenge": "plain-secret"}))
  data = {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": "plain-secret"}
  assert client.post("/token", data=data).status_code == 200


def test_pkce_plain_rejects_non_ascii_verifier(client):
  code = code_from(client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT,
                                               "code_challenge": "abc"}))
  data = {"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID, "code_verifier": "é"}
  response = client.post("/token", data=data)
  assert response.status_code == 400
  assert response.get_json()["error"] == "invalid_grant"


def test_authorize_rejects_unknown_challenge_method(client):
  assert authorize(client, code_challenge="x", code_challenge_method="S512").status_code == 400


def test_authorize_rejects_empty_challenge_method(client):
  assert authorize(client, code_challenge="x", code_challenge_method="").status_code == 400


def test_public_client_without_pkce_is_rejected(client):
  data = {"grant_type": "authorization_code", "code": login(client), "client_id": CLIENT_ID}
  assert client.post("/token", data=data).status_code == 401


@pytest.fixture
def users_file(tmp_path, monkeypatch):
  path = tmp_path / "users.json"
  path.write_text('{"users": [{"email": "admin@example.com", "groups": ["admins"], "name": "Ada"},'
                  ' {"email": "guest@example.com"}]}')
  monkeypatch.setattr(config, "USERS_FILE", str(path))
  return path


def test_users_file_populates_login_page(client, users_file):
  html = authorize(client).get_data(as_text=True)
  assert "admin@example.com" in html and "guest@example.com" in html


def test_auto_login_uses_user_from_file(client, users_file, monkeypatch):
  monkeypatch.setattr(config, "AUTO_LOGIN", "admin@example.com")
  response = authorize(client)
  assert response.status_code == 302
  claims = decode(client, exchange(client, code_from(response)))
  assert claims["groups"] == ["admins"] and claims["name"] == "Ada"


def test_auto_login_for_email_not_in_file_has_no_groups(client, monkeypatch):
  monkeypatch.setattr(config, "AUTO_LOGIN", "ci@example.com")
  claims = decode(client, exchange(client, code_from(authorize(client))))
  assert claims["email"] == "ci@example.com" and claims["groups"] == []


def test_set_user_wins_over_auto_login(client, monkeypatch):
  monkeypatch.setattr(config, "AUTO_LOGIN", "ci@example.com")
  client.post("/set-user", json={"email": "manual@example.com"})
  assert decode(client, exchange(client, code_from(authorize(client))))["email"] == "manual@example.com"


@pytest.mark.parametrize("content", ["not json", '{"users": "x"}', '[{"groups": []}]'])
def test_invalid_users_file_fails_fast(tmp_path, monkeypatch, content):
  path = tmp_path / "users.json"
  path.write_text(content)
  monkeypatch.setattr(config, "USERS_FILE", str(path))
  with pytest.raises(SystemExit) as error:
    create_app()
  assert "invalid configuration" in str(error.value)


def test_users_file_broken_while_running_returns_a_clear_error(client, users_file):
  assert authorize(client).status_code == 200
  users_file.write_text("{ broken")
  response = authorize(client)
  assert response.status_code == 500
  assert response.get_json()["error"] == "invalid_users_file"
  assert "cannot read users file" in response.get_json()["error_description"]
  users_file.write_text('[{"email": "a@b.c"}]')
  assert authorize(client).status_code == 200


def test_missing_users_file_fails_fast(monkeypatch):
  monkeypatch.setattr(config, "USERS_FILE", "/does/not/exist.json")
  with pytest.raises(SystemExit):
    create_app()


def test_expired_entries_are_purged_on_next_login(client):
  stale = login(client)
  oidc.store[stale]["expires_at"] = time.time() - 1
  login(client)
  assert stale not in oidc.store


def test_code_redeemed_concurrently_succeeds_only_once(client):
  import threading
  code = login(client)
  barrier = threading.Barrier(8)
  statuses = []

  def redeem():
    local = create_app().test_client()
    barrier.wait()
    statuses.append(exchange(local, code).status_code)

  threads = [threading.Thread(target=redeem) for _ in range(8)]
  [t.start() for t in threads]
  [t.join() for t in threads]
  assert sorted(statuses) == [200] + [400] * 7


def test_wrong_client_secret_does_not_consume_the_code(client):
  code = login(client)
  assert exchange(client, code, client_secret="nope").status_code == 401
  assert exchange(client, code).status_code == 200


def test_basic_auth_credentials_are_form_urldecoded(client, monkeypatch):
  monkeypatch.setattr(config, "CLIENT_SECRET", "s3cr+t/%")
  encoded = base64.b64encode(f"{CLIENT_ID}:s3cr%2Bt%2F%25".encode()).decode()
  code = login(client)
  response = client.post("/token", data={"code": code}, headers={"Authorization": f"Basic {encoded}"})
  assert response.status_code == 200


@pytest.mark.parametrize("body", ["[]", '"x"', "5", "not json"])
def test_set_user_rejects_bodies_that_are_not_a_json_object(client, body):
  response = client.post("/set-user", data=body, content_type="application/json")
  assert response.status_code == 400


def test_set_user_rejects_non_string_email(client):
  assert client.post("/set-user", json={"email": 5}).status_code == 400


def test_set_user_tolerates_non_string_groups(client):
  response = client.post("/set-user", json={"email": "a@b.c", "groups": 5})
  assert response.status_code == 200
  assert response.get_json()["user"]["groups"] == ["5"]


def test_set_user_requires_a_json_content_type(client):
  """A cross-site page can only send simple content types without a preflight."""
  response = client.post("/set-user", data='{"email": "evil@example.com"}', content_type="text/plain")
  assert response.status_code == 400
  assert oidc.next_user is None


def test_login_rejects_unknown_challenge_method(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc",
                                         "code_challenge_method": "S512"})
  assert response.status_code == 400
  assert not oidc.store


def test_login_defaults_challenge_method_to_plain(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc"})
  assert response.status_code == 302
  assert next(iter(oidc.store.values()))["pkce"] == {"challenge": "abc", "method": "plain"}


def test_authorize_rejects_unsupported_response_type(client):
  response = authorize(client, response_type="token")
  assert response.status_code == 400
  assert response.get_json()["error"] == "unsupported_response_type"


def test_authorize_requires_openid_scope(client):
  response = authorize(client, scope="email profile")
  assert response.status_code == 400
  assert response.get_json()["error"] == "invalid_scope"


def test_authorize_accepts_code_response_type_and_openid_scope(client):
  assert authorize(client, response_type="code", scope="openid email").status_code == 200
