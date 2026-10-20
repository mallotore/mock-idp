import base64, re, sys, threading

import jwt
import pytest
from urllib.parse import urlparse, parse_qs

from mock_idp.app import create_app
from helpers import (REDIRECT, ISSUER, CLIENT_ID, CLIENT_SECRET, KEY_ID, authorize, code_from, decode,
                     exchange, expire_access_token, expire_code, fill_store, login, peek_next_user, s256, set_clock,
                     stored_codes, stored_pkce)


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
  assert jwt.get_unverified_header(token)["kid"] == KEY_ID


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
  expire_code(code)
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
  assert peek_next_user()["groups"] == ["x", "y"]


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


def test_access_token_lives_for_the_full_ttl(client, monkeypatch, set_config):
  set_config(TOKEN_TTL_SECONDS=1)
  clock = [1000.9]
  set_clock(monkeypatch, lambda: clock[0])
  access_token = exchange(client, login(client)).get_json()["access_token"]
  auth = {"Authorization": f"Bearer {access_token}"}
  clock[0] = 1001.8
  assert client.get("/userinfo", headers=auth).status_code == 200
  clock[0] = 1001.95
  assert client.get("/userinfo", headers=auth).status_code == 401


def test_userinfo_rejects_expired_token(client):
  access_token = exchange(client, login(client)).get_json()["access_token"]
  expire_access_token(access_token)
  assert client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"}).status_code == 401


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
def users_file(tmp_path, set_config):
  path = tmp_path / "users.json"
  path.write_text('{"users": [{"email": "admin@example.com", "groups": ["admins"], "name": "Ada"},'
                  ' {"email": "guest@example.com"}]}')
  set_config(USERS_FILE=str(path))
  return path


def test_users_file_populates_login_page(client, users_file):
  html = authorize(client).get_data(as_text=True)
  assert "admin@example.com" in html and "guest@example.com" in html


def test_login_page_embeds_saved_users_with_groups_and_claims(client, users_file):
  html = authorize(client).get_data(as_text=True)
  assert '"groups": ["admins"]' in html and '"claims": {"name": "Ada"}' in html


def test_auto_login_uses_user_from_file(client, users_file, set_config):
  set_config(AUTO_LOGIN="admin@example.com")
  response = authorize(client)
  assert response.status_code == 302
  claims = decode(client, exchange(client, code_from(response)))
  assert claims["groups"] == ["admins"] and claims["name"] == "Ada"


def test_auto_login_for_email_not_in_file_has_no_groups(client, set_config):
  set_config(AUTO_LOGIN="ci@example.com")
  claims = decode(client, exchange(client, code_from(authorize(client))))
  assert claims["email"] == "ci@example.com" and claims["groups"] == []


def test_set_user_wins_over_auto_login(client, set_config):
  set_config(AUTO_LOGIN="ci@example.com")
  client.post("/set-user", json={"email": "manual@example.com"})
  assert decode(client, exchange(client, code_from(authorize(client))))["email"] == "manual@example.com"


@pytest.mark.parametrize("content", ["not json", '{"users": "x"}', '[{"groups": []}]'])
def test_invalid_users_file_fails_fast(tmp_path, set_config, content):
  path = tmp_path / "users.json"
  path.write_text(content)
  set_config(USERS_FILE=str(path))
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


def test_missing_users_file_fails_fast(set_config):
  set_config(USERS_FILE="/does/not/exist.json")
  with pytest.raises(SystemExit):
    create_app()


def test_expired_entries_are_purged_on_next_login(client):
  stale = login(client)
  expire_code(stale)
  login(client)
  assert stale not in stored_codes()


def test_code_redeemed_concurrently_succeeds_only_once(client):
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


def test_basic_auth_credentials_are_form_urldecoded(client, set_config):
  set_config(CLIENT_SECRET="s3cr+t/%")
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
  assert peek_next_user() is None


def test_login_rejects_unknown_challenge_method(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc",
                                         "code_challenge_method": "S512"})
  assert response.status_code == 400
  assert not stored_codes()


def test_login_defaults_challenge_method_to_plain(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc"})
  assert response.status_code == 302
  assert stored_pkce() == {"challenge": "abc", "method": "plain"}


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


@pytest.mark.parametrize("field, value", [("code", [1]), ("code", {"a": 1}), ("code_verifier", 5),
                                          ("redirect_uri", ["x"]), ("grant_type", ["authorization_code"])])
def test_token_rejects_non_string_json_values(client, field, value):
  body = {"grant_type": "authorization_code", "code": "code-x", "client_id": CLIENT_ID,
          "client_secret": CLIENT_SECRET, field: value}
  response = client.post("/token", json=body)
  assert response.status_code == 400
  assert response.get_json()["error"] == "invalid_request"


def test_concurrent_logins_do_not_fail_while_purging(client):
  fill_store(10000)
  previous = sys.getswitchinterval()
  sys.setswitchinterval(1e-6)
  statuses = []

  def post_logins():
    local = create_app().test_client()
    for _ in range(40):
      statuses.append(local.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT}).status_code)

  try:
    threads = [threading.Thread(target=post_logins) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
  finally:
    sys.setswitchinterval(previous)
  assert statuses.count(302) == len(statuses) == 240


def test_token_responses_are_not_cacheable(client):
  success = exchange(client, login(client))
  failure = exchange(client, "code-nope")
  assert success.status_code == 200 and failure.status_code == 400
  for response in (success, failure):
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_login_form_without_challenge_method_completes_with_plain_pkce(client):
  """The hidden fields of the login page, posted back as a browser would, carry a challenge without a method."""
  html = authorize(client, code_challenge="plain-secret").get_data(as_text=True)
  fields = dict(re.findall(r'<input type="hidden" name="(\w+)" value="([^"]*)"', html))
  assert "code_challenge_method" not in fields
  response = client.post("/login", data={**fields, "email": "a@b.c"})
  assert response.status_code == 302
  data = {"grant_type": "authorization_code", "code": code_from(response), "client_id": CLIENT_ID,
          "code_verifier": "plain-secret"}
  assert client.post("/token", data=data).status_code == 200


def test_login_rejects_empty_challenge_method(client):
  response = client.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT, "code_challenge": "abc",
                                         "code_challenge_method": ""})
  assert response.status_code == 400


@pytest.mark.parametrize("secret", ["é", "wrong-é"])
def test_non_ascii_client_secret_is_a_mismatch_not_an_error(client, secret):
  assert exchange(client, login(client), client_secret=secret).status_code == 401


def test_malformed_basic_auth_header_is_rejected(client):
  response = client.post("/token", data={"code": login(client)}, headers={"Authorization": "Basic !!!not-base64"})
  assert response.status_code == 401
