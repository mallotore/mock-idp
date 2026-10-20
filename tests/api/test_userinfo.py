from helpers import exchange, expire_access_tokens, login


def test_userinfo_requires_a_valid_bearer_token(client):
  assert client.get("/userinfo").status_code == 401
  assert client.get("/userinfo", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_access_token_lives_for_the_full_ttl(make_app, clock):
  client = make_app(token_ttl_seconds=1).test_client()
  clock.value = 1000.9
  access_token = exchange(client, login(client)).get_json()["access_token"]
  auth = {"Authorization": f"Bearer {access_token}"}
  clock.value = 1001.8
  assert client.get("/userinfo", headers=auth).status_code == 200
  clock.value = 1001.95
  assert client.get("/userinfo", headers=auth).status_code == 401


def test_userinfo_rejects_expired_token(client, clock):
  access_token = exchange(client, login(client)).get_json()["access_token"]
  expire_access_tokens(clock)
  assert client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"}).status_code == 401


def test_the_bearer_scheme_is_case_insensitive(client):
  access_token = exchange(client, login(client)).get_json()["access_token"]
  assert client.get("/userinfo", headers={"Authorization": f"bearer {access_token}"}).status_code == 200
