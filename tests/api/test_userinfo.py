from helpers import exchange, expire_access_token, login, set_clock


def test_userinfo_requires_a_valid_bearer_token(client):
  assert client.get("/userinfo").status_code == 401
  assert client.get("/userinfo", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_access_token_lives_for_the_full_ttl(make_app, monkeypatch):
  client = make_app(token_ttl_seconds=1).test_client()
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
