from helpers import ISSUER


def test_discovery_document(client):
  doc = client.get("/.well-known/openid-configuration").get_json()
  assert doc["issuer"] == ISSUER
  assert doc["token_endpoint"] == f"{ISSUER}/token"
  assert doc["jwks_uri"] == f"{ISSUER}/jwks"
  assert doc["authorization_endpoint"].endswith("/authorize")


def test_healthz(client):
  assert client.get("/healthz").get_json() == {"status": "ok"}


def test_discovery_advertises_userinfo_and_pkce(client):
  doc = client.get("/.well-known/openid-configuration").get_json()
  assert doc["userinfo_endpoint"] == f"{ISSUER}/userinfo"
  assert "S256" in doc["code_challenge_methods_supported"]


def test_discovery_advertises_only_the_authorization_code_grant(client):
  doc = client.get("/.well-known/openid-configuration").get_json()
  assert doc["grant_types_supported"] == ["authorization_code"]
  assert doc["response_types_supported"] == ["code"]
