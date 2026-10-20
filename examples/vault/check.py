"""Configures a dev Vault to use the mock IdP and performs real OIDC logins through it.

Runs inside docker compose (see run.sh). Only talks to Vault's HTTP API.
"""
import os
import sys
import time
from urllib.parse import urlparse, parse_qs

import requests

VAULT = os.environ["VAULT_ADDR"]
IDP = os.environ["IDP_URL"]
HEADERS = {"X-Vault-Token": os.environ["VAULT_TOKEN"]}
CLIENT_ID = os.getenv("MOCK_IDP_CLIENT_ID", "mock-idp-client")
CLIENT_SECRET = os.getenv("MOCK_IDP_CLIENT_SECRET", "mock-idp-secret")
REDIRECT = "http://localhost:8250/oidc/callback"
GROUPS = {
  "admins@example.com": ["admin-policy", "engineer-policy"],
  "devs@example.com": ["engineer-policy"],
}


def vault(method, path, **kwargs):
  response = requests.request(method, f"{VAULT}/v1/{path}", headers=HEADERS, **kwargs)
  response.raise_for_status()
  return response.json() if response.content else {}


def configure_vault():
  vault("POST", "sys/auth/oidc", json={"type": "oidc"})
  vault("POST", "auth/oidc/config", json={
    "oidc_discovery_url": IDP, "oidc_client_id": CLIENT_ID, "oidc_client_secret": CLIENT_SECRET,
    "default_role": "identities",
  })
  vault("POST", "auth/oidc/role/identities", json={
    "role_type": "oidc", "user_claim": "email", "groups_claim": "groups", "oidc_scopes": ["openid", "email"],
    "bound_audiences": [CLIENT_ID], "allowed_redirect_uris": [REDIRECT],
    "bound_claims": {"groups": list(GROUPS)},
  })
  accessor = vault("GET", "sys/auth")["data"]["oidc/"]["accessor"]
  for policy in {p for policies in GROUPS.values() for p in policies}:
    vault("PUT", f"sys/policies/acl/{policy}", json={"policy": 'path "secret/*" { capabilities = ["read"] }'})
  for name, policies in GROUPS.items():
    group = {"name": name, "type": "external", "policies": policies}
    group_id = vault("POST", "identity/group", json=group)["data"]["id"]
    vault("POST", "identity/group-alias", json={"name": name, "mount_accessor": accessor, "canonical_id": group_id})


def login(email, groups):
  """Same flow as `vault login -method=oidc`; /set-user stands in for the person at the browser."""
  nonce = f"nonce-{time.time_ns()}"
  auth_url = requests.post(f"{VAULT}/v1/auth/oidc/oidc/auth_url",
                           json={"role": "identities", "redirect_uri": REDIRECT, "client_nonce": nonce})
  auth_url.raise_for_status()

  requests.post(f"{IDP}/set-user", json={"email": email, "groups": groups}).raise_for_status()
  # The URL Vault returns points at the IdP's public address (for a browser); reach it via the compose network.
  authorize = urlparse(auth_url.json()["data"]["auth_url"])
  path_and_query = authorize._replace(scheme="", netloc="").geturl()
  redirect = requests.get(f"{IDP}{path_and_query}", allow_redirects=False)
  assert redirect.status_code == 302, redirect.text
  query = parse_qs(urlparse(redirect.headers["Location"]).query)

  return requests.get(f"{VAULT}/v1/auth/oidc/oidc/callback",
                      params={"state": query["state"][0], "code": query["code"][0], "client_nonce": nonce})


def check(description, condition):
  print(f"{'ok  ' if condition else 'FAIL'} {description}")
  if not condition:
    check.failed = True
check.failed = False


def main():
  for _ in range(30):
    try:
      requests.get(f"{VAULT}/v1/sys/health").raise_for_status()
      break
    except requests.RequestException:
      time.sleep(1)
  else:
    raise SystemExit(f"Vault not ready at {VAULT} after 30 attempts")

  configure_vault()

  admin = login("alice@example.com", ["admins@example.com"])
  check("admin group logs in with both policies",
        admin.ok and set(admin.json()["auth"]["identity_policies"]) == {"admin-policy", "engineer-policy"})

  dev = login("bob@example.com", ["devs@example.com"])
  check("dev group logs in with engineer-policy only",
        dev.ok and dev.json()["auth"]["identity_policies"] == ["engineer-policy"])

  unmapped = login("carol@example.com", ["unknown@example.com"])
  check("unmapped group is rejected", unmapped.status_code == 400 and "bound claim" in unmapped.text)

  nogroups = login("erin@example.com", [])
  check("missing groups claim is rejected", nogroups.status_code == 400)

  sys.exit(1 if check.failed else 0)


if __name__ == "__main__":
  main()
