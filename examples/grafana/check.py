import os
import sys

import requests

GRAFANA = os.environ["GRAFANA_URL"]
IDP = os.environ["IDP_URL"]


def login_through_grafana(email, groups):
  requests.post(f"{IDP}/set-user", json={"email": email, "groups": groups}).raise_for_status()
  session = requests.Session()
  session.get(f"{GRAFANA}/login/generic_oauth").raise_for_status()
  return session


def check(description, condition):
  print(f"{'ok  ' if condition else 'FAIL'} {description}")
  if not condition:
    check.failed = True


check.failed = False


def main():
  admin = login_through_grafana("alice@example.com", ["admins@example.com"])
  user = admin.get(f"{GRAFANA}/api/user").json()
  check("admin logs in with the email from the token", user.get("email") == "alice@example.com")
  check("admin group gets the Admin role", admin.get(f"{GRAFANA}/api/user/orgs").json()[0]["role"] == "Admin")

  dev = login_through_grafana("bob@example.com", ["devs@example.com"])
  check("other groups get the Viewer role", dev.get(f"{GRAFANA}/api/user/orgs").json()[0]["role"] == "Viewer")

  sys.exit(1 if check.failed else 0)


if __name__ == "__main__":
  main()
