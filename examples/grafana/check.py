import os
import sys

import requests

GRAFANA = os.environ["GRAFANA_URL"]
IDP = os.environ["IDP_URL"]
TIMEOUT = 30


def login_through_grafana(email, groups):
  requests.post(f"{IDP}/set-user", json={"email": email, "groups": groups}, timeout=TIMEOUT).raise_for_status()
  session = requests.Session()
  session.get(f"{GRAFANA}/login/generic_oauth", timeout=TIMEOUT).raise_for_status()
  return session


def api(session, path):
  response = session.get(f"{GRAFANA}/api/{path}", timeout=TIMEOUT)
  return response.json() if response.status_code == 200 else None


def role(session):
  orgs = api(session, "user/orgs")
  return orgs[0]["role"] if orgs else None


def check(description, condition):
  print(f"{'ok  ' if condition else 'FAIL'} {description}")
  if not condition:
    check.failed = True


check.failed = False


def main():
  admin = login_through_grafana("alice@example.com", ["admins@example.com"])
  user = api(admin, "user")
  check("admin logs in with the email from the token", user is not None and user.get("email") == "alice@example.com")
  check("admin group gets the Admin role", role(admin) == "Admin")

  dev = login_through_grafana("bob@example.com", ["devs@example.com"])
  check("other allowed groups get the Viewer role", role(dev) == "Viewer")

  stranger = login_through_grafana("carol@example.com", ["strangers@example.com"])
  check("a group outside allowed_groups cannot log in", api(stranger, "user") is None)

  sys.exit(1 if check.failed else 0)


if __name__ == "__main__":
  main()
