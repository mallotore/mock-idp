import sys
import threading

from helpers import REDIRECT, authorize, exchange, expire_codes, fill_store, login, stored_codes


def test_expired_entries_are_purged_on_next_login(client, clock):
  stale = login(client)
  expire_codes(clock)
  login(client)
  assert stale not in stored_codes(client)


def test_code_redeemed_concurrently_succeeds_only_once(app, client):
  code = login(client)
  barrier = threading.Barrier(8)
  statuses = []

  def redeem():
    local = app.test_client()
    barrier.wait()
    statuses.append(exchange(local, code).status_code)

  threads = [threading.Thread(target=redeem) for _ in range(8)]
  [t.start() for t in threads]
  [t.join() for t in threads]
  assert sorted(statuses) == [200] + [400] * 7


def test_concurrent_logins_do_not_fail_while_purging(app):
  fill_store(app, 10000)
  previous = sys.getswitchinterval()
  sys.setswitchinterval(1e-6)
  statuses = []

  def post_logins():
    local = app.test_client()
    for _ in range(40):
      statuses.append(local.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT}).status_code)

  try:
    threads = [threading.Thread(target=post_logins) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
  finally:
    sys.setswitchinterval(previous)
  assert statuses.count(302) == len(statuses) == 240


def test_seeded_identities_are_each_consumed_at_most_once(app):
  """Several /authorize calls race for one /set-user identity: exactly one of them gets it."""
  for round_number in range(20):
    email = f"user{round_number}@example.com"
    app.test_client().post("/set-user", json={"email": email})
    barrier, responses = threading.Barrier(6), []

    def authorize_now():
      local = app.test_client()
      barrier.wait()
      responses.append(authorize(local))

    threads = [threading.Thread(target=authorize_now) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(r.status_code for r in responses) == [200] * 5 + [302]
