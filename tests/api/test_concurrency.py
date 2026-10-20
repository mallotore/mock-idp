import sys, threading

from helpers import REDIRECT, exchange, expire_code, fill_store, login, stored_codes


def test_expired_entries_are_purged_on_next_login(client):
  stale = login(client)
  expire_code(stale)
  login(client)
  assert stale not in stored_codes()


def test_code_redeemed_concurrently_succeeds_only_once(client, make_app):
  code = login(client)
  barrier = threading.Barrier(8)
  statuses = []

  def redeem():
    local = make_app().test_client()
    barrier.wait()
    statuses.append(exchange(local, code).status_code)

  threads = [threading.Thread(target=redeem) for _ in range(8)]
  [t.start() for t in threads]
  [t.join() for t in threads]
  assert sorted(statuses) == [200] + [400] * 7


def test_concurrent_logins_do_not_fail_while_purging(make_app):
  fill_store(10000)
  previous = sys.getswitchinterval()
  sys.setswitchinterval(1e-6)
  statuses = []

  def post_logins():
    local = make_app().test_client()
    for _ in range(40):
      statuses.append(local.post("/login", data={"email": "a@b.c", "redirect_uri": REDIRECT}).status_code)

  try:
    threads = [threading.Thread(target=post_logins) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
  finally:
    sys.setswitchinterval(previous)
  assert statuses.count(302) == len(statuses) == 240
