import threading
from dataclasses import dataclass

import pytest

from mock_idp.settings import Settings
from mock_idp.stores import ExpiringStore, NextUser, State
from mock_idp.users import User


@dataclass
class Item:
  expires_at: float


@pytest.fixture
def store(clock):
  return ExpiringStore(clock.now)


def test_take_is_single_use(store, clock):
  item = Item(clock.now() + 10)
  store.put("k", item)
  assert store.take("k") is item
  assert store.take("k") is None


def test_expired_entries_are_not_returned(store, clock):
  store.put("k", Item(clock.now() + 10))
  clock.advance(11)
  assert store.get("k") is None
  assert store.take("k") is None


def test_an_entry_is_valid_until_its_expiry_time(store, clock):
  store.put("k", Item(clock.now() + 10))
  clock.advance(10)
  assert store.get("k") is not None
  assert store.take("k") is not None


def test_get_even_if_expired_also_returns_expired_entries(store, clock):
  item = Item(clock.now() - 1)
  store.put("k", item)
  assert store.get_even_if_expired("k") is item and store.get("k") is None


def test_purge_removes_only_expired_entries(store, clock):
  store.put("old", Item(clock.now() - 1))
  store.put("new", Item(clock.now() + 10))
  store.purge()
  assert list(store.snapshot()) == ["new"]


def test_next_user_is_consumed_once():
  slot = NextUser()
  user = User("a@b.c")
  slot.set(user)
  assert slot.peek() is user
  assert slot.take() is user
  assert slot.take() is None


def test_of_many_threads_taking_one_entry_only_one_gets_it(store, clock):
  store.put("k", Item(clock.now() + 10))
  barrier, winners = threading.Barrier(16), []

  def grab():
    barrier.wait()
    if store.take("k"):
      winners.append(1)

  threads = [threading.Thread(target=grab) for _ in range(16)]
  [t.start() for t in threads]
  [t.join() for t in threads]
  assert len(winners) == 1


def test_puts_and_purges_from_many_threads_do_not_fail(store, clock):
  errors = []

  def work(n):
    try:
      for i in range(2000):
        store.put(f"{n}-{i}", Item(clock.now() + (10 if i % 2 else -1)))
        store.purge()
        store.snapshot()
    except Exception as e:  # noqa: BLE001
      errors.append(e)

  threads = [threading.Thread(target=work, args=(n,)) for n in range(6)]
  [t.start() for t in threads]
  [t.join() for t in threads]
  assert not errors


def test_issue_code_stores_the_code_with_its_ttl_and_purges_expired_ones(clock):
  state = State(Settings(code_ttl_seconds=60), clock.now)
  stale = state.issue_code(User("a@b.c"), None, "http://x/cb", None)
  clock.advance(61)
  code = state.issue_code(User("a@b.c"), "n", "http://x/cb", None)
  assert code.startswith("code-")
  assert list(state.codes.snapshot()) == [code]
  assert stale not in state.codes.snapshot()
  assert state.codes.get(code).expires_at == clock.now() + 60


def test_a_missing_key_is_never_found(store):
  assert store.get(None) is None and store.get_even_if_expired(None) is None and store.take(None) is None
