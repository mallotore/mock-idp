import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

from .pkce import Pkce
from .settings import Settings
from .users import User


class Expiring(Protocol):
  expires_at: float


T = TypeVar("T", bound=Expiring)


@dataclass
class AuthCode:
  user: User
  nonce: str | None
  redirect_uri: str
  pkce: Pkce | None
  expires_at: float


@dataclass
class AccessToken:
  user: User
  expires_at: float


class ExpiringStore(Generic[T]):
  def __init__(self, now: Callable[[], float]):
    self._now = now
    self._items: dict[str, T] = {}
    self._lock = threading.Lock()

  def _live(self, item: T | None) -> T | None:
    return item if item and item.expires_at >= self._now() else None

  def put(self, key: str, item: T) -> None:
    with self._lock:
      self._items[key] = item

  def get(self, key: str | None) -> T | None:
    if key is None:
      return None
    with self._lock:
      item = self._items.get(key)
    return self._live(item)

  def get_even_if_expired(self, key: str | None) -> T | None:
    if key is None:
      return None
    with self._lock:
      return self._items.get(key)

  def take(self, key: str | None) -> T | None:
    if key is None:
      return None
    with self._lock:
      item = self._items.pop(key, None)
    return self._live(item)

  def purge(self) -> None:
    with self._lock:
      now = self._now()
      for key in [k for k, item in self._items.items() if item.expires_at < now]:
        del self._items[key]

  def snapshot(self) -> dict[str, T]:
    with self._lock:
      return dict(self._items)


class NextUser:
  def __init__(self) -> None:
    self._user: User | None = None
    self._lock = threading.Lock()

  def set(self, user: User) -> None:
    with self._lock:
      self._user = user

  def take(self) -> User | None:
    with self._lock:
      user, self._user = self._user, None
    return user

  def peek(self) -> User | None:
    with self._lock:
      return self._user


class State:
  def __init__(self, settings: Settings, now: Callable[[], float]):
    self.settings = settings
    self.now = now
    self.codes: ExpiringStore[AuthCode] = ExpiringStore(now)
    self.tokens: ExpiringStore[AccessToken] = ExpiringStore(now)
    self.next_user = NextUser()

  def issue_code(self, user: User, nonce: str | None, redirect_uri: str, pkce: Pkce | None) -> str:
    self.codes.purge()
    self.tokens.purge()
    code = f"code-{uuid.uuid4().hex}"
    self.codes.put(code, AuthCode(user, nonce, redirect_uri, pkce, self.now() + self.settings.code_ttl_seconds))
    return code
