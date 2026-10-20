import time, uuid
from dataclasses import dataclass
from .pkce import Pkce
from .users import User

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

codes: dict[str, AuthCode] = {}
tokens: dict[str, AccessToken] = {}
# Identity used by the next /authorize call, set through POST /set-user (consumed once).
next_user: User | None = None

def set_next_user(user: User) -> None:
  global next_user
  next_user = user

def take_next_user() -> User | None:
  global next_user
  user, next_user = next_user, None
  return user

def purge_expired() -> None:
  now = time.time()
  for registry in (codes, tokens):
    # Snapshot first: other request threads may insert while this one iterates.
    for key, value in list(registry.items()):
      if value.expires_at < now:
        registry.pop(key, None)

def issue_code(user: User, nonce: str | None, redirect_uri: str, pkce: Pkce | None, ttl: int) -> str:
  purge_expired()
  code = f"code-{uuid.uuid4().hex}"
  codes[code] = AuthCode(user, nonce, redirect_uri, pkce, time.time() + ttl)
  return code
