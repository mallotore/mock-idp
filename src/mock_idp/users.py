import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .settings import Settings


class UsersFileError(Exception):
  """The users file is unreadable or malformed."""


# Claims a user can never override through `claims` or the users file.
RESERVED_CLAIMS = {"iss", "aud", "exp", "iat", "nonce"}


@dataclass
class User:
  email: str
  groups: list[str] = field(default_factory=list)
  claims: dict[str, Any] = field(default_factory=dict)


def parse_groups(raw: Any) -> list[str]:
  if isinstance(raw, list):
    return [str(g).strip() for g in raw if str(g).strip()]
  return [g.strip() for g in str(raw or "").split(",") if g.strip()]


def build_user(email: str, groups: Any = None, claims: Mapping[str, Any] | None = None) -> User:
  extra = {k: v for k, v in (claims or {}).items() if k not in RESERVED_CLAIMS}
  return User(email, parse_groups(groups), extra)


def identity_claims(user: User) -> dict[str, Any]:
  """Claims describing the user, shared by the ID token and /userinfo."""
  return {"sub": user.email, "email": user.email, "groups": user.groups, **user.claims}


def load_users(settings: Settings) -> list[User]:
  """Reads the users file on every call so it can be edited without restarting."""
  if not settings.users_file:
    return []
  try:
    raw = json.loads(Path(settings.users_file).read_text())
  except (OSError, ValueError) as e:
    raise UsersFileError(f"cannot read users file {settings.users_file}: {e}") from None
  entries = raw.get("users") if isinstance(raw, dict) else raw
  if not isinstance(entries, list):
    raise UsersFileError(f'{settings.users_file} must be a list of users or {{"users": [...]}}')
  users = []
  for entry in entries:
    if not isinstance(entry, dict) or not entry.get("email"):
      raise UsersFileError(f"every user in {settings.users_file} needs an 'email'")
    extra = {k: v for k, v in entry.items() if k not in ("email", "groups")}
    users.append(build_user(entry["email"], entry.get("groups"), extra))
  return users


def auto_login_user(settings: Settings) -> User | None:
  if not settings.auto_login:
    return None
  return next((u for u in load_users(settings) if u.email == settings.auto_login), build_user(settings.auto_login))
