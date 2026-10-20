import json

import pytest

from mock_idp.users import (UsersFileError, User, auto_login_user, build_user, identity_claims, load_users,
                            parse_groups)


@pytest.mark.parametrize("raw, expected", [
  (["a", " b ", ""], ["a", "b"]),
  ("a, b ,, c", ["a", "b", "c"]),
  (None, []),
  (5, ["5"]),
  ("", []),
])
def test_parse_groups(raw, expected):
  assert parse_groups(raw) == expected


def test_build_user_drops_reserved_claims():
  user = build_user("a@b.c", "x", {"iss": "evil", "aud": "x", "exp": 1, "iat": 1, "nonce": "n", "name": "A"})
  assert user == User("a@b.c", ["x"], {"name": "A"})


def test_identity_claims_allow_overriding_sub():
  user = build_user("a@b.c", ["g"], {"sub": "user-1", "name": "A"})
  assert identity_claims(user) == {"sub": "user-1", "email": "a@b.c", "groups": ["g"], "name": "A"}


@pytest.fixture
def write_users(tmp_path, set_config):
  def write(content):
    path = tmp_path / "users.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    set_config(USERS_FILE=str(path))
  return write


def test_no_users_file_means_no_users(set_config):
  set_config(USERS_FILE=None)
  assert load_users() == []


@pytest.mark.parametrize("wrap", [lambda users: users, lambda users: {"users": users}])
def test_load_users_from_a_list_or_an_object(write_users, wrap):
  write_users(wrap([{"email": "a@b.c", "groups": ["g"], "name": "A"}]))
  assert load_users() == [User("a@b.c", ["g"], {"name": "A"})]


@pytest.mark.parametrize("content", [
  [{"groups": ["g"]}],
  [{"email": ""}],
  {"users": "x"},
  '"just a string"',
  ["not an object"],
  "{ broken",
])
def test_invalid_users_files_are_rejected(write_users, content):
  write_users(content)
  with pytest.raises(UsersFileError):
    load_users()


def test_unreadable_users_file_is_rejected(set_config):
  set_config(USERS_FILE="/does/not/exist.json")
  with pytest.raises(UsersFileError, match="cannot read users file"):
    load_users()


def test_auto_login_user_from_the_file(write_users, set_config):
  write_users([{"email": "admin@example.com", "groups": ["admins"]}])
  set_config(AUTO_LOGIN="admin@example.com")
  assert auto_login_user() == User("admin@example.com", ["admins"], {})


def test_auto_login_user_falls_back_to_a_bare_user(write_users, set_config):
  write_users([{"email": "admin@example.com"}])
  set_config(AUTO_LOGIN="ci@example.com")
  assert auto_login_user() == User("ci@example.com", [], {})


def test_no_auto_login_configured(set_config):
  set_config(AUTO_LOGIN=None)
  assert auto_login_user() is None
