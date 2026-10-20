import pytest

from mock_idp.__main__ import main


def test_invalid_setting_stops_start_up_with_a_message_naming_it(tmp_path):
  with pytest.raises(SystemExit) as error:
    main({"MOCK_IDP_PORT": "abc", "MOCK_IDP_KEY_DIR": str(tmp_path / "keys")})
  assert str(error.value) == "mock-idp: invalid configuration: MOCK_IDP_PORT must be an integer, got 'abc'"


@pytest.mark.parametrize("content", ["not json", '{"users": "x"}', '[{"groups": []}]', None])
def test_invalid_users_file_stops_start_up(tmp_path, content):
  path = tmp_path / "users.json"
  if content is not None:
    path.write_text(content)
  with pytest.raises(SystemExit) as error:
    main({"MOCK_IDP_USERS_FILE": str(path), "MOCK_IDP_KEY_DIR": str(tmp_path / "keys")})
  assert "invalid configuration" in str(error.value)
