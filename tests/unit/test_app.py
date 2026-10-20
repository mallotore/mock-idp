from dataclasses import replace

from mock_idp.app import create_app


def test_create_app_does_not_touch_the_file_system(base_settings, tmp_path):
  settings = replace(base_settings, key_dir=tmp_path / "keys", users_file=str(tmp_path / "missing.json"))
  create_app(settings)
  assert not (tmp_path / "keys").exists()
