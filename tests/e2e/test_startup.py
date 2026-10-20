import socket
import subprocess
import sys
import time

import requests


def free_port():
  with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    return sock.getsockname()[1]


def test_bad_users_file_fails_before_any_key_is_created(tmp_path):
  result = subprocess.run(
    [sys.executable, "-m", "mock_idp"],
    capture_output=True,
    text=True,
    env={
      "PATH": "/usr/bin:/bin",
      "MOCK_IDP_USERS_FILE": str(tmp_path / "missing.json"),
      "MOCK_IDP_KEY_DIR": str(tmp_path / "keys"),
    },
  )
  assert result.returncode != 0
  assert "cannot read users file" in result.stderr
  assert "ready to be used" not in result.stdout
  assert not (tmp_path / "keys").exists()


def test_start_up_generates_the_keys_and_serves(tmp_path):
  port, keys = free_port(), tmp_path / "keys"
  server = subprocess.Popen(
    [sys.executable, "-m", "mock_idp"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    env={"PATH": "/usr/bin:/bin", "MOCK_IDP_PORT": str(port), "MOCK_IDP_KEY_DIR": str(keys)},
  )
  try:
    for _ in range(50):
      try:
        if requests.get(f"http://127.0.0.1:{port}/healthz").ok:
          break
      except requests.ConnectionError:
        time.sleep(0.2)
    else:
      raise AssertionError("server did not start")
    assert requests.get(f"http://127.0.0.1:{port}/jwks").json()["keys"]
    assert (keys / "private.pem").exists() and (keys / "jwks.json").exists()
  finally:
    server.terminate()
    server.wait(timeout=10)
