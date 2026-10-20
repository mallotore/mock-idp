import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .settings import Settings


class KeysError(Exception):
  pass


def b64url_uint(i: int) -> str:
  return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")


def thumbprint(n: str, e: str) -> str:
  members = json.dumps({"e": e, "kty": "RSA", "n": n}, separators=(",", ":"))
  return base64.urlsafe_b64encode(hashlib.sha256(members.encode()).digest()).decode().rstrip("=")


def key_id(private_key: rsa.RSAPrivateKey) -> str:
  numbers = private_key.public_key().public_numbers()
  return thumbprint(b64url_uint(numbers.n), b64url_uint(numbers.e))


def write_private_key_atomically(path: Path, pem: bytes) -> None:
  tmp = path.with_suffix(".tmp")
  fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  try:
    with os.fdopen(fd, "wb") as f:
      os.fchmod(f.fileno(), 0o600)
      f.write(pem)
    os.replace(tmp, path)
  except BaseException:
    tmp.unlink(missing_ok=True)
    raise


def create_keys(settings: Settings) -> None:
  if not settings.private_key_path.exists():
    print("Creating new private key (RSA 2048)")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
      serialization.Encoding.PEM,
      serialization.PrivateFormat.TraditionalOpenSSL,
      serialization.NoEncryption(),
    )
    write_private_key_atomically(settings.private_key_path, pem)
  else:
    print("RSA keys already exists")


def load_private_key(settings: Settings) -> rsa.RSAPrivateKey:
  private_key = serialization.load_pem_private_key(settings.private_key_path.read_bytes(), password=None)
  if not isinstance(private_key, rsa.RSAPrivateKey):
    raise KeysError(f"{settings.private_key_path} is not an RSA private key")
  return private_key


def create_jwks_json(settings: Settings) -> None:
  public_numbers = load_private_key(settings).public_key().public_numbers()
  n, e = b64url_uint(public_numbers.n), b64url_uint(public_numbers.e)
  jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": thumbprint(n, e), "n": n, "e": e}]}

  with open(settings.jwks_path, "w") as f:
    json.dump(jwks, f, indent=2)
  print(f"JWKS created in {settings.jwks_path}")


def prepare(settings: Settings) -> None:
  try:
    settings.key_dir.mkdir(parents=True, exist_ok=True)
    create_keys(settings)
    create_jwks_json(settings)
  except (OSError, ValueError) as e:
    raise KeysError(f"cannot prepare keys in MOCK_IDP_KEY_DIR {settings.key_dir}: {e}") from None
  print("Mock IDP server is ready to be used")
