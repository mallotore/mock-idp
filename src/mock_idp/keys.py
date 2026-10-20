import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .settings import Settings

KEY_ID = "mock-key-1"


class KeysError(Exception):
  pass


def b64url_uint(i: int) -> str:
  return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")


def write_private_key_atomically(path: Path, pem: bytes) -> None:
  tmp = path.with_suffix(".tmp")
  fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
  with os.fdopen(fd, "wb") as f:
    f.write(pem)
  os.replace(tmp, path)


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


def create_jwks_json(settings: Settings) -> None:
  with open(settings.private_key_path, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
  if not isinstance(private_key, rsa.RSAPrivateKey):
    raise KeysError(f"{settings.private_key_path} is not an RSA private key")
  public_numbers = private_key.public_key().public_numbers()

  jwks = {
    "keys": [
      {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": KEY_ID,
        "n": b64url_uint(public_numbers.n),
        "e": b64url_uint(public_numbers.e),
      }
    ]
  }

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
