#!/usr/bin/env python3
import json, base64, os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import config

def b64url_uint(i: int) -> str:
  return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")

def create_keys():
  if not config.PRIVATE_KEY_PATH.exists():
    print("Creating new private key (RSA 2048)")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
      serialization.Encoding.PEM,
      serialization.PrivateFormat.TraditionalOpenSSL,
      serialization.NoEncryption(),
    )
    # Owner-only, written to a temp file and renamed so a crash never leaves a truncated key.
    tmp = config.PRIVATE_KEY_PATH.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
      f.write(pem)
    os.replace(tmp, config.PRIVATE_KEY_PATH)
  else:
    print("RSA keys already exists")

def create_jwks_json():
  with open(config.PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
  public_numbers = private_key.public_key().public_numbers()

  jwks = {
    "keys": [{
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": config.KEY_ID,
      "n": b64url_uint(public_numbers.n),
      "e": b64url_uint(public_numbers.e),
    }]
  }

  with open(config.JWKS_PATH, "w") as f:
    json.dump(jwks, f, indent=2)
  print(f"JWKS created in {config.JWKS_PATH}")

def main():
  config.KEY_DIR.mkdir(parents=True, exist_ok=True)
  create_keys()
  create_jwks_json()
  print("Mock IDP server is ready to be used")

if __name__ == "__main__":
  main()
