from flask import Flask, jsonify, request
import base64
import json
import os
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

VALID_KEY_FILE = os.path.join(BASE_DIR, "valid_private.pem")
EXPIRED_KEY_FILE = os.path.join(BASE_DIR, "expired_private.pem")
METADATA_FILE = os.path.join(BASE_DIR, "key_metadata.json")


def int_to_base64(value):
    """Convert an integer to URL-safe Base64 for JWKS."""
    value_bytes = value.to_bytes(
        (value.bit_length() + 7) // 8,
        byteorder="big"
    )

    return base64.urlsafe_b64encode(
        value_bytes
    ).rstrip(b"=").decode("utf-8")


def generate_private_key():
    """Generate a 2048-bit RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def save_private_key(private_key, filename):
    """Save an RSA private key to disk."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(filename, "wb") as file:
        file.write(pem)


def load_private_key(filename):
    """Load a saved RSA private key."""
    with open(filename, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


def create_and_save_keys():
    """Create one valid key and one expired key."""
    current_time = int(time.time())

    valid_private_key = generate_private_key()
    expired_private_key = generate_private_key()

    valid_key = {
        "private_key": valid_private_key,
        "kid": str(uuid.uuid4()),
        "expiry": current_time + 86400
    }

    expired_key = {
        "private_key": expired_private_key,
        "kid": str(uuid.uuid4()),
        "expiry": current_time - 3600
    }

    save_private_key(valid_private_key, VALID_KEY_FILE)
    save_private_key(expired_private_key, EXPIRED_KEY_FILE)

    metadata = {
        "valid_kid": valid_key["kid"],
        "valid_expiry": valid_key["expiry"],
        "expired_kid": expired_key["kid"],
        "expired_expiry": expired_key["expiry"]
    }

    with open(METADATA_FILE, "w") as file:
        json.dump(metadata, file)

    return valid_key, expired_key


def load_or_create_keys():
    """Reuse saved keys so kid values remain stable across restarts."""
    files_exist = (
        os.path.exists(VALID_KEY_FILE)
        and os.path.exists(EXPIRED_KEY_FILE)
        and os.path.exists(METADATA_FILE)
    )

    if files_exist:
        with open(METADATA_FILE, "r") as file:
            metadata = json.load(file)

        # If the valid key has expired, create a fresh pair.
        if metadata["valid_expiry"] <= int(time.time()):
            return create_and_save_keys()

        valid_key = {
            "private_key": load_private_key(VALID_KEY_FILE),
            "kid": metadata["valid_kid"],
            "expiry": metadata["valid_expiry"]
        }

        expired_key = {
            "private_key": load_private_key(EXPIRED_KEY_FILE),
            "kid": metadata["expired_kid"],
            "expiry": metadata["expired_expiry"]
        }

        return valid_key, expired_key

    return create_and_save_keys()


valid_key, expired_key = load_or_create_keys()


@app.route("/")
def home():
    return "JWKS server is working!"


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    keys = []

    if valid_key["expiry"] > int(time.time()):
        public_key = valid_key["private_key"].public_key()
        numbers = public_key.public_numbers()

        jwk = {
            "kty": "RSA",
            "kid": valid_key["kid"],
            "use": "sig",
            "alg": "RS256",
            "n": int_to_base64(numbers.n),
            "e": int_to_base64(numbers.e)
        }

        keys.append(jwk)

    return jsonify({"keys": keys})


@app.route("/auth", methods=["POST"])
def auth():
    current_time = int(time.time())

    if request.args.get("expired") is not None:
        selected_key = expired_key

        payload = {
            "sub": "user123",
            "iat": current_time,
            "exp": current_time - 3600
        }

    else:
        selected_key = valid_key

        payload = {
            "sub": "user123",
            "iat": current_time,
            "exp": current_time + 3600
        }

    headers = {
        "kid": selected_key["kid"]
    }

    token = jwt.encode(
        payload,
        selected_key["private_key"],
        algorithm="RS256",
        headers=headers
    )

    return token, 200


if __name__ == "__main__":
    app.run(port=8080)