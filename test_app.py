import json
import jwt

import app as app_module
from app import app, valid_key, expired_key


def test_home():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"JWKS server is working!" in response.data


def test_jwks_endpoint():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()

    assert "keys" in data
    assert len(data["keys"]) == 1

    key = data["keys"][0]

    assert key["kid"] == valid_key["kid"]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert "n" in key
    assert "e" in key


def test_expired_key_not_in_jwks():
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]

    assert expired_key["kid"] not in kids


def test_valid_auth():
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    token = response.data.decode()

    header = jwt.get_unverified_header(token)

    assert header["kid"] == valid_key["kid"]

    payload = jwt.decode(
        token,
        options={"verify_signature": False}
    )

    assert payload["exp"] > payload["iat"]


def test_expired_auth():
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.data.decode()

    header = jwt.get_unverified_header(token)

    assert header["kid"] == expired_key["kid"]

    payload = jwt.decode(
        token,
        options={"verify_signature": False}
    )

    assert payload["exp"] < payload["iat"]


def test_auth_get_not_allowed():
    client = app.test_client()

    response = client.get("/auth")

    assert response.status_code == 405


def test_create_and_reload_keys(tmp_path, monkeypatch):
    valid_file = tmp_path / "valid_private.pem"
    expired_file = tmp_path / "expired_private.pem"
    metadata_file = tmp_path / "key_metadata.json"

    monkeypatch.setattr(
        app_module,
        "VALID_KEY_FILE",
        str(valid_file)
    )

    monkeypatch.setattr(
        app_module,
        "EXPIRED_KEY_FILE",
        str(expired_file)
    )

    monkeypatch.setattr(
        app_module,
        "METADATA_FILE",
        str(metadata_file)
    )

    valid, expired = app_module.create_and_save_keys()

    assert valid_file.exists()
    assert expired_file.exists()
    assert metadata_file.exists()

    loaded_valid, loaded_expired = app_module.load_or_create_keys()

    assert loaded_valid["kid"] == valid["kid"]
    assert loaded_expired["kid"] == expired["kid"]


def test_expired_saved_key_creates_new_keys(tmp_path, monkeypatch):
    valid_file = tmp_path / "valid_private.pem"
    expired_file = tmp_path / "expired_private.pem"
    metadata_file = tmp_path / "key_metadata.json"

    monkeypatch.setattr(
        app_module,
        "VALID_KEY_FILE",
        str(valid_file)
    )

    monkeypatch.setattr(
        app_module,
        "EXPIRED_KEY_FILE",
        str(expired_file)
    )

    monkeypatch.setattr(
        app_module,
        "METADATA_FILE",
        str(metadata_file)
    )

    app_module.create_and_save_keys()

    with open(metadata_file, "r") as file:
        metadata = json.load(file)

    old_kid = metadata["valid_kid"]

    metadata["valid_expiry"] = 0

    with open(metadata_file, "w") as file:
        json.dump(metadata, file)

    new_valid, new_expired = app_module.load_or_create_keys()

    assert new_valid["kid"] != old_kid
    assert new_valid["expiry"] > new_expired["expiry"]