import base64
import json
import os
from typing import Any, Dict

import ascon
import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SERVER_URL = os.getenv("GUARD_APP_SERVER_URL", "http://127.0.0.1:8000")
PUBLIC_KEY_ENDPOINT = os.getenv("GUARD_APP_PUBLIC_KEY_ENDPOINT", "/api/public-key")
LOGS_ENDPOINT = os.getenv("GUARD_APP_LOGS_ENDPOINT", "/api/logs")
AEAD_INFO = b"GuardApp Ascon KEK"
TIMEOUT_SECONDS = 20.0


def encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def decode_b64(text: str) -> bytes:
    return base64.b64decode(text.encode("utf-8"))


def derive_kek(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=b"",
        info=AEAD_INFO,
    ).derive(shared_secret)


def parse_public_key_response(response: httpx.Response) -> bytes:
    text = response.text.strip()
    if not text:
        raise ValueError("Empty public-key response")

    try:
        payload = response.json()
    except ValueError:
        payload = text

    if isinstance(payload, str):
        return decode_b64(payload)

    if isinstance(payload, dict):
        for key in ("public_key", "key", "server_public_key", "data"):
            if key in payload:
                return decode_b64(payload[key])

    raise ValueError(f"Unsupported public-key body: {payload!r}")


def load_server_public_key(public_key_bytes: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)


def build_secure_payload(server_public_key_bytes: bytes, payload: Dict[str, Any]) -> Dict[str, str]:
    server_public_key = load_server_public_key(server_public_key_bytes)
    client_private = ec.generate_private_key(ec.SECP256R1())
    client_public_bytes = client_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    shared_secret = client_private.exchange(ec.ECDH(), server_public_key)
    kek = derive_kek(shared_secret)

    session_key = os.urandom(16)
    wrapped_nonce = os.urandom(16)
    data_nonce = os.urandom(16)

    wrapped_ascon_key = ascon.encrypt(kek, wrapped_nonce, b"", session_key, variant="Ascon-128")
    ciphertext_data = ascon.encrypt(
        session_key,
        data_nonce,
        b"",
        json.dumps(payload).encode("utf-8"),
        variant="Ascon-128",
    )

    return {
        "client_public_key": encode_b64(client_public_bytes),
        "wrapped_ascon_key": encode_b64(wrapped_ascon_key),
        "wrapped_ascon_key_nonce": encode_b64(wrapped_nonce),
        "ciphertext_data": encode_b64(ciphertext_data),
        "ciphertext_data_nonce": encode_b64(data_nonce),
    }


async def fetch_server_public_key(client: httpx.AsyncClient) -> bytes:
    response = await client.get(f"{SERVER_URL}{PUBLIC_KEY_ENDPOINT}", timeout=TIMEOUT_SECONDS)
    response.raise_for_status()
    return parse_public_key_response(response)


async def post_secure_payload(client: httpx.AsyncClient, payload: Dict[str, str]) -> httpx.Response:
    return await client.post(
        f"{SERVER_URL}{LOGS_ENDPOINT}",
        json=payload,
        timeout=TIMEOUT_SECONDS,
    )


def flip_bit(data: bytes, bit_index: int = 0) -> bytes:
    if not data:
        raise ValueError("Cannot flip a bit in empty data")
    mask = 1 << bit_index
    return bytes([data[0] ^ mask]) + data[1:]
