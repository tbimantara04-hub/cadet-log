import base64
import json

import pytest
import httpx

from .crypto_helpers import (
    SERVER_URL,
    build_secure_payload,
    decode_b64,
    fetch_server_public_key,
    flip_bit,
    post_secure_payload,
)


SAMPLE_PAYLOAD = {
    "guard_id": "SECURITY-TEST-GUARD",
    "student_name": "Alice Adversary",
    "destination": "Main Gate",
    "estimated_return": "2026-12-31 23:59",
}


@pytest.mark.asyncio
async def test_api_public_key_endpoint_returns_ecdh_point():
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{SERVER_URL}/api/public-key", timeout=20.0)
        assert response.status_code == 200
        raw_body = response.text.strip()
        assert raw_body, "Public-key endpoint returned empty body"

        try:
            key_bytes = decode_b64(raw_body)
        except Exception as exc:
            pytest.fail(f"Public key response is not valid base64: {exc}")

        assert len(key_bytes) in (65, 33), "Server public key should be an EC encoded point"
        assert key_bytes[0] in (2, 3, 4), "Expected compressed or uncompressed EC point prefix"


@pytest.mark.asyncio
async def test_ecdh_payload_round_trip_success():
    async with httpx.AsyncClient() as client:
        server_public_key_bytes = await fetch_server_public_key(client)
        secure_payload = build_secure_payload(server_public_key_bytes, SAMPLE_PAYLOAD)
        response = await post_secure_payload(client, secure_payload)

        assert response.status_code in (200, 201), f"Expected success, got {response.status_code}"

        try:
            payload = response.json()
        except ValueError:
            payload = {}

        assert any(key in payload for key in ("success", "status", "inserted_count", "detail")), (
            "Response body did not contain an expected success marker"
        )


@pytest.mark.asyncio
async def test_ascon_ciphertext_tampering_is_rejected():
    async with httpx.AsyncClient() as client:
        server_public_key_bytes = await fetch_server_public_key(client)
        secure_payload = build_secure_payload(server_public_key_bytes, SAMPLE_PAYLOAD)

        tampered_payload = secure_payload.copy()
        ciphertext_bytes = decode_b64(tampered_payload["ciphertext_data"])

        # flip one bit in the ciphertext to force AEAD authentication failure
        tampered_bytes = flip_bit(ciphertext_bytes, 0)
        tampered_payload["ciphertext_data"] = base64.b64encode(tampered_bytes).decode("utf-8")

        response = await post_secure_payload(client, tampered_payload)
        assert response.status_code >= 400, "Tampered ciphertext should not be accepted"
        assert response.status_code < 500, "Ciphertext tampering should fail with a client rejection"


@pytest.mark.asyncio
async def test_ascon_wrapped_key_tampering_is_rejected():
    async with httpx.AsyncClient() as client:
        server_public_key_bytes = await fetch_server_public_key(client)
        secure_payload = build_secure_payload(server_public_key_bytes, SAMPLE_PAYLOAD)

        tampered_payload = secure_payload.copy()
        wrapped_key_bytes = decode_b64(tampered_payload["wrapped_ascon_key"])
        tampered_payload["wrapped_ascon_key"] = base64.b64encode(flip_bit(wrapped_key_bytes, 1)).decode("utf-8")

        response = await post_secure_payload(client, tampered_payload)
        assert response.status_code >= 400, "Tampered wrapped key should not be accepted"
        assert response.status_code < 500, "Wrapped key tampering should fail with a client rejection"


@pytest.mark.asyncio
async def test_plaintext_payload_without_encryption_is_rejected():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{SERVER_URL}/api/logs",
            json={
                "guard_id": "PLAIN-TEXT-ATTACK",
                "student_name": "Mallory",
                "destination": "Side Gate",
                "estimated_return": "2026-12-31 23:59",
            },
            timeout=20.0,
        )

        assert response.status_code in (400, 403), (
            "A downgrade attack that sends plaintext without the encrypted wrapper must be rejected"
        )
