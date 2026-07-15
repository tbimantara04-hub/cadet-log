import base64
import json
import os
import sqlite3
import threading

import ascon
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError

BASE_DIR = os.path.dirname(__file__)
DB_DIR = os.path.join(BASE_DIR, "db")
DB_PATH = os.path.join(DB_DIR, "guard_app.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")
ECC_PRIVATE_KEY_HEX = os.getenv("ECC_PRIVATE_KEY_HEX")
AEAD_INFO = b"GuardApp Ascon KEK"


class EncryptedPayload(BaseModel):
    client_public_key: str
    wrapped_ascon_key: str
    wrapped_ascon_key_nonce: str
    ciphertext_data: str
    ciphertext_data_nonce: str


app = FastAPI(
    title="Guard App Backend",
    description="Lightweight Hybrid Cryptography Gateway",
)


def init_db() -> None:
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()
    finally:
        conn.close()


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def load_server_private_key() -> ec.EllipticCurvePrivateKey:
    if ECC_PRIVATE_KEY_HEX:
        try:
            priv_int = int(ECC_PRIVATE_KEY_HEX, 16)
            return ec.derive_private_key(priv_int, ec.SECP256R1())
        except ValueError:
            raise RuntimeError("ECC_PRIVATE_KEY_HEX is not a valid hex integer")

    print("WARNING: No ECC_PRIVATE_KEY_HEX found in env. Generating ephemeral key for session.")
    return ec.generate_private_key(ec.SECP256R1())


server_private_key = load_server_private_key()
server_public_key = server_private_key.public_key()
DB_LOCK = threading.Lock()


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.get("/api/public-key", response_class=PlainTextResponse)
def get_public_key() -> str:
    raw_public_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return b64encode(raw_public_bytes)


@app.post("/api/logs")
async def receive_logs(request: Request) -> dict:
    try:
        raw_payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON") from exc

    if not isinstance(raw_payload, dict):
        raise HTTPException(status_code=403, detail="Encrypted payload must be a JSON object")

    try:
        payload = EncryptedPayload(**raw_payload)
    except ValidationError as exc:
        raise HTTPException(status_code=403, detail="Invalid or missing encrypted payload") from exc

    client_pub_bytes = b64decode(payload.client_public_key)
    wrapped_ascon_key = b64decode(payload.wrapped_ascon_key)
    wrapped_key_nonce = b64decode(payload.wrapped_ascon_key_nonce)
    ciphertext_data = b64decode(payload.ciphertext_data)
    data_nonce = b64decode(payload.ciphertext_data_nonce)

    try:
        client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), client_pub_bytes
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid client public key: {exc}")

    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=b"",
        info=AEAD_INFO,
    ).derive(shared_secret)

    try:
        ascon_symmetric_key = ascon.decrypt(
            kek,
            wrapped_key_nonce,
            b"",
            wrapped_ascon_key,
            variant="Ascon-128",
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to unwrap Ascon key (Decryption/Auth failed)")

    try:
        decrypted_json_bytes = ascon.decrypt(
            ascon_symmetric_key,
            data_nonce,
            b"",
            ciphertext_data,
            variant="Ascon-128",
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to decrypt data payload")

    try:
        decrypted_json = json.loads(decrypted_json_bytes.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid decrypted JSON payload: {exc}")

    guard_id = decrypted_json.get("guard_id")
    student_name = decrypted_json.get("student_name")
    destination = decrypted_json.get("destination")
    estimated_return = decrypted_json.get("estimated_return")

    if not all((guard_id, student_name, destination, estimated_return)):
        raise HTTPException(status_code=400, detail="Missing required decrypted fields")

    with DB_LOCK:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO gate_logs (guard_id, nama_mahasiswa, tujuan, estimasi_kembali) VALUES (?, ?, ?, ?)",
                (guard_id, student_name, destination, estimated_return),
            )
            conn.commit()
        finally:
            conn.close()

    return {"success": True, "inserted_count": 1}
