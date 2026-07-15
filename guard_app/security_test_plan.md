# Guard App Security Test Plan

## Overview
This test plan targets the hybrid cryptography flow for the Guard App backend:
- ECDH key exchange integrity using ECC P-256.
- Ascon-128 AEAD tag validation for ciphertext tampering.
- Concurrency/load behavior for asynchronous FastAPI backend under 50–100 user submissions.

## Available Test Modules
- `backend/tests/crypto_helpers.py` — reusable cryptographic helpers and payload builder.
- `backend/tests/test_crypto_security.py` — functional tests for ECDH negotiation and tamper detection.
- `backend/tests/test_load.py` — concurrency tests that simulate bulk user entry.

## Test Vectors
1. ECDH Shared Secret Integrity
   - Request `/api/public-key`
   - Generate an ephemeral ECC P-256 client key pair
   - Derive a 16-byte KEK with HKDF-SHA256 and `info = b"GuardApp Ascon KEK"`
   - Wrap a session key and send encrypted payload
   - Confirm server accepts valid data

2. Ascon-128 AEAD Tag Validation
   - Create a valid encrypted payload
   - Flip a single bit in:
     - `ciphertext_data`
     - `wrapped_ascon_key`
   - Confirm the backend rejects tampered payloads with a `4xx` error instead of accepting them

3. Concurrency / Load Testing
   - Simulate 50 and 100 concurrent secure submissions
   - Track response success rate and latency
   - Validate no user request is incorrectly rejected when valid

## How to Run the Tests
### 1. Start the backend server
If you have a FastAPI app source, start it in the VS Code terminal with:
```powershell
cd "d:\SEMESTER 6\uas2\guard_app"
& "C:/Users/garra/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```
If `uvicorn` is not installed:
```powershell
& "C:/Users/garra/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pip install uvicorn[standard]
```

### 2. Run the security and load tests
```powershell
cd "d:\SEMESTER 6\uas2\guard_app"
& "C:/Users/garra/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pytest backend/tests -q
```

### 3. Override server settings
Set environment variables if the backend is running on a different host or path:
```powershell
$env:GUARD_APP_SERVER_URL = "http://127.0.0.1:8000"
$env:GUARD_APP_PUBLIC_KEY_ENDPOINT = "/api/public-key"
$env:GUARD_APP_LOGS_ENDPOINT = "/api/logs"
```

## Result Matrix Templates
### Security Result Matrix
| Test ID | Test Name | Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| 1 | ECDH key exchange | Validate server public key and shared-secret derivation | Valid EC point, 200 OK | | |
| 2 | Valid payload acceptance | Valid encrypted log submission should succeed | 200/201 OK | | |
| 3 | Ciphertext tamper rejection | Flip ciphertext bit, expect rejection | 4xx | | |
| 4 | Wrapped key tamper rejection | Flip wrapped key bit, expect rejection | 4xx | | |

### Load Benchmark Matrix
| Users | Requests | Successes | Failures | Avg latency (s) | Max latency (s) | Notes |
|---|---|---|---|---|---|---|
| 50 | 50 | | | | | |
| 100 | 100 | | | | | |

### Confusion Matrix for Tamper Detection
| Actual / Predicted | Accept | Reject |
|---|---|---|---|
| Valid payload | TP | FN |
| Tampered payload | FP | TN |

## Notes
- The backend test code is intentionally written to use base64-encoded ECC points and Ascon-128 AEAD payloads.
- If the app uses a different JSON schema, adjust the helper constants in `backend/tests/crypto_helpers.py`.
- These tests are designed for integration-level validation: they assume the FastAPI backend is running and reachable at `127.0.0.1:8000`.
