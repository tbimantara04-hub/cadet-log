import asyncio
import time

import pytest
import httpx

from .crypto_helpers import (
    build_secure_payload,
    fetch_server_public_key,
    post_secure_payload,
)


async def submit_payload(client: httpx.AsyncClient, server_public_key_bytes: bytes, index: int) -> httpx.Response:
    payload = {
        "guard_id": f"LOAD-{index:03}",
        "student_name": f"Load Test {index}",
        "destination": "Gate B",
        "estimated_return": "2026-12-31 23:59",
    }
    secure_payload = build_secure_payload(server_public_key_bytes, payload)
    return await post_secure_payload(client, secure_payload)


@pytest.mark.asyncio
@pytest.mark.parametrize("user_count", [50, 100])
async def test_bulk_entry_concurrency(user_count: int):
    async with httpx.AsyncClient() as client:
        server_public_key_bytes = await fetch_server_public_key(client)

        start = time.perf_counter()
        tasks = [submit_payload(client, server_public_key_bytes, index) for index in range(user_count)]
        responses = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start

        statuses = [r.status_code for r in responses]
        assert all(code in (200, 201) for code in statuses), f"Load test had failures: {statuses}"

        latencies = [r.elapsed.total_seconds() for r in responses]
        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)

        print(f"Bulk entry for {user_count} simulated users completed in {elapsed:.2f}s")
        print(f"Avg HTTP latency: {avg_latency:.3f}s, max: {max_latency:.3f}s")
        assert avg_latency < 5.0, "Average latency is too high for the expected backend load"
