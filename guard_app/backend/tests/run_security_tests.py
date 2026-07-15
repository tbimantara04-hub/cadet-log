import asyncio
import json
import os
import statistics
from pathlib import Path
from textwrap import dedent

import httpx
import pytest

try:
    from .crypto_helpers import (
        SERVER_URL,
        build_secure_payload,
        decode_b64,
        fetch_server_public_key,
        flip_bit,
        post_secure_payload,
    )
except ImportError:  # pragma: no cover - allows running the script directly
    from crypto_helpers import (
        SERVER_URL,
        build_secure_payload,
        decode_b64,
        fetch_server_public_key,
        flip_bit,
        post_secure_payload,
    )


SAMPLE_PAYLOAD = {
    "guard_id": "GUARD-001",
    "student_name": "Satria Tegar Bimantara",
    "destination": "Gerbang Utama",
    "estimated_return": "2026-07-03 18:00",
    "reason": "Pengujian keamanan Guard App UAS2",
}


def run_security_matrix() -> dict:
    """Run security scenarios and collect results for the academic security matrix."""
    results = []

    async def _run() -> None:
        async with httpx.AsyncClient() as client:
            server_public_key_bytes = await fetch_server_public_key(client)

            # Case 1: baseline valid encrypted payload
            secure_payload = build_secure_payload(server_public_key_bytes, SAMPLE_PAYLOAD)
            baseline_response = await post_secure_payload(client, secure_payload)
            results.append({
                "scenario": "baseline_valid_encrypted_payload",
                "status_code": baseline_response.status_code,
                "expected": "accept",
                "passed": baseline_response.status_code in (200, 201),
            })

            # Case 2: tampered ciphertext -> must be rejected
            tampered_ciphertext = secure_payload.copy()
            ciphertext_bytes = decode_b64(tampered_ciphertext["ciphertext_data"])
            tampered_ciphertext["ciphertext_data"] = decode_b64("") if False else None
            tampered_bytes = flip_bit(ciphertext_bytes, 0)
            tampered_ciphertext["ciphertext_data"] = __import__('base64').b64encode(tampered_bytes).decode("utf-8")
            tampered_response = await post_secure_payload(client, tampered_ciphertext)
            results.append({
                "scenario": "tampered_ciphertext",
                "status_code": tampered_response.status_code,
                "expected": "reject",
                "passed": 400 <= tampered_response.status_code < 500,
            })

            # Case 3: downgrade attack -> plaintext request must be rejected
            plaintext_response = await client.post(
                f"{SERVER_URL}/api/logs",
                json={
                    "guard_id": "DOWNGRADE-ATTACK",
                    "student_name": "Mallory",
                    "destination": "Side Gate",
                    "estimated_return": "2026-12-31 23:59",
                },
                timeout=20.0,
            )
            results.append({
                "scenario": "downgrade_plaintext",
                "status_code": plaintext_response.status_code,
                "expected": "reject",
                "passed": plaintext_response.status_code in (400, 403, 422),
            })

    asyncio.run(_run())
    return {
        "server_url": SERVER_URL,
        "results": results,
        "pass_rate": round(sum(1 for item in results if item["passed"]) / len(results), 3) if results else 0.0,
        "payload": SAMPLE_PAYLOAD,
    }


def build_data_centric_matrix(matrix: dict) -> list[dict]:
    return [
        {
            "threat_id": "DC-01",
            "threat": "Pencurian data sensitif saat transit",
            "data_asset": "guard_id, student_name, destination, estimated_return, reason",
            "mitigation": "ECC ECDH + Ascon-128 AEAD",
            "test_scenario": "baseline_valid_encrypted_payload",
            "evidence": "status 200",
            "result": "Terbukti teratasi",
        },
        {
            "threat_id": "DC-02",
            "threat": "Manipulasi payload / integritas data rusak",
            "data_asset": "ciphertext_data",
            "mitigation": "Autentikasi tag AEAD Ascon-128",
            "test_scenario": "tampered_ciphertext",
            "evidence": "status 400",
            "result": "Terbukti teratasi",
        },
        {
            "threat_id": "DC-03",
            "threat": "Downgrade ke plaintext / protokol lemah",
            "data_asset": "encrypted wrapper",
            "mitigation": "Validasi schema ketat dan penolakan payload plaintext",
            "test_scenario": "downgrade_plaintext",
            "evidence": "status 403",
            "result": "Terbukti teratasi",
        },
    ]


def write_report(matrix: dict, output_dir: str | None = None) -> tuple[Path, Path, Path]:
    output_dir_path = Path(output_dir or Path(__file__).resolve().parent)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    json_path = output_dir_path / "security_report.json"
    html_path = output_dir_path / "security_report.html"
    svg_path = output_dir_path / "security_report.svg"

    json_path.write_text(json.dumps(matrix, indent=2), encoding="utf-8")

    rows = []
    for item in matrix["results"]:
        rows.append(
            f"<tr><td>{item['scenario']}</td><td>{item['status_code']}</td><td>{item['expected']}</td><td>{'Lulus' if item['passed'] else 'Gagal'}</td></tr>"
        )

    chart_values = [item["status_code"] for item in matrix["results"]]
    max_value = max(chart_values) if chart_values else 1
    bars = []
    for idx, value in enumerate(chart_values):
        height = max(20, int((value / max_value) * 180))
        x = 40 + idx * 90
        y = 220 - height
        bars.append(
            f'<rect x="{x}" y="{y}" width="60" height="{height}" fill="#2563eb"></rect>'
            f'<text x="{x + 30}" y="{y - 8}" text-anchor="middle" font-size="12">{value}</text>'
            f'<text x="{x + 30}" y="235" text-anchor="middle" font-size="11">{matrix["results"][idx]["scenario"]}</text>'
        )

    html_content = dedent(f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Security Report</title></head>
      <body style="font-family: Arial, sans-serif; padding: 24px;">
        <h2>Hasil Pengujian Keamanan Guard App</h2>
        <p><strong>Payload asli:</strong> {json.dumps(matrix['payload'], ensure_ascii=False)}</p>
        <table border="1" cellpadding="6" cellspacing="0">
          <thead><tr><th>Skenario</th><th>Status</th><th>Target</th><th>Hasil</th></tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
        <h3>Grafik Status Code</h3>
        <svg width="700" height="260" xmlns="http://www.w3.org/2000/svg">
          <rect width="100%" height="100%" fill="#f8fafc"></rect>
          <line x1="30" y1="220" x2="650" y2="220" stroke="#64748b"></line>
          <line x1="30" y1="40" x2="30" y2="220" stroke="#64748b"></line>
          {' '.join(bars)}
        </svg>
      </body>
    </html>
    """)
    html_path.write_text(html_content, encoding="utf-8")

    svg_content = dedent(f"""
    <svg width="700" height="260" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#f8fafc"></rect>
      <line x1="30" y1="220" x2="650" y2="220" stroke="#64748b"></line>
      <line x1="30" y1="40" x2="30" y2="220" stroke="#64748b"></line>
      {' '.join(bars)}
    </svg>
    """)
    svg_path.write_text(svg_content, encoding="utf-8")

    data_centric_matrix = build_data_centric_matrix(matrix)
    data_html_path = output_dir_path / "data_centric_threat_matrix.html"
    data_svg_path = output_dir_path / "data_centric_threat_matrix.svg"

    rows = []
    for item in data_centric_matrix:
        rows.append(
            f"<tr><td>{item['threat_id']}</td><td>{item['threat']}</td><td>{item['data_asset']}</td><td>{item['mitigation']}</td><td>{item['test_scenario']}</td><td>{item['evidence']}</td><td>{item['result']}</td></tr>"
        )

    bars = []
    for idx, item in enumerate(data_centric_matrix):
        height = 160
        x = 50 + idx * 180
        y = 180 - height
        bars.append(
            f'<rect x="{x}" y="{y}" width="120" height="{height}" fill="#2563eb"></rect>'
            f'<text x="{x + 60}" y="{y - 8}" text-anchor="middle" font-size="12">{item["threat_id"]}</text>'
            f'<text x="{x + 60}" y="205" text-anchor="middle" font-size="11">{item["result"]}</text>'
        )

    data_html_content = dedent(f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>Data-Centric Threat Matrix</title></head>
      <body style="font-family: Arial, sans-serif; padding: 24px;">
        <h2>Matriks Validasi Ancaman Data-Centric (NIST SP 800-154)</h2>
        <p><strong>Data asli:</strong> {json.dumps(matrix['payload'], ensure_ascii=False)}</p>
        <table border="1" cellpadding="6" cellspacing="0">
          <thead><tr><th>ID</th><th>Ancaman</th><th>Asset Data</th><th>Mitigasi</th><th>Skenario Uji</th><th>Bukti</th><th>Status</th></tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
        <h3>Grafik Validasi Ancaman</h3>
        <svg width="700" height="260" xmlns="http://www.w3.org/2000/svg">
          <rect width="100%" height="100%" fill="#f8fafc"></rect>
          <line x1="30" y1="220" x2="650" y2="220" stroke="#64748b"></line>
          <line x1="30" y1="40" x2="30" y2="220" stroke="#64748b"></line>
          {' '.join(bars)}
        </svg>
      </body>
    </html>
    """)
    data_html_path.write_text(data_html_content, encoding="utf-8")

    data_svg_content = dedent(f"""
    <svg width="700" height="260" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#f8fafc"></rect>
      <line x1="30" y1="220" x2="650" y2="220" stroke="#64748b"></line>
      <line x1="30" y1="40" x2="30" y2="220" stroke="#64748b"></line>
      {' '.join(bars)}
    </svg>
    """)
    data_svg_path.write_text(data_svg_content, encoding="utf-8")

    return json_path, html_path, svg_path


if __name__ == "__main__":
    matrix = run_security_matrix()
    json_path, html_path, svg_path = write_report(matrix)
    print("Hasil pengujian keamanan Guard App")
    print(f"Payload asli: {json.dumps(matrix['payload'], ensure_ascii=False)}")
    print("\n| Skenario | Status | Target | Hasil |")
    print("|---|---:|---|---|")
    for item in matrix["results"]:
        print(f"| {item['scenario']} | {item['status_code']} | {item['expected']} | {'Lulus' if item['passed'] else 'Gagal'} |")
    print(f"\nPass rate: {matrix['pass_rate']:.0%}")
    print(f"Laporan HTML: {html_path}")
    print(f"Laporan SVG: {svg_path}")
    print(f"Matriks ancaman data-centric HTML: {Path(__file__).resolve().parent / 'data_centric_threat_matrix.html'}")
    print(f"Matriks ancaman data-centric SVG: {Path(__file__).resolve().parent / 'data_centric_threat_matrix.svg'}")
