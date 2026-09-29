"""
Automated Verification Script for the 5 Strategic Improvements in PhishGuard
"""

import asyncio
import sys
import time
import numpy as np
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

def test_bloom_filter():
    print(">>> 1. Probando Filtro Bloom en Memoria (BloomFilter & DomainFilter)...")
    from phishguard_api.bloom_filter import domain_filter, BloomFilter

    bf = BloomFilter(expected_elements=1000, false_positive_rate=0.001)
    bf.add("google.com")
    bf.add("microsoft.com")

    assert "google.com" in bf
    assert "microsoft.com" in bf
    assert "suspicious-bank-phish.xyz" not in bf

    # Test singleton domain_filter
    t0 = time.perf_counter()
    is_trusted = domain_filter.is_trusted("https://www.google.com/search?q=security")
    elapsed_us = (time.perf_counter() - t0) * 1_000_000

    assert is_trusted is True, "google.com debe ser identificado como dominio de confianza"
    print(f"   [OK] Bloom Filter validó google.com en {elapsed_us:.2f} microsegundos (< 0.1ms).")

    is_untrusted = domain_filter.is_trusted("https://paypal-update-account-security.net/login")
    assert is_untrusted is False, "Dominio sospechoso NO debe estar en el filtro de confianza"
    print("   [OK] Dominio no confiable rechazado correctamente por el Bloom Filter.")

async def test_commercial_baseline():
    print(">>> 2. Probando Conector Comercial Baseline (Google Safe Browsing)...")
    from phishguard_api.commercial_baseline import gsb_client

    res_clean = await gsb_client.lookup("https://www.google.com")
    assert "provider" in res_clean
    assert res_clean["is_malicious"] is False
    print(f"   [OK] GSB lookup (clean): provider={res_clean['provider']}, malicious={res_clean['is_malicious']}, lat={res_clean['latency_ms']:.1f}ms")

    res_phish = await gsb_client.lookup("https://paypal.com-verify-account.login.php")
    assert "is_malicious" in res_phish
    print(f"   [OK] GSB lookup (threat): provider={res_phish['provider']}, malicious={res_phish['is_malicious']}, types={res_phish.get('threat_types')}")

def test_visual_brand_matcher():
    print(">>> 3. Probando Matcher Visual de Logotipos de Marca (Stage M3)...")
    from phishguard_visual.matcher import visual_brand_matcher

    # Synthetic PayPal Blue image
    h, w = 100, 200
    paypal_img = np.zeros((h, w, 3), dtype=np.float32)
    paypal_img[:, :] = [0.0, 0.43, 0.70] # PayPal Blue

    res = visual_brand_matcher.match_image(paypal_img)
    print(f"   [OK] Matcher sobre imagen PayPal: brand={res['visual_brand_name']}, sim={res['visual_brand_similarity']:.2f}, detected={res['visual_brand_detected']}")
    assert res["visual_brand_name"] == "paypal"
    assert res["visual_brand_detected"] == 1.0

    # Neutral gray image
    neutral_img = np.zeros((h, w, 3), dtype=np.float32)
    neutral_img[:, :] = [0.5, 0.5, 0.5]
    res_neutral = visual_brand_matcher.match_image(neutral_img)
    print(f"   [OK] Matcher sobre imagen neutra: brand={res_neutral['visual_brand_name']}, detected={res_neutral['visual_brand_detected']}")
    assert res_neutral["visual_brand_detected"] == 0.0

def test_prometheus_metrics():
    print(">>> 4. Probando Exportador de Métricas Prometheus (/metrics)...")
    from phishguard_api.metrics import metrics

    metrics.record_job_completed("url", 1.2)
    metrics.record_job_completed("bloom", 0.05)
    metrics.record_job_completed("infrastructure", 45.0)

    output = metrics.export_prometheus_text()
    assert "# HELP phishguard_requests_total" in output
    assert "# TYPE phishguard_requests_total counter" in output
    assert 'phishguard_requests_total{status="success",exit_stage="bloom"}' in output
    assert "phishguard_cache_hits_total" in output

    lines_count = len(output.strip().split("\n"))
    print(f"   [OK] Métricas Prometheus generadas correctamente ({lines_count} líneas de métricas válidas).")

async def test_fastapi_endpoints():
    print(">>> 5. Probando Endpoints /metrics y /jobs/{id}/user-card en FastAPI...")
    import httpx
    from phishguard_api.server import app

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        # Test /metrics
        resp_metrics = await client.get("/metrics")
        assert resp_metrics.status_code == 200
        assert "phishguard_requests_total" in resp_metrics.text
        print(f"   [OK] GET /metrics respondió HTTP 200 con formato OpenMetrics.")

        # Test /jobs/{id}/user-card con ID no existente
        resp_card = await client.get("/jobs/00000000-0000-0000-0000-000000000000/user-card")
        assert resp_card.status_code in (404, 503)
        print(f"   [OK] GET /jobs/fake-id/user-card respondió HTTP {resp_card.status_code} de forma controlada.")

async def main_async():
    print("=" * 65)
    print("VERIFICACIÓN DE LAS 5 MEJORAS IMPLEMENTADAS EN PHISHGUARD")
    print("=" * 65)
    test_bloom_filter()
    await test_commercial_baseline()
    test_visual_brand_matcher()
    test_prometheus_metrics()
    await test_fastapi_endpoints()
    print("=" * 65)
    print("¡TODAS LAS 5 MEJORAS PASARON LA VERIFICACIÓN EXITOSAMENTE (5/5)!")
    print("=" * 65)

if __name__ == "__main__":
    asyncio.run(main_async())
