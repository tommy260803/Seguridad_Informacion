from __future__ import annotations

import json
import statistics
import time
from pathlib import Path
from phishguard_ml.hybrid_model import predict_hybrid


def run_usability_benchmark(iterations: int = 50) -> dict:
    """
    Ejecuta una evaluación empírica de sobrecarga de latencia y usabilidad
    para medir el impacto en la navegación del usuario (Threshold de Nielsen < 100ms).
    """
    test_urls = [
        "https://www.google.com/search?q=security",
        "https://www.paypal.com/signin",
        "https://paypal.attacker-phishing.com/login",
        "https://github.com/explore",
        "https://bcp.actualizar-datos-seguros.com/login",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://facebook.verify-account-security.tk/auth",
        "https://aws.amazon.com/console/",
    ]

    latencies_ms: list[float] = []

    print(f"Iniciando benchmark de usabilidad ({iterations * len(test_urls)} inferencias)...")
    start_total = time.perf_counter()

    for i in range(iterations):
        for url in test_urls:
            t0 = time.perf_counter()
            _ = predict_hybrid(url)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(elapsed_ms)

    total_time_s = time.perf_counter() - start_total

    latencies_sorted = sorted(latencies_ms)
    n = len(latencies_sorted)

    p50 = latencies_sorted[int(n * 0.50)]
    p90 = latencies_sorted[int(n * 0.90)]
    p95 = latencies_sorted[int(n * 0.95)]
    p99 = latencies_sorted[int(n * 0.99)]
    mean_val = statistics.mean(latencies_sorted)
    stdev_val = statistics.stdev(latencies_sorted) if n > 1 else 0.0

    # Cumplimiento del umbral perceptivo de Nielsen (100 ms)
    nielsen_compliant_count = sum(lat < 100.0 for lat in latencies_sorted)
    nielsen_compliance_pct = (nielsen_compliant_count / n) * 100.0

    # Simulación de renderizado del interstitial de advertencia
    sample_interstitial_html = """
    <div id="phishguard-interstitial" style="background:#dc2626; color:white; padding:20px; font-family:sans-serif;">
        <h1>¡Advertencia de Seguridad!</h1>
        <p>PhishGuard ha detectado un posible intento de suplantación de identidad (Phishing).</p>
        <button id="pg-leave-btn">Salir del sitio</button>
        <button id="pg-proceed-btn">Continuar bajo mi propio riesgo</button>
    </div>
    """
    dom_payload_bytes = len(sample_interstitial_html.encode("utf-8"))

    results = {
        "benchmark_version": "1.0.0",
        "total_inferences": n,
        "total_benchmark_time_seconds": round(total_time_s, 2),
        "latency_metrics_ms": {
            "p50_median": round(p50, 3),
            "p90": round(p90, 3),
            "p95": round(p95, 3),
            "p99": round(p99, 3),
            "mean": round(mean_val, 3),
            "std_dev": round(stdev_val, 3),
            "min": round(latencies_sorted[0], 3),
            "max": round(latencies_sorted[-1], 3),
        },
        "usability_evaluation": {
            "nielsen_100ms_threshold": "100.0 ms",
            "compliance_percentage": round(nielsen_compliance_pct, 2),
            "perceived_user_lag": "Perceptiblemente instantáneo (< 100ms)" if p95 < 100.0 else "Retardo leve",
            "interstitial_payload_bytes": dom_payload_bytes,
        }
    }

    out_path = Path("artifacts/usability_benchmark_report.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Reporte de benchmark guardado en {out_path}")
    return results


if __name__ == "__main__":
    report = run_usability_benchmark(iterations=30)
    print("\n=== RESULTADOS DE USABILIDAD Y LATENCIA ===")
    print(f"Inferencias totales: {report['total_inferences']}")
    print(f"Latencia p50 (Mediana): {report['latency_metrics_ms']['p50_median']} ms")
    print(f"Latencia p95:           {report['latency_metrics_ms']['p95']} ms")
    print(f"Latencia p99:           {report['latency_metrics_ms']['p99']} ms")
    print(f"Cumplimiento Nielsen:   {report['usability_evaluation']['compliance_percentage']}% de peticiones < 100ms")
    print(f"Veredicto usabilidad:   {report['usability_evaluation']['perceived_user_lag']}")
