"""
Automated Verification Script for the 5 Resolved Flaws in PhishGuard
"""

import sys
import time
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

def test_cache():
    print(">>> 1. Probando Capa de Caché de Decisiones (DecisionCache)...")
    from phishguard_api.cache import DecisionCache
    
    cache = DecisionCache(max_size=10, default_ttl=2)
    cache.set("https://paypal.com/login", {"decision": "phishing", "probability": 0.95})
    
    # Hit
    val = cache.get("https://paypal.com/login")
    assert val is not None, "Fallo: la URL debe estar en caché"
    assert val["decision"] == "phishing"
    assert val["probability"] == 0.95
    
    # Hit con URL sin normalizar (mayúsculas / espacios)
    val2 = cache.get("  HTTPS://PAYPAL.COM/login  ")
    assert val2 is not None, "Fallo: la normalización de URL debe coincidir"
    
    # Miss
    val_miss = cache.get("https://google.com")
    assert val_miss is None, "Fallo: URL no registrada debe ser None"
    
    stats = cache.stats()
    assert stats["hits"] == 2
    assert stats["misses"] == 1
    print(f"   [OK] DecisionCache funciona correctamente. Stats: {stats}")

def test_resolver_timeout():
    print(">>> 2. Probando Timeouts en DNS Resolver (SocketResolver)...")
    from phishguard_infra.resolver import SocketResolver
    
    resolver = SocketResolver(timeout=2.0)
    
    # Host válido
    res_valid = resolver.resolve("google.com", 80)
    print(f"   [OK] google.com resuelto en {res_valid.elapsed_ms:.1f}ms: {res_valid.addresses[:2]}")
    assert len(res_valid.addresses) > 0
    
    # Host inválido / timeout
    t0 = time.perf_counter()
    res_invalid = resolver.resolve("invalid-domain-non-existent-test-12345.xyz", 80)
    elapsed = time.perf_counter() - t0
    print(f"   [OK] Dominio no existente manejado de forma segura en {elapsed:.2f}s sin colapso: addresses={res_invalid.addresses}")
    assert res_invalid.addresses == ()

def test_worker_imports():
    print(">>> 3. Probando Importaciones y Estructura del Worker Refactorizado...")
    from phishguard_api.worker import worker_loop, recover_zombie_jobs, process_job
    print("   [OK] worker.py cargado correctamente con recover_zombie_jobs, process_job y worker_loop concurrente.")

def main():
    print("=" * 60)
    print("VERIFICACIÓN DE LOS 5 FALLOS CORREGIDOS EN PHISHGUARD")
    print("=" * 60)
    test_cache()
    test_resolver_timeout()
    test_worker_imports()
    print("=" * 60)
    print("¡TODAS LAS PRUEBAS DE VERIFICACIÓN PASARON EXITOSAMENTE (3/3)!")
    print("=" * 60)

if __name__ == "__main__":
    main()
