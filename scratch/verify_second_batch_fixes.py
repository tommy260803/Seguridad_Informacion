"""
Automated Verification Script for the Second Batch of 5 Critical Fixes in PhishGuard
"""

import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

def test_m0_model_loaded():
    print(">>> 1. Verificando Carga Real del Modelo M0 en memoria...")
    from phishguard_api.inference import registry, predict_m0
    assert registry.m0_model is not None, "ERROR: m0_model debe estar cargado y no ser None"
    
    p_clean = predict_m0("https://google.com")
    p_phish = predict_m0("https://paypal-security-update-account-verification.login.php.suspicious.net")
    
    print(f"   [OK] M0 cargado exitosamente: p(google.com) = {p_clean:.4f}, p(phishing_sample) = {p_phish:.4f}")
    assert p_clean < 0.20, "Google.com debe tener baja probabilidad de phishing"
    assert p_phish > 0.70, "URL sospechosa debe tener alta probabilidad de phishing"

def test_ssrf_protection():
    print(">>> 2. Verificando Blindaje Anti-SSRF...")
    from phishguard_infra.policy import validate_url_ssrf_safety, UnsafeTargetError

    # 1. AWS/GCP Cloud Metadata IP
    blocked = False
    try:
        validate_url_ssrf_safety("http://169.254.169.254/latest/meta-data/")
    except UnsafeTargetError as err:
        blocked = True
        print(f"   [OK] Bloqueada IP de metadatos de nube: {err.detail}")
    assert blocked, "Fallo: http://169.254.169.254 debió ser bloqueado"

    # 2. Localhost
    blocked = False
    try:
        validate_url_ssrf_safety("http://localhost:5432/admin")
    except UnsafeTargetError as err:
        blocked = True
        print(f"   [OK] Bloqueado localhost: {err.detail}")
    assert blocked, "Fallo: localhost debió ser bloqueado"

    # 3. Subred privada RFC1918
    blocked = False
    try:
        validate_url_ssrf_safety("http://192.168.1.1/router-login")
    except UnsafeTargetError as err:
        blocked = True
        print(f"   [OK] Bloqueada IP privada RFC1918: {err.detail}")
    assert blocked, "Fallo: 192.168.1.1 debió ser bloqueada"

    # 4. Dominio público legítimo
    allowed = True
    try:
        validate_url_ssrf_safety("https://google.com")
    except UnsafeTargetError:
        allowed = False
    assert allowed, "Fallo: google.com debió ser permitido"
    print("   [OK] Dominio público legítimo (google.com) permitido sin falsos positivos.")

def test_database_engine_config():
    print(">>> 3. Verificando Configuración de Conexión PostgreSQL (pool_pre_ping)...")
    from phishguard_api.database import engine
    
    pool = engine.pool
    print(f"   [OK] Pool size: {pool.size()}, max_overflow: {pool._max_overflow}, pre_ping: {pool._pre_ping}, recycle: {pool._recycle}")
    assert pool._pre_ping is True, "ERROR: pool_pre_ping debe estar habilitado"
    assert pool._recycle == 1800, "ERROR: pool_recycle debe ser 1800s"
    assert pool.size() == 10, "ERROR: pool_size debe ser 10"

def test_idn_homoglyph_preservation():
    print(">>> 4. Verificando Preservación de Homóglifos IDN en CanonicalUrl...")
    from phishguard_data.urls import canonicalize_url
    from phishguard_data.psl import PublicSuffixList
    
    psl = PublicSuffixList.from_file(list(Path("data/raw").rglob("public_suffix_list.dat"))[-1])
    
    # URL con homóglifo cirílico 'а' en lugar de latino 'a'
    homoglyph_url = "https://pаypаl.com/signin"
    canonical = canonicalize_url(homoglyph_url, psl=psl)
    
    print(f"   [OK] Canonical Punycode host: {canonical.host}")
    print(f"   [OK] Preserved visual display_host: {canonical.display_host.encode('ascii', 'backslashreplace').decode('ascii')}")
    print(f"   [OK] Flag is_idn_homoglyph: {canonical.is_idn_homoglyph}")
    
    assert canonical.is_idn_homoglyph is True, "Debe detectar que el dominio es un IDN / Punycode"
    assert "xn--" in canonical.host, "La forma de red debe estar en Punycode"
    assert canonical.display_host == "pаypаl.com", "La forma visual debe retener los caracteres originales"

def test_resolver_shared_executor():
    print(">>> 5. Verificando Executor Estático Compartido en SocketResolver...")
    from phishguard_infra.resolver import SocketResolver, _SHARED_RESOLVER_EXECUTOR
    
    r1 = SocketResolver()
    r2 = SocketResolver()
    
    assert r1._executor is _SHARED_RESOLVER_EXECUTOR, "r1 debe usar el executor estático compartido"
    assert r2._executor is _SHARED_RESOLVER_EXECUTOR, "r2 debe usar el executor estático compartido"
    assert not _SHARED_RESOLVER_EXECUTOR._shutdown, "El executor no debe estar apagado"
    
    res = r1.resolve("google.com", 80)
    print(f"   [OK] DNS compartido resolvió exitosamente google.com en {res.elapsed_ms:.1f}ms: {res.addresses[:2]}")
    assert len(res.addresses) > 0

def main():
    print("=" * 65)
    print("VERIFICACIÓN DE LOS 5 FALLOS CRÍTICOS RESUELTOS (LOTE 2)")
    print("=" * 65)
    test_m0_model_loaded()
    test_ssrf_protection()
    test_database_engine_config()
    test_idn_homoglyph_preservation()
    test_resolver_shared_executor()
    print("=" * 65)
    print("¡TODOS LOS 5 FALLOS FUERON CORREGIDOS Y VERIFICADOS CON ÉXITO (5/5)!")
    print("=" * 65)

if __name__ == "__main__":
    main()
