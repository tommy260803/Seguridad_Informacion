"""
Automated Verification Script for the 5 Differentiating Value Improvements in PhishGuard
"""

import sys
import json
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

def test_sla_profiles():
    print(">>> 1. Probando Perfiles Adaptativos Conscientes de SLA (InspectionProfile)...")
    from phishguard_orchestrator.profiles import InspectionProfile, get_profile_config

    p_browser = get_profile_config(InspectionProfile.REAL_TIME_BROWSER)
    assert p_browser.target_sla_ms == 5.0
    assert p_browser.policy.budget == 0.0
    print(f"   [OK] Profile REAL_TIME_BROWSER: SLA={p_browser.target_sla_ms}ms, Budget={p_browser.policy.budget}")

    p_gateway = get_profile_config("enterprise_gateway")
    assert p_gateway.target_sla_ms == 35.0
    assert p_gateway.policy.budget == 2.0
    print(f"   [OK] Profile ENTERPRISE_GATEWAY: SLA={p_gateway.target_sla_ms}ms, Budget={p_gateway.policy.budget}")

    p_forensic = get_profile_config(InspectionProfile.DEEP_FORENSIC)
    assert p_forensic.target_sla_ms == 1500.0
    assert p_forensic.policy.budget == 3.0
    print(f"   [OK] Profile DEEP_FORENSIC: SLA={p_forensic.target_sla_ms}ms, Budget={p_forensic.policy.budget}")

def test_forensic_manifest():
    print(">>> 2. Probando Manifiesto Forense Criptográfico Inmutable (SHA-256 / HMAC)...")
    from phishguard_explain.forensic_manifest import generate_forensic_manifest, compute_sha256

    test_html = "<html><body><h1>Fake Bank Login</h1></body></html>"
    manifest = generate_forensic_manifest(
        job_id="test-job-uuid-1234",
        url="https://fake-login-bank.com/auth",
        decision="phishing",
        probability=0.985,
        confidence=0.95,
        modalities_consulted=["url", "infrastructure", "content"],
        evidence_summary=[{"feature": "domain_age_days", "value": 2.0}],
        raw_html=test_html
    )

    hashes = manifest["cryptographic_hashes"]
    expected_html_hash = compute_sha256(test_html)
    assert hashes["html_dom_sha256"] == expected_html_hash
    assert len(hashes["manifest_hmac_signature"]) == 64
    assert manifest["subject"]["decision"] == "phishing"
    assert manifest["chain_of_custody"]["tamper_evident"] is True
    print(f"   [OK] Manifiesto generado con éxito. HTML SHA-256: {hashes['html_dom_sha256'][:16]}... HMAC: {hashes['manifest_hmac_signature'][:16]}...")

def test_anti_cloaking():
    print(">>> 3. Probando Motor de Detección Anti-Cloaking / Evasión de Sandbox...")
    from phishguard_content.cloaking import cloaking_detector

    # Phishing evasion page with webdriver detection and fake cloudflare challenge
    evasive_html = """
    <html>
      <script>
        if (navigator.webdriver) {
            window.location.href = "https://google.com";
        }
      </script>
      <div>checking your browser before accessing</div>
    </html>
    """
    res_cloaked = cloaking_detector.analyze_content(evasive_html)
    print(f"   [OK] Evasive sample detected: cloaking={res_cloaked['cloaking_detected']}, risk={res_cloaked['evasion_risk']}, techniques={res_cloaked['detected_techniques']}")
    assert res_cloaked["cloaking_detected"] == 1.0
    assert "anti_crawler_webdriver_detection" in res_cloaked["detected_techniques"]
    assert "fake_security_challenge_interstitial" in res_cloaked["detected_techniques"]

    # Benign normal page
    clean_html = "<html><body><h1>Bienvenido a nuestra tienda oficial</h1></body></html>"
    res_clean = cloaking_detector.analyze_content(clean_html)
    assert res_clean["cloaking_detected"] == 0.0
    print("   [OK] Página legítima sin técnicas de evasión clasificada como limpia.")

def test_homoglyphs_tr39():
    print(">>> 4. Probando Normalizador Dual de Homóglifos Unicode TR39...")
    from phishguard_ml.homoglyphs import to_visual_skeleton, analyze_homoglyphs

    # Attack: 'pаypаl.com' with Cyrillic '\u0430'
    cyrillic_paypal = "p\u0430yp\u0430l.com"
    skeleton = to_visual_skeleton(cyrillic_paypal)
    assert skeleton == "paypal.com", f"Esqueleto visual debe ser 'paypal.com', obtenido: {skeleton}"
    print(f"   [OK] Proyección TR39: '{cyrillic_paypal.encode('ascii', 'backslashreplace').decode('ascii')}' -> '{skeleton}'")

    analysis = analyze_homoglyphs(cyrillic_paypal, registered_domain="xn--pypl-53dc.com")
    print(f"   [OK] Análisis homóglifos: spoofing_detected={analysis['homoglyph_brand_spoofing_detected']}, target={analysis['closest_brand_target']}")
    assert analysis["homoglyph_brand_spoofing_detected"] == 1.0
    assert analysis["closest_brand_target"] == "paypal"

    # Legitimate non-homoglyph domain
    clean_analysis = analyze_homoglyphs("wikipedia.org", registered_domain="wikipedia.org")
    assert clean_analysis["homoglyph_brand_spoofing_detected"] == 0.0
    print("   [OK] Dominio limpio sin homóglifos verificado correctamente.")

def test_stix_exporter():
    print(">>> 5. Probando Exportador de Inteligencia de Amenazas OASIS STIX 2.1...")
    from phishguard_api.stix_exporter import export_to_stix21

    bundle = export_to_stix21(
        job_id="test-stix-1234",
        url="https://paypal-update-account.secure-verify.net/signin",
        decision="phishing",
        probability=0.992,
        confidence=0.98,
        brand_name="paypal",
        modalities_consulted=["url", "infrastructure", "content", "visual"]
    )

    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    
    types = [obj["type"] for obj in bundle["objects"]]
    assert "indicator" in types
    assert "observed-data" in types
    assert "attack-pattern" in types
    assert "identity" in types
    assert "relationship" in types
    
    print(f"   [OK] STIX 2.1 Bundle generado con éxito: ID={bundle['id']}, {len(bundle['objects'])} objetos STIX.")

def main():
    print("=" * 70)
    print("VERIFICACIÓN DE LAS 5 MEJORAS DE VALOR DIFERENCIADOR EN PHISHGUARD")
    print("=" * 70)
    test_sla_profiles()
    test_forensic_manifest()
    test_anti_cloaking()
    test_homoglyphs_tr39()
    test_stix_exporter()
    print("=" * 70)
    print("¡TODAS LAS 5 MEJORAS DIFERENCIADORAS PASARON CON ÉXITO (5/5)!")
    print("=" * 70)

if __name__ == "__main__":
    main()
