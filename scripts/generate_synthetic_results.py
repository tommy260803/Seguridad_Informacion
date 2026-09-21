"""Generate synthetic infrastructure, content, and visual analysis results for M1/M2/M3 training."""
import json
import random
from pathlib import Path

random.seed(20260916)

DATASET = Path("data/processed/0.1.0")
OUTPUT = Path("artifacts/analysis-results")
OUTPUT.mkdir(parents=True, exist_ok=True)

# Load samples to get sample_ids and URLs
samples = []
with open(DATASET / "samples.jsonl", encoding="utf-8") as f:
    for line in f:
        row = json.loads(line)
        samples.append(row)

print(f"Loaded {len(samples)} samples")

infra_lines = []
content_lines = []
visual_lines = []

for sample in samples:
    sid = sample["sample_id"]
    url = sample["canonical_url"]
    label = sample["label"]  # 1=phishing, 0=legitimate
    is_phishing = label == 1

    # --- Infrastructure features ---
    # Phishing sites: more likely to have IP hosts, TLS failures, more redirects
    has_ip = random.random() < (0.35 if is_phishing else 0.02)
    tls_fail = random.random() < (0.25 if is_phishing else 0.01)
    redirect_count = random.randint(0, 5) if is_phishing else random.randint(0, 2)
    dns_count = random.randint(1, 4) if is_phishing else random.randint(1, 3)
    uses_https = 1.0 if (random.random() < 0.7 if is_phishing else random.random() < 0.95) else 0.0

    infra_features = {
        "dns_address_count_initial": dns_count,
        "dns_ipv4_count_initial": dns_count,
        "dns_ipv6_count_initial": max(0, dns_count - random.randint(0, 2)),
        "redirect_count": redirect_count,
        "redirect_host_change_count": random.randint(0, redirect_count),
        "redirect_registered_domain_change_count": random.randint(0, min(redirect_count, 2)),
        "tls_hop_count": 1 if not tls_fail else 2,
        "tls_verification_failure_count": 1 if tls_fail else 0,
        "tls_max_chain_length": random.randint(1, 3),
        "certificate_available": 0.0 if tls_fail else 1.0,
        "final_status_code": 200 if not tls_fail else random.choice([0, 403, 502]),
        "final_uses_https": uses_https,
        "total_dns_ms": round(random.uniform(5, 200), 1),
        "total_request_ms": round(random.random() * 5000 + 200, 1),
    }

    infra_result = {"status": "success", "features": infra_features}
    infra_lines.append(json.dumps({"sample_id": sid, "result": infra_result}))

    # --- Content features ---
    # Phishing: more forms, password inputs, login terms, external resources
    form_count = random.randint(1, 4) if is_phishing else random.randint(0, 2)
    pw_inputs = random.randint(1, 3) if is_phishing and random.random() < 0.6 else 0
    email_inputs = random.randint(0, 2) if is_phishing and random.random() < 0.3 else 0
    script_count = random.randint(1, 8) if is_phishing else random.randint(0, 5)
    iframe_count = random.randint(0, 3) if is_phishing and random.random() < 0.4 else 0
    ext_links = random.randint(0, 5) if is_phishing else random.randint(0, 10)
    login_terms = random.randint(1, 6) if is_phishing else random.randint(0, 2)
    payment_terms = random.randint(0, 3) if is_phishing and random.random() < 0.3 else 0

    content_features = {
        "content_truncated": 0.0,
        "content_bytes": random.randint(5000, 500000),
        "html_tag_count": random.randint(20, 500),
        "html_title_length": random.randint(5, 80),
        "html_text_length": random.randint(100, 10000),
        "html_form_count": form_count,
        "html_password_input_count": pw_inputs,
        "html_email_input_count": email_inputs,
        "html_payment_input_count": 0,
        "html_script_count": script_count,
        "html_iframe_count": iframe_count,
        "html_link_count": ext_links,
        "html_external_link_count": random.randint(0, min(ext_links, 5)),
        "html_external_resource_count": random.randint(0, 8),
        "html_external_form_action_count": random.randint(0, 3) if is_phishing else 0,
        "html_login_term_count": login_terms,
        "html_payment_term_count": payment_terms,
    }

    content_result = {"status": "success", "features": content_features}
    content_lines.append(json.dumps({"sample_id": sid, "result": content_result}))

    # --- Visual features ---
    # Phishing: darker pages, more edges, lower luminance
    width = random.choice([1280, 1366, 1440, 1920])
    height = random.choice([720, 768, 900, 1080])
    mean_lum = random.uniform(0.15, 0.45) if is_phishing else random.uniform(0.35, 0.75)
    edge_dens = random.uniform(0.08, 0.25) if is_phishing else random.uniform(0.03, 0.12)
    dark_ratio = random.uniform(0.2, 0.6) if is_phishing else random.uniform(0.05, 0.3)
    sat_ratio = random.uniform(0.05, 0.25)

    visual_features = {
        "visual_width": width,
        "visual_height": height,
        "visual_aspect_ratio": round(width / height, 4),
        "visual_mean_luminance": round(mean_lum, 4),
        "visual_luminance_std": round(random.uniform(0.1, 0.35), 4),
        "visual_edge_density": round(edge_dens, 4),
        "visual_dark_pixel_ratio": round(dark_ratio, 4),
        "visual_saturated_pixel_ratio": round(sat_ratio, 4),
    }

    visual_result = {"status": "success", "features": visual_features}
    visual_lines.append(json.dumps({"sample_id": sid, "result": visual_result}))

# Write JSONL files
(OUTPUT / "infrastructure-results.jsonl").write_text("\n".join(infra_lines) + "\n", encoding="utf-8")
(OUTPUT / "content-results.jsonl").write_text("\n".join(content_lines) + "\n", encoding="utf-8")
(OUTPUT / "visual-results.jsonl").write_text("\n".join(visual_lines) + "\n", encoding="utf-8")

print(f"Generated {len(infra_lines)} infra results")
print(f"Generated {len(content_lines)} content results")
print(f"Generated {len(visual_lines)} visual results")
print(f"Output: {OUTPUT}")
