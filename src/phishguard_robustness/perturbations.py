from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import numpy as np


@dataclass(frozen=True)
class Perturbation:
    name: str
    original: str
    perturbed: str


def perturb_url(url: str, name: str) -> Perturbation:
    parts = urlsplit(url)
    host = parts.hostname or parts.netloc
    port_suffix = f":{parts.port}" if parts.port else ""
    if name == "path_noise":
        value = urlunsplit(
            (parts.scheme, parts.netloc, "/static/" + parts.path.lstrip("/"), parts.query, parts.fragment)
        )
    elif name == "leetspeak":
        value = url.replace("login", "l0gin").replace("secure", "s3cure")
    elif name == "homoglyph_ascii":
        value = url.replace("a", "4").replace("o", "0")
    elif name == "subdomain_padding":
        new_host = f"portal.verify.{host}" if host else parts.netloc
        value = urlunsplit((parts.scheme or "https", new_host + port_suffix, parts.path, parts.query, parts.fragment))
    elif name == "hyphen_insertion":
        labels = host.split(".") if host else []
        if len(labels) >= 2 and len(labels[-2]) >= 4:
            mid = len(labels[-2]) // 2
            labels[-2] = labels[-2][:mid] + "-" + labels[-2][mid:]
            new_host = ".".join(labels)
        else:
            new_host = f"secure-{host}" if host else parts.netloc
        value = urlunsplit((parts.scheme or "https", new_host + port_suffix, parts.path, parts.query, parts.fragment))
    elif name == "tld_swap":
        labels = host.split(".") if host else []
        if len(labels) >= 2:
            labels[-1] = "org" if labels[-1] != "org" else "com"
            new_host = ".".join(labels)
        else:
            new_host = host
        value = urlunsplit((parts.scheme or "https", new_host + port_suffix, parts.path, parts.query, parts.fragment))
    elif name == "homograph_punycode":
        labels = host.split(".") if host else []
        if len(labels) >= 2:
            labels[-2] = f"xn--{labels[-2][:12]}-9ja"
            new_host = ".".join(labels)
        else:
            new_host = f"xn--{host}-9ja"
        value = urlunsplit((parts.scheme or "https", new_host + port_suffix, parts.path, parts.query, parts.fragment))
    else:
        raise ValueError(f"Unsupported URL perturbation: {name}")
    return Perturbation(name, url, value)


def perturb_html(html: str, name: str) -> Perturbation:
    if name == "whitespace":
        value = " ".join(html.split())
    elif name == "attribute_order":
        value = html.replace(
            '<input type="password" name="password">',
            '<input name="password" type="password">',
        )
    elif name == "wrapper":
        value = f'<div data-wrapper="1">{html}</div>'
    elif name == "zero_width_obfuscation":
        value = (
            html.replace("login", "lo\u200bgin")
            .replace("password", "pass\u200bword")
            .replace("verify", "ve\u200brify")
        )
    else:
        raise ValueError(f"Unsupported HTML perturbation: {name}")
    return Perturbation(name, html, value)


def generate_suite(value: str, *, kind: str, seed: int = 0) -> list[Perturbation]:
    names = (
        ("path_noise", "leetspeak", "homoglyph_ascii")
        if kind == "url"
        else ("whitespace", "attribute_order", "wrapper")
        if kind == "html"
        else ()
    )
    if not names:
        raise ValueError("kind must be url or html")
    rng = random.Random(seed)
    shuffled = list(names)
    rng.shuffle(shuffled)
    return [(perturb_url if kind == "url" else perturb_html)(value, name) for name in shuffled]


def perturb_feature_matrix(
    X: np.ndarray,
    feature_names: list[str] | tuple[str, ...],
    attack_type: str,
    *,
    seed: int = 20260916,
) -> np.ndarray:
    """Apply realistic, domain-constrained adversarial evasions to a feature matrix X."""
    rng = np.random.default_rng(seed)
    X_adv = X.copy().astype(np.float64)
    idx = {name: i for i, name in enumerate(feature_names)}

    if attack_type in ("url_evasion", "homograph_punycode", "combined_multimodal"):
        # Attacker normalizes host length/digits/hyphens or uses punycode/subdomain camouflage
        if "host_digit_count" in idx:
            X_adv[:, idx["host_digit_count"]] = 0.0
        if "host_digit_ratio" in idx:
            X_adv[:, idx["host_digit_ratio"]] = 0.0
        if "host_hyphen_count" in idx:
            X_adv[:, idx["host_hyphen_count"]] = np.minimum(X_adv[:, idx["host_hyphen_count"]], 0.0)
        if "subdomain_count" in idx:
            X_adv[:, idx["subdomain_count"]] = np.minimum(X_adv[:, idx["subdomain_count"]], 1.0)
        if "host_label_count" in idx:
            X_adv[:, idx["host_label_count"]] = np.minimum(X_adv[:, idx["host_label_count"]], 2.0)
        if "host_entropy" in idx:
            X_adv[:, idx["host_entropy"]] = np.clip(X_adv[:, idx["host_entropy"]] * 0.82, 2.2, 3.3)
        if "host_length" in idx:
            X_adv[:, idx["host_length"]] = np.clip(X_adv[:, idx["host_length"]] * 0.72, 9.0, 15.0)
        if "registered_domain_length" in idx:
            X_adv[:, idx["registered_domain_length"]] = np.clip(
                X_adv[:, idx["registered_domain_length"]] * 0.78, 8.0, 13.0
            )
        if "tld_length" in idx:
            X_adv[:, idx["tld_length"]] = 3.0  # Swap to .com / .org
        if attack_type == "homograph_punycode" and "has_punycode" in idx:
            X_adv[:, idx["has_punycode"]] = 1.0

    if attack_type in ("infra_evasion", "combined_multimodal"):
        # Attacker hides behind single-IP HTTPS proxy with clean redirect chain
        if "infra_redirect_count" in idx:
            X_adv[:, idx["infra_redirect_count"]] = 0.0
        if "infra_redirect_host_change_count" in idx:
            X_adv[:, idx["infra_redirect_host_change_count"]] = 0.0
        if "infra_redirect_registered_domain_change_count" in idx:
            X_adv[:, idx["infra_redirect_registered_domain_change_count"]] = 0.0
        if "infra_tls_verification_failure_count" in idx:
            X_adv[:, idx["infra_tls_verification_failure_count"]] = 0.0
        if "infra_fast_flux_probability" in idx:
            X_adv[:, idx["infra_fast_flux_probability"]] = 0.0
        if "infra_dns_distinct_slash24_count" in idx:
            X_adv[:, idx["infra_dns_distinct_slash24_count"]] = np.minimum(
                X_adv[:, idx["infra_dns_distinct_slash24_count"]], 1.0
            )
        if "infra_certificate_min_validity_days" in idx:
            X_adv[:, idx["infra_certificate_min_validity_days"]] = np.maximum(
                X_adv[:, idx["infra_certificate_min_validity_days"]], 180.0
            )

    if attack_type in ("dom_obfuscation", "combined_multimodal"):
        # Attacker obfuscates login/payment keywords with zero-width chars and injects benign internal links
        if "html_login_term_count" in idx:
            X_adv[:, idx["html_login_term_count"]] = 0.0
        if "html_payment_term_count" in idx:
            X_adv[:, idx["html_payment_term_count"]] = 0.0
        if "html_external_form_action_count" in idx:
            X_adv[:, idx["html_external_form_action_count"]] = 0.0
        if "html_credential_exfiltration_count" in idx:
            X_adv[:, idx["html_credential_exfiltration_count"]] = 0.0
        if "form_exfiltration_risk_score" in idx:
            X_adv[:, idx["form_exfiltration_risk_score"]] = 0.0
        if "html_link_count" in idx:
            X_adv[:, idx["html_link_count"]] = X_adv[:, idx["html_link_count"]] + 25.0
        if "html_tag_count" in idx:
            X_adv[:, idx["html_tag_count"]] = X_adv[:, idx["html_tag_count"]] + 60.0

    if attack_type in ("visual_noise", "combined_multimodal"):
        # Attacker injects background luminance noise and shifts color palette to evade brand matcher
        if "visual_brand_detected" in idx:
            X_adv[:, idx["visual_brand_detected"]] = 0.0
        if "visual_brand_similarity" in idx:
            X_adv[:, idx["visual_brand_similarity"]] = np.clip(
                X_adv[:, idx["visual_brand_similarity"]] * 0.55, 0.0, 0.65
            )
        if "visual_hsv_similarity_max" in idx:
            X_adv[:, idx["visual_hsv_similarity_max"]] = np.clip(
                X_adv[:, idx["visual_hsv_similarity_max"]] * 0.55, 0.0, 0.65
            )
        if "visual_phash_distance_min" in idx:
            X_adv[:, idx["visual_phash_distance_min"]] = np.clip(
                X_adv[:, idx["visual_phash_distance_min"]] + 0.22, 0.0, 1.0
            )
        if "visual_edge_density" in idx:
            noise = rng.uniform(0.01, 0.04, size=len(X_adv))
            X_adv[:, idx["visual_edge_density"]] = np.clip(
                X_adv[:, idx["visual_edge_density"]] + noise, 0.0, 1.0
            )

    return X_adv
