from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

import numpy as np


FEATURE_VERSION = "url-features-1.0.0"
SUSPICIOUS_TOKENS = frozenset(
    {
        "account",
        "auth",
        "bank",
        "confirm",
        "credential",
        "login",
        "password",
        "payment",
        "secure",
        "signin",
        "update",
        "verify",
        "wallet",
    }
)
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")


FEATURE_NAMES = (
    "url_length",
    "host_length",
    "registered_domain_length",
    "path_length",
    "query_length",
    "host_label_count",
    "subdomain_count",
    "path_depth",
    "query_parameter_count",
    "url_digit_count",
    "url_digit_ratio",
    "host_digit_count",
    "host_digit_ratio",
    "url_hyphen_count",
    "host_hyphen_count",
    "dot_count",
    "underscore_count",
    "at_count",
    "percent_escape_count",
    "equals_count",
    "ampersand_count",
    "non_alphanumeric_ratio",
    "url_entropy",
    "host_entropy",
    "token_count",
    "longest_token_length",
    "suspicious_token_count",
    "suspicious_token_ratio",
    "has_ip_host",
    "has_userinfo",
    "has_nondefault_port",
    "uses_https",
    "has_punycode",
    "tld_length",
    "max_repeated_character_run",
    "path_has_file_extension",
)

FEATURE_PROFILES = {
    "authority_only": (
        "host_length",
        "registered_domain_length",
        "host_label_count",
        "subdomain_count",
        "host_digit_count",
        "host_digit_ratio",
        "host_hyphen_count",
        "host_entropy",
        "has_ip_host",
        "has_punycode",
        "tld_length",
    ),
    "full_url": FEATURE_NAMES,
}


@dataclass(frozen=True)
class UrlFeatureContext:
    canonical_url: str
    registered_domain: str


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _max_run(value: str) -> int:
    if not value:
        return 0
    longest = current = 1
    previous = value[0]
    for character in value[1:]:
        if character == previous:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
            previous = character
    return longest


def extract_url_features(context: UrlFeatureContext) -> dict[str, float]:
    parsed = urlsplit(context.canonical_url)
    host = (parsed.hostname or "").lower()
    url_lower = context.canonical_url.lower()
    tokens = TOKEN_PATTERN.findall(url_lower)
    suspicious_count = sum(token in SUSPICIOUS_TOKENS for token in tokens)
    digit_count = sum(character.isdigit() for character in context.canonical_url)
    host_digit_count = sum(character.isdigit() for character in host)
    alphanumeric_count = sum(character.isalnum() for character in context.canonical_url)
    host_labels = [label for label in host.split(".") if label]
    registered_labels = [label for label in context.registered_domain.split(".") if label]
    try:
        ipaddress.ip_address(host)
        has_ip_host = 1.0
    except ValueError:
        has_ip_host = 0.0
    try:
        port = parsed.port
    except ValueError:
        port = None
    nondefault_port = port is not None and not (
        (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
    )
    final_path_segment = parsed.path.rsplit("/", 1)[-1]
    has_extension = bool(re.search(r"\.[a-z0-9]{1,8}$", final_path_segment, flags=re.IGNORECASE))
    values = {
        "url_length": len(context.canonical_url),
        "host_length": len(host),
        "registered_domain_length": len(context.registered_domain),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "host_label_count": len(host_labels),
        "subdomain_count": max(0, len(host_labels) - len(registered_labels)),
        "path_depth": len([part for part in parsed.path.split("/") if part]),
        "query_parameter_count": len(parse_qsl(parsed.query, keep_blank_values=True)),
        "url_digit_count": digit_count,
        "url_digit_ratio": _ratio(digit_count, len(context.canonical_url)),
        "host_digit_count": host_digit_count,
        "host_digit_ratio": _ratio(host_digit_count, len(host)),
        "url_hyphen_count": context.canonical_url.count("-"),
        "host_hyphen_count": host.count("-"),
        "dot_count": context.canonical_url.count("."),
        "underscore_count": context.canonical_url.count("_"),
        "at_count": context.canonical_url.count("@"),
        "percent_escape_count": len(PERCENT_ESCAPE.findall(context.canonical_url)),
        "equals_count": context.canonical_url.count("="),
        "ampersand_count": context.canonical_url.count("&"),
        "non_alphanumeric_ratio": 1.0 - _ratio(alphanumeric_count, len(context.canonical_url)),
        "url_entropy": _entropy(url_lower),
        "host_entropy": _entropy(host),
        "token_count": len(tokens),
        "longest_token_length": max((len(token) for token in tokens), default=0),
        "suspicious_token_count": suspicious_count,
        "suspicious_token_ratio": _ratio(suspicious_count, len(tokens)),
        "has_ip_host": has_ip_host,
        "has_userinfo": float("@" in parsed.netloc),
        "has_nondefault_port": float(nondefault_port),
        "uses_https": float(parsed.scheme == "https"),
        "has_punycode": float(any(label.startswith("xn--") for label in host_labels)),
        "tld_length": len(host_labels[-1]) if host_labels else 0,
        "max_repeated_character_run": _max_run(url_lower),
        "path_has_file_extension": float(has_extension),
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}


def feature_matrix(rows: list[UrlFeatureContext]) -> np.ndarray:
    return np.asarray(
        [[extract_url_features(row)[name] for name in FEATURE_NAMES] for row in rows],
        dtype=np.float64,
    )
