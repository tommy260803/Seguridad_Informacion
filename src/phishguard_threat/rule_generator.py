from __future__ import annotations

import datetime
import re
import uuid
from typing import Any
from urllib.parse import urlsplit


class ThreatRuleGenerator:
    """
    Genera reglas de detección estándar para centros de operaciones de seguridad (SOC)
    en formatos Sigma (SIEMs: Splunk, Elastic, QRadar) y YARA-L (Google Chronicle SecOps).
    """

    @staticmethod
    def generate_sigma_rule(
        job_id: str,
        url: str,
        probability: float,
        brand_name: str | None = None,
        resolved_ips: list[str] | None = None,
    ) -> str:
        """
        Genera una regla Sigma YAML para interceptar tráfico hacia el indicador malicioso.
        """
        parsed = urlsplit(url)
        domain = (parsed.hostname or url).lower()
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"sigma-{job_id}-{domain}"))
        now_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        ips = resolved_ips or []
        level = "critical" if probability >= 0.85 else "high" if probability >= 0.50 else "medium"

        lines = [
            f"title: PhishGuard Malicious Phishing Indicator - {domain}",
            f"id: {rule_id}",
            "status: experimental",
            f"description: Detects outbound communication with phishing domain identified by PhishGuard (Probability: {probability:.1%})" + (f" targeting brand {brand_name}" if brand_name else ""),
            "references:",
            f"    - https://phishguard.security.local/analyses/{job_id}",
            "author: PhishGuard Automated Threat Intelligence Pipeline",
            f"date: {now_date}",
            "tags:",
            "    - attack.initial_access",
            "    - attack.t1566.002",
            "    - attack.credential_access",
            "logsource:",
            "    category: proxy",
            "    product: zeek",
            "detection:",
            "    selection_web:",
            "        c-uri|contains:",
            f"            - '{domain}'",
        ]

        if ips:
            lines.append("    selection_ip:")
            lines.append("        dst_ip:")
            for ip in ips:
                lines.append(f"            - '{ip}'")
            lines.append("    condition: selection_web or selection_ip")
        else:
            lines.append("    condition: selection_web")

        lines.extend([
            "falsepositives:",
            "    - Internal security scanners",
            "    - Sandboxed research environments",
            f"level: {level}",
        ])
        return "\n".join(lines) + "\n"

    @staticmethod
    def generate_yaral_rule(
        job_id: str,
        url: str,
        probability: float,
        brand_name: str | None = None,
        resolved_ips: list[str] | None = None,
    ) -> str:
        """
        Genera una regla YARA-L 2.0 compatible con Google Chronicle SecOps.
        """
        parsed = urlsplit(url)
        domain = (parsed.hostname or url).lower()
        clean_rule_name = re.sub(r"[^a-zA-Z0-9_]", "_", f"phishguard_ioc_{domain}")
        clean_rule_name = re.sub(r"_+", "_", clean_rule_name).strip("_")
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        severity = "CRITICAL" if probability >= 0.85 else "HIGH" if probability >= 0.50 else "MEDIUM"
        ips = resolved_ips or []

        rule = f"""rule {clean_rule_name} {{
  meta:
    author = "PhishGuard Threat Intelligence Generator"
    description = "Matches telemetry events contacting detected phishing indicator {domain}"
    job_id = "{job_id}"
    phishing_probability = "{probability:.2f}"
    targeted_brand = "{brand_name or 'unspecified'}"
    severity = "{severity}"
    generated_at = "{now_iso}"
    mitre_attack = "T1566.002"

  events:
    $net.metadata.event_type = "NETWORK_CONNECTION"
    (
      $net.target.hostname = "{domain}"
"""
        for ip in ips:
            rule += f'      or $net.target.ip = "{ip}"\n'
        rule += """    )

  condition:
    $net
}
"""
        return rule
