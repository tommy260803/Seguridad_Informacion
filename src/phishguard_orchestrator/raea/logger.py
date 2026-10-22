from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from phishguard_orchestrator.raea.models import RAEAExecutionResult


class DecisionLogger:
    """Registrador estructurado de decisiones RAEA-Phish para auditabilidad científica."""

    def __init__(self, log_dir: Path | None = None):
        self.log_dir = log_dir or Path("artifacts/raea/logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.in_memory_logs: List[Dict[str, Any]] = []

    def log_execution(self, url: str, result: RAEAExecutionResult, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
        entry = {
            "url": url,
            "decision": result.decision,
            "probability_phishing": result.probability_phishing,
            "modalities_consulted": list(result.modalities_consulted),
            "total_cost": result.total_cost,
            "abstained": result.abstained,
            "transitions": [t.to_dict() for t in result.transitions],
            "metadata": metadata or {},
        }
        self.in_memory_logs.append(entry)
        return entry

    def flush_to_jsonl(self, filename: str = "raea_decisions.jsonl") -> Path:
        out_path = self.log_dir / filename
        with open(out_path, "a", encoding="utf-8") as f:
            for entry in self.in_memory_logs:
                f.write(json.dumps(entry) + "\n")
        self.in_memory_logs.clear()
        return out_path
