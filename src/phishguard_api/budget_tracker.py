from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModalityExecutionRecord:
    modality: str
    latency_ms: float
    cost_units: float
    llm_prompt_tokens: int = 0
    llm_completion_tokens: int = 0
    llm_model: str = ""
    estimated_usd: float = 0.0


class ExecutionBudgetTracker:
    """
    Rastreador determinista de costos computacionales, latencia y consumo de tokens LLM
    para la instrumentación empírica del proceso de decisión secuencial (MDP).
    """

    # Tarifas estimadas por 1M tokens (ej. Gemini 1.5 Flash)
    USD_PER_MILLION_PROMPT = 0.075
    USD_PER_MILLION_COMPLETION = 0.300

    def __init__(self, initial_budget_units: float = 3.0):
        self.initial_budget_units = initial_budget_units
        self.records: dict[str, ModalityExecutionRecord] = {}
        self._start_times: dict[str, float] = {}

    def start_modality(self, modality: str) -> None:
        self._start_times[modality] = time.perf_counter()

    def finish_modality(
        self,
        modality: str,
        cost_units: float = 1.0,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        model_name: str = "",
    ) -> ModalityExecutionRecord:
        start = self._start_times.get(modality, time.perf_counter())
        latency_ms = (time.perf_counter() - start) * 1000.0

        usd_prompt = (prompt_tokens / 1_000_000.0) * self.USD_PER_MILLION_PROMPT
        usd_completion = (completion_tokens / 1_000_000.0) * self.USD_PER_MILLION_COMPLETION
        total_usd = round(usd_prompt + usd_completion, 7)

        rec = ModalityExecutionRecord(
            modality=modality,
            latency_ms=round(latency_ms, 2),
            cost_units=cost_units,
            llm_prompt_tokens=prompt_tokens,
            llm_completion_tokens=completion_tokens,
            llm_model=model_name,
            estimated_usd=total_usd,
        )
        self.records[modality] = rec
        return rec

    def summary(self) -> dict[str, Any]:
        total_units = sum(r.cost_units for r in self.records.values())
        total_latency = sum(r.latency_ms for r in self.records.values())
        total_tokens = sum(r.llm_prompt_tokens + r.llm_completion_tokens for r in self.records.values())
        total_usd = sum(r.estimated_usd for r in self.records.values())

        return {
            "initial_budget_units": self.initial_budget_units,
            "spent_budget_units": round(total_units, 2),
            "remaining_budget_units": max(0.0, round(self.initial_budget_units - total_units, 2)),
            "total_latency_ms": round(total_latency, 2),
            "total_llm_tokens": total_tokens,
            "total_estimated_usd": round(total_usd, 7),
            "modalities": {
                name: {
                    "latency_ms": rec.latency_ms,
                    "cost_units": rec.cost_units,
                    "tokens": rec.llm_prompt_tokens + rec.llm_completion_tokens,
                    "estimated_usd": rec.estimated_usd,
                }
                for name, rec in self.records.items()
            },
        }
