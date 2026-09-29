"""
Prometheus Observability Metrics Exporter for PhishGuard.
Tracks throughput, latencies by stage, cache hit ratios, and worker states
in standard Prometheus/OpenMetrics text format without requiring heavy external dependencies.
"""

from __future__ import annotations

import time
import threading
from typing import Dict

class MetricsCollector:
    """Thread-safe Prometheus metric registry and formatter."""

    def __init__(self):
        self._lock = threading.Lock()
        self.requests_total: Dict[str, int] = {
            "completed_url": 0,
            "completed_infrastructure": 0,
            "completed_content": 0,
            "completed_visual": 0,
            "completed_cache": 0,
            "completed_bloom": 0,
            "failed": 0
        }
        self.stage_latency_sum: Dict[str, float] = {
            "url": 0.0,
            "infrastructure": 0.0,
            "content": 0.0,
            "visual": 0.0,
            "total": 0.0
        }
        self.stage_latency_count: Dict[str, int] = {
            "url": 0,
            "infrastructure": 0,
            "content": 0,
            "visual": 0,
            "total": 0
        }
        self.active_jobs = 0

    def record_job_completed(self, exit_stage: str, latency_ms: float):
        key = f"completed_{exit_stage.lower()}"
        with self._lock:
            if key in self.requests_total:
                self.requests_total[key] += 1
            else:
                self.requests_total["completed_url"] += 1

            self.stage_latency_sum["total"] += (latency_ms / 1000.0)
            self.stage_latency_count["total"] += 1

    def record_job_failed(self):
        with self._lock:
            self.requests_total["failed"] += 1

    def record_stage_latency(self, stage: str, latency_ms: float):
        with self._lock:
            if stage in self.stage_latency_sum:
                self.stage_latency_sum[stage] += (latency_ms / 1000.0)
                self.stage_latency_count[stage] += 1

    def inc_active_jobs(self):
        with self._lock:
            self.active_jobs += 1

    def dec_active_jobs(self):
        with self._lock:
            self.active_jobs = max(0, self.active_jobs - 1)

    def export_prometheus_text(self) -> str:
        """Formats collected metrics according to Prometheus OpenMetrics text format."""
        from phishguard_api.cache import decision_cache

        cache_stats = decision_cache.stats()
        lines = []

        # HELP and TYPE for requests_total
        lines.append("# HELP phishguard_requests_total Total number of analysis jobs processed")
        lines.append("# TYPE phishguard_requests_total counter")
        with self._lock:
            for key, count in self.requests_total.items():
                if key == "failed":
                    lines.append(f'phishguard_requests_total{{status="failed",exit_stage="none"}} {count}')
                else:
                    stage = key.replace("completed_", "")
                    lines.append(f'phishguard_requests_total{{status="success",exit_stage="{stage}"}} {count}')

        # Latency metrics
        lines.append("# HELP phishguard_request_duration_seconds Latency of analysis stages in seconds")
        lines.append("# TYPE phishguard_request_duration_seconds summary")
        with self._lock:
            for stage in self.stage_latency_sum:
                s = self.stage_latency_sum[stage]
                c = self.stage_latency_count[stage]
                lines.append(f'phishguard_request_duration_seconds_sum{{stage="{stage}"}} {s:.6f}')
                lines.append(f'phishguard_request_duration_seconds_count{{stage="{stage}"}} {c}')

        # Active jobs gauge
        lines.append("# HELP phishguard_active_jobs Number of currently running analysis jobs")
        lines.append("# TYPE phishguard_active_jobs gauge")
        with self._lock:
            lines.append(f"phishguard_active_jobs {self.active_jobs}")

        # Cache metrics
        lines.append("# HELP phishguard_cache_hits_total Number of cache hits")
        lines.append("# TYPE phishguard_cache_hits_total counter")
        lines.append(f"phishguard_cache_hits_total {cache_stats['hits']}")

        lines.append("# HELP phishguard_cache_misses_total Number of cache misses")
        lines.append("# TYPE phishguard_cache_misses_total counter")
        lines.append(f"phishguard_cache_misses_total {cache_stats['misses']}")

        lines.append("# HELP phishguard_cache_size Current number of items in decision cache")
        lines.append("# TYPE phishguard_cache_size gauge")
        lines.append(f"phishguard_cache_size {cache_stats['size']}")

        return "\n".join(lines) + "\n"

# Global singleton
metrics = MetricsCollector()
