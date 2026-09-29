#!/usr/bin/env python3
"""
PhishGuard Load and Concurrency Benchmarking Suite
Simulates parallel API requests to measure throughput, latency percentiles (P50, P95, P99), and success rates.
"""

import argparse
import asyncio
import time
import sys
from pathlib import Path
import numpy as np

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from phishguard_orchestrator.engine import AdaptivePolicy, decide_next
from phishguard_api.inference import predict_m0

SAMPLE_URLS = [
    "https://paypal.com-security-check.login-verify.com/login.php",
    "https://google.com",
    "https://bankofamerica.secure-verify-account.net/auth",
    "https://github.com",
    "https://chase-update-information.com/signin",
    "https://microsoft.com",
    "https://amazon-account-alert.support-online.org/login",
    "https://wikipedia.org",
    "https://netflix-billing-update.com/user",
    "https://apple.com"
]

async def simulate_single_request(request_id: int, sem: asyncio.Semaphore) -> dict:
    async with sem:
        start_time = time.perf_counter()
        url = SAMPLE_URLS[request_id % len(SAMPLE_URLS)]
        
        try:
            # Stage M0 Lexical Inference
            prob = predict_m0(url)
            
            # Stage M5 Orchestration Decision
            policy = AdaptivePolicy()
            action, reason, confidence, uncertainty = decide_next(
                prob, ("url",), policy, step=1
            )
            
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                "request_id": request_id,
                "status": "success",
                "latency_ms": elapsed_ms,
                "probability": prob,
                "action": action,
                "uncertainty": uncertainty
            }
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                "request_id": request_id,
                "status": "failed",
                "latency_ms": elapsed_ms,
                "error": str(exc)
            }

async def run_load_test(concurrency: int, total_requests: int):
    print(f"=" * 60)
    print(f"PhishGuard Load Test Benchmark")
    print(f"Concurrency: {concurrency} workers | Total Requests: {total_requests}")
    print(f"=" * 60)
    
    sem = asyncio.Semaphore(concurrency)
    start_total = time.perf_counter()
    
    tasks = [simulate_single_request(i, sem) for i in range(total_requests)]
    results = await asyncio.gather(*tasks)
    
    total_elapsed_sec = time.perf_counter() - start_total
    
    successful = [r for r in results if r["status"] == "success"]
    failed = [r for r in results if r["status"] == "failed"]
    
    latencies = np.array([r["latency_ms"] for r in results])
    
    p50 = np.percentile(latencies, 50)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    throughput = total_requests / total_elapsed_sec
    
    print("\n--- BENCHMARK RESULTS ---")
    print(f"Total Time Elapsed:    {total_elapsed_sec:.4f} seconds")
    print(f"Throughput:            {throughput:.2f} req/sec")
    print(f"Successful Requests:   {len(successful)} ({len(successful)/total_requests:.1%})")
    print(f"Failed Requests:       {len(failed)} ({len(failed)/total_requests:.1%})")
    print(f"Mean Latency:          {np.mean(latencies):.3f} ms")
    print(f"P50 Latency:           {p50:.3f} ms")
    print(f"P95 Latency:           {p95:.3f} ms")
    print(f"P99 Latency:           {p99:.3f} ms")
    print(f"Min / Max Latency:     {np.min(latencies):.3f} ms / {np.max(latencies):.3f} ms")
    print(f"=" * 60)

def main():
    parser = argparse.ArgumentParser(description="PhishGuard Load Testing Script")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent request workers")
    parser.add_argument("--total-requests", type=int, default=100, help="Total number of requests to issue")
    args = parser.parse_args()
    
    asyncio.run(run_load_test(args.concurrency, args.total_requests))

if __name__ == "__main__":
    main()
