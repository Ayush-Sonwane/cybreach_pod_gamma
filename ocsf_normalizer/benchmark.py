"""
Normalization benchmark: throughput and processing latency.

Loads the real SIEM fixtures (splunk/sentinel/ecs/qradar/logscale) and runs
batch normalization through ``BaseNormalizer.process_batch`` at configurable
sizes, printing a throughput (events/sec) and latency (ms) report suitable for
performance demonstrations.

Usage (from the repo root):

    python ocsf_normalizer/benchmark.py [--sizes 112 560 1120] [--reps 3]

Worker count comes from the OCSF_POOL_WORKERS env var (default: CPU count),
mirroring the API startup pool.
"""

import argparse
import json
import os
import time
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, List

from src.normalizer.base import BaseNormalizer, _worker_init

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "fixtures")
VENDORS = ["splunk", "sentinel", "ecs", "qradar", "logscale"]


def load_events() -> List[Dict]:
    events = []
    for vendor in VENDORS:
        path = os.path.join(FIXTURES_DIR, f"{vendor}_events.json")
        with open(path, encoding="utf-8") as f:
            events.extend(json.load(f))
    return events


def run_batch(pool: ProcessPoolExecutor, batch: List[Dict]) -> Dict:
    start = time.perf_counter()
    result = BaseNormalizer().process_batch(batch, pool)
    duration_ms = (time.perf_counter() - start) * 1000
    return {
        "size": result["total"],
        "succeeded": result["success_count"],
        "failed": result["failure_count"],
        "duration_ms": round(duration_ms, 3),
        "throughput_events_per_sec": round(result["total"] / (duration_ms / 1000), 1),
        "avg_ms_per_event": round(duration_ms / max(result["total"], 1), 3),
    }


def run_single_baseline(events: List[Dict]) -> Dict:
    normalizer = BaseNormalizer()
    latencies = []
    for raw in events:
        start = time.perf_counter()
        normalizer.process_log(raw)
        latencies.append((time.perf_counter() - start) * 1000)
    latencies.sort()
    return {
        "size": len(latencies),
        "min_ms": round(latencies[0], 3),
        "avg_ms": round(sum(latencies) / len(latencies), 3),
        "max_ms": round(latencies[-1], 3),
        "p95_ms": round(latencies[max(1, int(0.95 * len(latencies))) - 1], 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes", type=int, nargs="*", default=None,
        help="Batch sizes to benchmark (default: 1x, 5x, 10x the fixture count)",
    )
    parser.add_argument("--reps", type=int, default=3, help="Repetitions per size")
    args = parser.parse_args()

    events = load_events()
    n = len(events)
    sizes = args.sizes or [n, n * 5, n * 10]
    workers = int(os.getenv("OCSF_POOL_WORKERS", os.cpu_count() or 1))

    print(f"fixtures loaded: {n} events ({', '.join(VENDORS)})")
    print(f"workers: {workers}")

    single = run_single_baseline(events)
    print("\nsingle-event baseline (in-process, sequential):")
    print(f"  size={single['size']} min={single['min_ms']}ms "
          f"avg={single['avg_ms']}ms max={single['max_ms']}ms "
          f"p95={single['p95_ms']}ms")

    with ProcessPoolExecutor(max_workers=workers, initializer=_worker_init) as pool:
        report = {"pool_workers": workers, "batches": {}}
        for size in sizes:
            batch = (events * (size // n + 1))[:size]
            runs = [run_batch(pool, batch) for _ in range(args.reps)]
            report["batches"][str(size)] = runs
            best = min(runs, key=lambda r: r["duration_ms"])
            print(
                f"\nbatch size {size}: {args.reps} runs | best: "
                f"duration={best['duration_ms']}ms "
                f"throughput={best['throughput_events_per_sec']} ev/sec "
                f"avg={best['avg_ms_per_event']}ms/event "
                f"(success={best['succeeded']}/{best['size']}, "
                f"failed={best['failed']})"
            )

    print("\nreport (json):")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
