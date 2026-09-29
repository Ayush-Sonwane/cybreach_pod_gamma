"""
Normalization benchmark: throughput and processing latency.

Loads the real SIEM fixtures (splunk/sentinel/ecs/qradar/logscale) and runs
batch normalization through ``BaseNormalizer.process_batch`` at configurable
sizes, printing a throughput (events/sec) and latency (ms) report suitable for
performance demonstrations.

Throughput and latency are reported both for the mixed multi-vendor feed and
per SIEM platform adapter (splunk, sentinel, ecs, qradar, logscale) so the
normalizer's per-adapter EPS can be compared directly.

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


def load_events_by_vendor() -> Dict[str, List[Dict]]:
    by_vendor = {}
    for vendor in VENDORS:
        path = os.path.join(FIXTURES_DIR, f"{vendor}_events.json")
        with open(path, encoding="utf-8") as f:
            by_vendor[vendor] = json.load(f)
    return by_vendor


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
    by_vendor = load_events_by_vendor()
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

        report["per_vendor"] = {}
        per_vendor_size = sizes[0]
        print(f"\nper-vendor batch throughput at size {per_vendor_size} (best of runs):")
        for vendor in VENDORS:
            v_events = by_vendor[vendor]
            v_batch = (v_events * (per_vendor_size // max(len(v_events), 1) + 1))[:per_vendor_size]
            v_runs = [run_batch(pool, v_batch) for _ in range(args.reps)]
            report["per_vendor"][vendor] = v_runs
            best = min(v_runs, key=lambda r: r["duration_ms"])
            print(
                f"  {vendor:9s} n={best['size']:4d} "
                f"throughput={best['throughput_events_per_sec']:8.1f} ev/sec "
                f"avg={best['avg_ms_per_event']:.3f} ms/event "
                f"(success={best['succeeded']}/{best['size']}, "
                f"failed={best['failed']})"
            )

        report["per_vendor_latency"] = {}
        print("\nper-vendor single-event latency (in-process, sequential):")
        for vendor in VENDORS:
            s = run_single_baseline(by_vendor[vendor])
            report["per_vendor_latency"][vendor] = s
            print(
                f"  {vendor:9s} n={s['size']:4d} min={s['min_ms']}ms "
                f"avg={s['avg_ms']}ms max={s['max_ms']}ms p95={s['p95_ms']}ms"
            )

    print("\nreport (json):")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()