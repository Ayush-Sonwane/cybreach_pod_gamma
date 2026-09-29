# run_tests.py
"""Run both Gamma test suites.

Gamma's two services each export a top-level package named `src`, so they
cannot be collected in a single pytest process -- whichever lands on sys.path
first shadows the other, and the second suite fails to import with
`ModuleNotFoundError: No module named 'src'`.

Running them from their own directories is what makes each suite importable.
This script does that for both, so a single command covers the whole pod.

    python run_tests.py            # both suites
    python run_tests.py -k NoData  # extra args are forwarded to pytest
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

SUITES = (
    "ocsf_normalizer",
    "revalidation_service",
)


def main(argv: list[str]) -> int:
    failed = []

    for suite in SUITES:
        print(f"\n{'=' * 70}\n== {suite}\n{'=' * 70}", flush=True)

        result = subprocess.run(
            [sys.executable, "-m", "pytest", *argv],
            cwd=REPO_ROOT / suite,
        )

        if result.returncode != 0:
            failed.append(suite)

    print(f"\n{'=' * 70}")

    if failed:
        print(f"FAILED: {', '.join(failed)}")
        return 1

    print("All Gamma suites passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
