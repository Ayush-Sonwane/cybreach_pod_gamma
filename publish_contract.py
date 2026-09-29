"""
Publishes the frozen OCSF normalized-event schema contract.

Writes `ocsf_normalizer_schema.v1.json` (JSON Schema Draft-07) into the
workspace's shared `contracts/` directory.

M5: the five topic names and the verdict event schema used to live in
hand-written copies scattered across the pods, with nothing reading them
cross-pod. The plan (Week 1) asks for ONE contract registry at the workspace
root that every pod publishes to and every contract test loads from. This
script now targets that root `contracts/` directory instead of a pod-local
`cybreach_pod_gamma/contracts/`. Set `M2_CONTRACTS_PATH` to point elsewhere
(used by tests); the default is the sibling `contracts/` of the workspace root.
"""
import json
import os
from pathlib import Path

# The shared registry. Defaults to <workspace-root>/contracts, two levels up
# from this file (pod root -> workspace root), so the canonical copy is the one
# the contract tests read.
CONTRACTS_DIR = os.getenv(
    "M2_CONTRACTS_PATH",
    str(Path(__file__).resolve().parent.parent / "contracts"),
)
OUTPUT_DIR = Path(CONTRACTS_DIR)
OUTPUT_FILE = OUTPUT_DIR / "ocsf_normalizer_schema.v1.json"

# Valid JSON Schema Draft-07 for OCSF Normalized Event Output
OCSF_SCHEMA_CONTRACT = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "OCSFNormalizedEvent",
    "type": "object",
    "required": ["class_uid", "category_uid", "severity_id", "time", "metadata"],
    "properties": {
        "class_uid": {"type": "integer", "description": "OCSF Event Class ID"},
        "category_uid": {"type": "integer", "description": "OCSF Category ID"},
        "severity_id": {"type": "integer", "minimum": 0, "maximum": 6},
        "time": {"type": "string", "format": "date-time"},
        "metadata": {
            "type": "object",
            "properties": {
                "version": {"type": "string"},
                "product": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "vendor_name": {"type": "string"}
                    }
                }
            }
        },
        "observables": {
            "type": "array",
            "items": {"type": "object"}
        }
    }
}

def publish():
    # Ensure directory exists before writing
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(OCSF_SCHEMA_CONTRACT, f, indent=2)
    print(f"[+] Successfully published OCSF Schema contract to '{OUTPUT_FILE}'")

if __name__ == "__main__":
    publish()