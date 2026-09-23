import json
import os
from pathlib import Path

# Define root target directory (creates contracts/ if it does not exist)
OUTPUT_DIR = Path(__file__).parent / "contracts"
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