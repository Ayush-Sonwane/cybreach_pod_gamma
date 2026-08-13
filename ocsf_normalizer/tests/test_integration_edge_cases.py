import pytest
from src.transformer import FieldTransformer
from src.adapters.splunk_adapter import SplunkAdapter
from src.adapters.qradar_adapter import QRadarAdapter
from src.adapters.asim_adapter import ASIMAdapter
from src.adapters.ecs_adapter import ECSAdapter
from src.adapters.logscale_adapter import LogScaleAdapter

ADAPTERS = [
    ("splunk", SplunkAdapter()),
    ("qradar", QRadarAdapter()),
    ("asim", ASIMAdapter()),
    ("ecs", ECSAdapter()),
    ("logscale", LogScaleAdapter()),
]

# ==============================================================================
# 1. MISSING FIELDS & NULL VALUES
# ==============================================================================
class TestMissingAndNullFields:

    @pytest.mark.parametrize("vendor,adapter", ADAPTERS)
    def test_completely_empty_payload(self, vendor, adapter):
        """Pipeline should handle empty payload without KeyError/AttributeError."""
        raw = {}
        transformed = FieldTransformer.transform(vendor, raw)
        event = adapter.normalize(transformed)
        
        assert event is not None
        # Safely handle both dict objects and Pydantic/dataclass models
        user_val = event.get("user") if isinstance(event, dict) else getattr(event, "user", None)
        assert user_val is None or getattr(user_val, "name", None) is None

    @pytest.mark.parametrize("vendor,adapter", ADAPTERS)
    def test_explicit_null_values(self, vendor, adapter):
        """Pipeline should handle explicit None values for mandatory/optional fields."""
        raw = {
            "sourceip": None,
            "destinationip": None,
            "sourceport": None,
            "username": None,
            "magnitude": None,
            "starttime": None,
        }
        transformed = FieldTransformer.transform(vendor, raw)
        event = adapter.normalize(transformed)
        
        assert event is not None


# ==============================================================================
# 2. UNEXPECTED DATA TYPES (TYPE COERCION)
# ==============================================================================
class TestUnexpectedDataTypes:

    def test_string_port_coercion(self):
        """FieldTransformer should coerce string ports to integers."""
        raw = {"sourceport": "443", "destinationport": "8080"}
        transformed = FieldTransformer.transform("qradar", raw)
        
        assert isinstance(transformed.get("src_port"), int)
        assert transformed["src_port"] == 443

    def test_invalid_type_graceful_fallback(self):
        """Non-numeric string for an integer field should pass through without crashing."""
        raw = {"sourceport": "invalid_port_number"}
        transformed = FieldTransformer.transform("qradar", raw)
        
        # Ensures transformation doesn't raise an unhandled Exception on invalid types
        assert "src_port" in transformed


# ==============================================================================
# 3. EDGE-CASE SCENARIOS & ENUM MAPPING
# ==============================================================================
class TestEdgeCasesAndEnums:

    def test_unrecognized_enumeration(self):
        """Unknown vendor severity strings should fall back or retain raw value without crashing."""
        raw = {"magnitude": "ULTRA_CRITICAL_UNKNOWN_VENDOR_LEVEL"}
        transformed = FieldTransformer.transform("qradar", raw)
        
        assert transformed is not None

    def test_malformed_timestamp_formats(self):
        """Handles unexpected date format strings gracefully."""
        raw = {"starttime": "NOT_A_DATE"}
        transformed = FieldTransformer.transform("qradar", raw)
        
        assert transformed is not None