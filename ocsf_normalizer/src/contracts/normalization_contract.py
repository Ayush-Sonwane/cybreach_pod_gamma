"""
Inter-pod normalization contract (Pod Gamma).

Defines the *guaranteed* shape of a normalized OCSF event produced by the
OCSF Normalizer, and the validation functions other pods (notably the
Re-Validation Service) can import to consume normalizer output safely.

This contract is intentionally platform-agnostic and versioned so that
downstream consumers are insulated from per-SIEM normalization details.

Contract version under test: 1.1.0
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict

from src.schema.ocsf_schema import OCSFSchemaRegistry, DEFAULT as DEFAULT_REGISTRY
from src.validator import OCSFValidator
from src.provenance_validator import ProvenanceValidator


# ---------------------------------------------------------------------------
# Typed structural contract
# ---------------------------------------------------------------------------

class ProvenanceEntry(TypedDict):
    """A single field-level lineage mapping (raw -> OCSF)."""
    ocsf_field: str
    raw_field: str


class ProductInfo(TypedDict):
    """Vendor/product descriptor attached to every normalized event."""
    name: str
    vendor_name: str


class Metadata(TypedDict):
    """Envelope metadata carried on every normalized event."""
    version: str
    product: ProductInfo
    provenance: List[ProvenanceEntry]


class NormalizedOCSFEvent(TypedDict, total=False):
    """The canonical output of the OCSF Normalizer (inter-pod contract)."""
    class_uid: int
    category_uid: int
    activity_id: int
    severity_id: int
    status_id: int
    time: int
    message: Optional[str]
    metadata: Metadata
    user: Optional[Dict[str, Any]]
    actor: Optional[Dict[str, Any]]
    src_endpoint: Optional[Dict[str, Any]]
    dst_endpoint: Optional[Dict[str, Any]]
    file: Optional[Dict[str, Any]]
    process: Optional[Dict[str, Any]]
    device: Optional[Dict[str, Any]]
    unmapped: Optional[Dict[str, Any]]


class ValidationResult(TypedDict):
    """Contract-validation result returned to downstream consumers."""
    is_valid: bool
    errors: List[str]


# ---------------------------------------------------------------------------
# Contract validation
# ---------------------------------------------------------------------------

class NormalizationContractValidator:
    """
    Validates that an event meets the inter-pod normalization contract.

    Combines core OCSF schema validation, metadata/provenance validation, and
    provenance integrity checks into a single portable entry point that other
    pods (e.g. the Re-Validation Service) can depend on.
    """

    def __init__(
        self,
        registry: Optional[OCSFSchemaRegistry] = None,
        strict_raw_fields: bool = False,
    ):
        self.registry = registry or DEFAULT_REGISTRY
        self.provenance_validator = ProvenanceValidator(
            registry=self.registry,
            strict_raw_fields=strict_raw_fields,
        )

    def validate_event(
        self, ocsf_event: Dict[str, Any], raw_event: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate a normalized event against the inter-pod contract.

        Args:
            ocsf_event: the normalized OCSF event dict.
            raw_event:  optional original vendor payload (required only when
                        ``strict_raw_fields`` is enabled).

        Returns:
            {"is_valid": bool, "errors": List[str]}
        """
        errors: List[str] = []

        # 1. Core OCSF schema compliance
        is_valid, ocsf_errors = OCSFValidator.validate_event(
            ocsf_event, registry=self.registry
        )
        if not is_valid:
            errors.extend(ocsf_errors)

        # 2. metadata structure (version, product, provenance)
        is_valid, meta_errors = OCSFValidator.validate_metadata(
            ocsf_event, registry=self.registry
        )
        if not is_valid:
            errors.extend(meta_errors)

        # 3. Provenance integrity
        is_valid, prov_errors = self.provenance_validator.validate(
            ocsf_event, raw_event
        )
        if not is_valid:
            errors.extend(prov_errors)

        return {"is_valid": len(errors) == 0, "errors": errors}


# Module-level convenience singleton (platform-agnostic, non-strict)
DEFAULT_CONTRACT_VALIDATOR = NormalizationContractValidator()
