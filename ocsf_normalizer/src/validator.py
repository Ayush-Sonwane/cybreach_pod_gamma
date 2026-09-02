"""
OCSF schema validation driven by the declarative OCSFSchemaRegistry.

The registry (``src/schema/ocsf_schema.py``) is the single source of truth for
field types, enum ranges, complex-object schemas, and class-specific rules.
This validator walks that registry instead of relying on hardcoded if/elif
checks, so adding a new event class does not require code changes here.

Backward compatibility is preserved:
* ``validate_event()`` keeps the mandatory-field, timestamp-type, complex-object
  and class-rule checks that existing callers depend on, and now also applies
  registry-driven enum/range constraints.
* ``validate_metadata()`` is a distinct, opt-in check so events produced
  without a ``metadata`` block (legacy callers) still pass the core validator.
* Both core methods remain ``@classmethod`` so ``OCSFValidator.validate_event()``
  callers (and the FastAPI app) keep working without instantiating.
"""

from typing import Any, Dict, List, Optional, Tuple

from src.schema.ocsf_schema import OCSFSchemaRegistry, DEFAULT as DEFAULT_REGISTRY


class OCSFValidator:
    """
    Validates normalized JSON payloads against core OCSF schema requirements,
    including complex object (endpoint, user, file, process, device) validation
    and declarative enum/range constraints sourced from the schema registry.
    """

    # Core mandatory fields required across all OCSF event classes
    MANDATORY_BASE_FIELDS = ["class_uid", "category_uid", "time"]

    # Complex object fields that should be dictionaries when present
    COMPLEX_OBJECT_FIELDS = [
        "user",
        "actor",
        "src_endpoint",
        "dst_endpoint",
        "file",
        "process",
        "device",
    ]

    # Class-level schema registry (used by @classmethod calls)
    _registry = DEFAULT_REGISTRY

    def __init__(self, registry: Optional[OCSFSchemaRegistry] = None):
        # Per-instance registry; classmethod calls fall back to class default.
        self._registry = registry or self._registry

    def _get_registry(self) -> OCSFSchemaRegistry:
        return self._registry

    @classmethod
    def validate_event(
        cls,
        ocsf_event: Dict[str, Any],
        registry: Optional[OCSFSchemaRegistry] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validates an OCSF event dictionary against the schema registry.

        Args:
            ocsf_event: the OCSF event dict.
            registry:   optional registry override.  Defaults to the class
                        registry (``OCSFValidator._registry``).  A custom
                        registry MUST be passed here explicitly — because
                        ``validate_event`` is a classmethod, per-instance
                        registries set in ``__init__`` are not seen by calls
                        made through an instance.

        Returns:
            (is_valid: bool, errors: List[str])
        """
        registry = registry or cls._registry
        errors: List[str] = []

        # 1. Check top-level mandatory OCSF fields
        for field in cls.MANDATORY_BASE_FIELDS:
            if field not in ocsf_event or ocsf_event[field] is None:
                errors.append(f"Missing mandatory OCSF field: '{field}'")
                continue

            # 2a. Apply registry-driven type/range/enum constraints
            spec = registry.get_base_field_spec(field)
            if spec:
                err = registry.validate_field_value(field, ocsf_event[field], spec)
                if err:
                    errors.append(err)

        # 2b. Validate optional scalar base fields against the registry
        for field, spec in registry.base_fields.items():
            if field in cls.MANDATORY_BASE_FIELDS:
                continue
            value = ocsf_event.get(field)
            if value is None:
                continue
            err = registry.validate_field_value(field, value, spec)
            if err:
                errors.append(err)

        # 3. Validate complex objects
        for field in cls.COMPLEX_OBJECT_FIELDS:
            value = ocsf_event.get(field)
            if value is None:
                continue
            errors.extend(registry.validate_complex_object(field, value))

        # 4. Class-specific validation rules (sourced from registry)
        errors.extend(registry.validate_class_rules(ocsf_event))

        # 5. Final Verdict
        is_valid = len(errors) == 0
        return is_valid, errors

    @classmethod
    def validate_metadata(
        cls,
        ocsf_event: Dict[str, Any],
        registry: Optional[OCSFSchemaRegistry] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validate the optional ``metadata`` block (version, product, provenance)
        against ``METADATA_SCHEMA`` in the registry.

        Args:
            ocsf_event: the OCSF event dict.
            registry:   optional registry override (see ``validate_event``).

        Returns:
            (is_valid: bool, errors: List[str])
        """
        registry = registry or cls._registry
        errors: List[str] = []
        metadata = ocsf_event.get("metadata")
        if metadata is None:
            errors.append("Missing mandatory 'metadata' block")
            return False, errors
        errors.extend(registry.validate_metadata(metadata))
        is_valid = len(errors) == 0
        return is_valid, errors
