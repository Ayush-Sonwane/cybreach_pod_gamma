"""
Declarative OCSF Schema Registry (v1.1.0+)

Defines the canonical OCSF event structure as data, not code.  Every field,
type constraint, enum range, nested object schema, class-specific rule, and
provenance entry format lives here.  Both the normalizer and the revalidation
service import this single source of truth.

Design principles
-----------------
* **Data-driven**: validators walk the registry instead of hardcoded if/elif.
* **Platform-agnostic**: no SIEM-specific field names; provenance is validated
  structurally (``ocsf_field`` / ``raw_field`` are non-empty strings).
* **Extensible**: adding a new OCSF event class means adding a new entry to
  ``EVENT_CLASSES`` — no code changes required.
* **Portable**: plain Python dicts — no JSON-Schema dependency, no Pydantic
  dependency.  Other pods can ``import`` this directly or replicate the dict
  structure in their own language.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Primitive type helpers
# ---------------------------------------------------------------------------

_TYPES = {
    "int": int,
    "float": (int, float),
    "str": str,
    "bool": bool,
    "list": list,
    "dict": dict,
}


def _check_type(value: Any, expected: str) -> bool:
    """Return True if *value* matches the ``expected`` type name."""
    if expected not in _TYPES:
        return True  # unknown type spec — pass through
    return isinstance(value, _TYPES[expected])


# ---------------------------------------------------------------------------
# Field specification: { type, required, range?, enum?, nested? }
# ---------------------------------------------------------------------------

# Base scalar fields present on every OCSF event
BASE_FIELDS: Dict[str, Dict[str, Any]] = {
    "class_uid":     {"type": "int", "required": True},
    "category_uid":  {"type": "int", "required": True},
    "activity_id":   {"type": "int", "required": False, "default": 0},
    "severity_id":   {"type": "int", "required": False, "default": 1, "range": (1, 6)},
    "status_id":     {"type": "int", "required": False, "default": 99, "enum": [1, 2, 99]},
    "time":          {"type": "float", "required": True},
    "message":       {"type": "str", "required": False},
    "type_uid":      {"type": "int", "required": False},
    "type_name":     {"type": "str", "required": False},
}

# Complex (nested) object schemas — each key maps to a sub-schema
COMPLEX_OBJECTS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "user": {
        "name":       {"type": "str", "required": False},
        "uid":        {"type": "str", "required": False},
        "domain":     {"type": "str", "required": False},
        "type_id":    {"type": "int", "required": False},
        "email_addr": {"type": "str", "required": False},
        "org":        {"type": "str", "required": False},
    },
    "actor": {
        "user":       {"type": "dict", "required": False, "nested": "user"},
        "process":    {"type": "dict", "required": False, "nested": "process"},
        "session_uid": {"type": "str", "required": False},
        "type_id":    {"type": "int", "required": False},
    },
    "src_endpoint": {
        "name":       {"type": "str", "required": False},
        "uid":        {"type": "str", "required": False},
        "ip":         {"type": "str", "required": False},
        "port":       {"type": "float", "required": False},
        "hostname":   {"type": "str", "required": False},
        "domain":     {"type": "str", "required": False},
        "mac":        {"type": "str", "required": False},
        "type_id":    {"type": "int", "required": False},
    },
    "dst_endpoint": {
        "name":       {"type": "str", "required": False},
        "uid":        {"type": "str", "required": False},
        "ip":         {"type": "str", "required": False},
        "port":       {"type": "float", "required": False},
        "hostname":   {"type": "str", "required": False},
        "domain":     {"type": "str", "required": False},
        "mac":        {"type": "str", "required": False},
        "type_id":    {"type": "int", "required": False},
    },
    "file": {
        "name":        {"type": "str", "required": False},
        "path":        {"type": "str", "required": False},
        "size":        {"type": "int", "required": False},
        "uid":         {"type": "str", "required": False},
        "type_id":     {"type": "int", "required": False},
        "parent_folder": {"type": "str", "required": False},
    },
    "process": {
        "pid":         {"type": "int", "required": False},
        "name":        {"type": "str", "required": False},
        "path":        {"type": "str", "required": False},
        "cmd_line":    {"type": "str", "required": False},
        "created_time": {"type": "int", "required": False},
    },
    "device": {
        "name":        {"type": "str", "required": False},
        "uid":         {"type": "str", "required": False},
        "ip":          {"type": "str", "required": False},
        "port":        {"type": "int", "required": False},
        "hostname":    {"type": "str", "required": False},
        "domain":      {"type": "str", "required": False},
        "mac":         {"type": "str", "required": False},
        "type_id":     {"type": "int", "required": False},
    },
}

# Metadata sub-structure
METADATA_SCHEMA: Dict[str, Any] = {
    "version": {"type": "str", "required": True},
    "product": {
        "type": "dict",
        "required": True,
        "nested_schema": {
            "name":        {"type": "str", "required": True},
            "vendor_name": {"type": "str", "required": True},
        },
    },
    "provenance": {
        "type": "list",
        "required": True,
        "entry_schema": {
            "ocsf_field": {"type": "str", "required": True},
            "raw_field":  {"type": "str", "required": True},
        },
    },
}

# Per-event-class constraints (extensible — add new class UIDs here)
EVENT_CLASSES: Dict[int, Dict[str, Any]] = {
    3002: {
        "name": "Authentication",
        "category_uid": 3,
        "requires_any": ["user", "actor"],
    },
    4001: {
        "name": "Network Activity",
        "category_uid": 4,
        "requires_all": ["src_endpoint", "dst_endpoint"],
    },
}


# ---------------------------------------------------------------------------
# Public API — the schema registry object consumed by validators
# ---------------------------------------------------------------------------

class OCSFSchemaRegistry:
    """
    Single entry-point for OCSF schema definitions.

    Instantiate once (or use the module-level ``DEFAULT`` singleton) and pass
    to validators.  All state is read-only after construction.
    """

    def __init__(
        self,
        base_fields: Optional[Dict[str, Dict[str, Any]]] = None,
        complex_objects: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None,
        metadata_schema: Optional[Dict[str, Any]] = None,
        event_classes: Optional[Dict[int, Dict[str, Any]]] = None,
    ):
        # Copy the module-level defaults so each registry instance is
        # independent — mutating one instance's mappings must never leak
        # into the module singleton (DEFAULT) or other instances.
        self.base_fields = dict(base_fields) if base_fields is not None else dict(BASE_FIELDS)
        self.complex_objects = dict(complex_objects) if complex_objects is not None else dict(COMPLEX_OBJECTS)
        self.metadata_schema = dict(metadata_schema) if metadata_schema is not None else dict(METADATA_SCHEMA)
        self.event_classes = dict(event_classes) if event_classes is not None else dict(EVENT_CLASSES)

    # -- helpers used by validators ----------------------------------------

    def get_base_field_spec(self, field: str) -> Optional[Dict[str, Any]]:
        return self.base_fields.get(field)

    def get_complex_object_spec(self, object_name: str) -> Optional[Dict[str, Dict[str, Any]]]:
        return self.complex_objects.get(object_name)

    def get_event_class_spec(self, class_uid: int) -> Optional[Dict[str, Any]]:
        return self.event_classes.get(class_uid)

    def all_complex_object_names(self) -> List[str]:
        return list(self.complex_objects.keys())

    def validate_field_value(
        self, field: str, value: Any, spec: Dict[str, Any]
    ) -> Optional[str]:
        """
        Validate a single scalar value against its field spec.

        Returns an error string on failure, ``None`` on success.
        """
        expected_type = spec.get("type")
        if expected_type and value is not None and not _check_type(value, expected_type):
            return (
                f"Invalid '{field}': Expected {expected_type}, "
                f"got {type(value).__name__}"
            )

        if value is not None:
            rng = spec.get("range")
            if rng and isinstance(value, (int, float)):
                lo, hi = rng
                if not (lo <= value <= hi):
                    return (
                        f"Invalid '{field}': Value {value} out of range [{lo}, {hi}]"
                    )

            enum = spec.get("enum")
            if enum is not None and value not in enum:
                return (
                    f"Invalid '{field}': Value {value!r} not in allowed set {enum}"
                )

        return None

    def validate_complex_object(
        self, obj_name: str, obj_value: Any
    ) -> List[str]:
        """
        Validate a complex object (dict) against its nested schema.

        Returns a list of error strings (empty on success).
        """
        errors: List[str] = []
        if not isinstance(obj_value, dict):
            errors.append(
                f"Invalid '{obj_name}': Expected dict, got {type(obj_value).__name__}"
            )
            return errors

        spec = self.get_complex_object_spec(obj_name)
        if spec is None:
            return errors  # unknown object — no rules

        for sub_field, sub_spec in spec.items():
            sub_val = obj_value.get(sub_field)
            if sub_val is None:
                continue
            # Handle nested complex objects (e.g. actor.user → user schema)
            nested_name = sub_spec.get("nested")
            if nested_name and isinstance(sub_val, dict):
                errors.extend(self.validate_complex_object(nested_name, sub_val))
                continue
            err = self.validate_field_value(
                f"{obj_name}.{sub_field}", sub_val, sub_spec
            )
            if err:
                errors.append(err)

        return errors

    def validate_metadata(self, metadata: Any) -> List[str]:
        """
        Validate the ``metadata`` dict against ``METADATA_SCHEMA``.

        Returns a list of error strings (empty on success).
        """
        errors: List[str] = []
        if not isinstance(metadata, dict):
            errors.append(
                f"Invalid 'metadata': Expected dict, got {type(metadata).__name__}"
            )
            return errors

        for field, spec in self.metadata_schema.items():
            value = metadata.get(field)

            if spec.get("required") and value is None:
                errors.append(f"Missing mandatory metadata field: '{field}'")
                continue

            if value is None:
                continue

            expected_type = spec.get("type")
            if expected_type == "dict":
                if not isinstance(value, dict):
                    errors.append(
                        f"Invalid 'metadata.{field}': Expected dict, "
                        f"got {type(value).__name__}"
                    )
                    continue
                nested = spec.get("nested_schema", {})
                for sub_field, sub_spec in nested.items():
                    sub_val = value.get(sub_field)
                    if sub_spec.get("required") and sub_val is None:
                        errors.append(
                            f"Missing mandatory 'metadata.{field}.{sub_field}'"
                        )
                        continue
                    if sub_val is not None:
                        err = self.validate_field_value(
                            f"metadata.{field}.{sub_field}", sub_val, sub_spec
                        )
                        if err:
                            errors.append(err)

            elif expected_type == "list":
                if not isinstance(value, list):
                    errors.append(
                        f"Invalid 'metadata.{field}': Expected list, "
                        f"got {type(value).__name__}"
                    )
                    continue
                entry_spec = spec.get("entry_schema", {})
                for idx, entry in enumerate(value):
                    if not isinstance(entry, dict):
                        errors.append(
                            f"Invalid 'metadata.{field}[{idx}]': Expected dict"
                        )
                        continue
                    for ef, es in entry_spec.items():
                        ev = entry.get(ef)
                        if es.get("required") and ev is None:
                            errors.append(
                                f"Missing '{field}[{idx}].{ef}'"
                            )
                        elif ev is not None:
                            err = self.validate_field_value(
                                f"metadata.{field}[{idx}].{ef}", ev, es
                            )
                            if err:
                                errors.append(err)
            else:
                err = self.validate_field_value(
                    f"metadata.{field}", value, spec
                )
                if err:
                    errors.append(err)

        return errors

    def validate_class_rules(self, ocsf_event: Dict[str, Any]) -> List[str]:
        """
        Apply class-specific constraints from ``EVENT_CLASSES``.

        Returns a list of error strings (empty on success).
        """
        errors: List[str] = []
        class_uid = ocsf_event.get("class_uid")
        if class_uid is None:
            return errors

        spec = self.get_event_class_spec(class_uid)
        if spec is None:
            return errors  # unknown class — no class-specific rules

        requires_all = spec.get("requires_all", [])
        for field in requires_all:
            if field not in ocsf_event:
                errors.append(
                    f"Class {class_uid} ({spec.get('name', 'Unknown')}) "
                    f"requires '{field}'"
                )

        requires_any = spec.get("requires_any", [])
        if requires_any and not any(f in ocsf_event for f in requires_any):
            fields_str = " or ".join(f"'{f}'" for f in requires_any)
            errors.append(
                f"Class {class_uid} ({spec.get('name', 'Unknown')}) "
                f"requires {fields_str}"
            )

        return errors


# Module-level singleton for convenience
DEFAULT = OCSFSchemaRegistry()
