"""
Provenance integrity validation for OCSF normalized events.

Provenance (``metadata.provenance``) records which raw vendor field each OCSF
field was derived from, giving field-level auditability.  This validator checks
that provenance is:

1. **Well-formed** — a list of ``{ocsf_field, raw_field}`` dicts with non-empty
   string values.
2. **Unique** — no duplicate ``ocsf_field`` entries (a single OCSF field has
   exactly one source).
3. **Accurate against the normalized event** — every non-default OCSF field that
   was actually populated in the event has a matching provenance entry
   (completeness).
4. **Schema-valid** — each ``ocsf_field`` is a real OCSF field path in the
   schema registry.
5. **Traceable** (strict mode only) — each ``raw_field`` exists in the raw
   vendor payload.  This is strict because some adapters record provenance for
   default/fallback values even when the raw field is absent, so it is opt-in.

The validator is platform-agnostic: it has no SIEM-specific logic and compares
provenance structurally against the normalized event and the schema registry.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from src.schema.ocsf_schema import OCSFSchemaRegistry, DEFAULT as DEFAULT_REGISTRY


# OCSF fields that always hold a value on a normalized event regardless of the
# raw payload (they are computed/derived) — completeness checks skip these
# because the adapters always populate them even as defaults.
COMPUTED_FIELDS = {"class_uid", "category_uid", "activity_id"}


class ProvenanceValidator:
    """
    Validates the ``metadata.provenance`` block of a normalized OCSF event.
    """

    def __init__(
        self,
        registry: Optional[OCSFSchemaRegistry] = None,
        strict_raw_fields: bool = False,
    ):
        self.registry = registry or DEFAULT_REGISTRY
        self.strict_raw_fields = strict_raw_fields

    # -- public API --------------------------------------------------------

    def validate(
        self,
        ocsf_event: Dict[str, Any],
        raw_event: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validate provenance against the normalized event and schema registry.

        Args:
            ocsf_event: the normalized OCSF event dict (must contain
                        ``metadata.provenance``).
            raw_event:  the original vendor payload (optional; required for
                        strict raw-field traceability).

        Returns:
            (is_valid: bool, errors: List[str])
        """
        errors: List[str] = []

        provenance = self._extract_provenance(ocsf_event, errors)
        if provenance is None:
            return False, errors

        self._validate_structure(provenance, errors)
        if len(errors) > 0:
            return False, errors

        self._validate_no_duplicates(provenance, errors)
        if len(errors) > 0:
            return False, errors

        self._validate_ocsf_paths(provenance, errors)
        self._validate_completeness(provenance, ocsf_event, errors)

        if self.strict_raw_fields:
            if raw_event is None:
                errors.append(
                    "Strict provenance validation requires the raw_event payload"
                )
            elif not errors:
                # Only check raw fields once structure/no-duplicate checks pass;
                # absent-raw-field reports are only meaningful on clean entries.
                self._validate_raw_fields(provenance, raw_event, errors)

        is_valid = len(errors) == 0
        return is_valid, errors

    # -- internal helpers --------------------------------------------------

    def _extract_provenance(
        self, ocsf_event: Dict[str, Any], errors: List[str]
    ) -> Optional[List[Any]]:
        metadata = ocsf_event.get("metadata")
        if not isinstance(metadata, dict):
            errors.append("Missing 'metadata' dict on normalized event")
            return None

        provenance = metadata.get("provenance")
        if provenance is None:
            errors.append("Missing 'metadata.provenance' on normalized event")
            return None

        if not isinstance(provenance, list):
            errors.append(
                "Invalid 'metadata.provenance': Expected list, "
                f"got {type(provenance).__name__}"
            )
            return None

        return provenance

    def _validate_structure(
        self, provenance: List[Any], errors: List[str]
    ) -> None:
        for idx, entry in enumerate(provenance):
            if not isinstance(entry, dict):
                errors.append(f"Provenance[{idx}]: Expected dict, got {type(entry).__name__}")
                continue
            ocsf_field = entry.get("ocsf_field")
            raw_field = entry.get("raw_field")
            if not isinstance(ocsf_field, str) or not ocsf_field.strip():
                errors.append(f"Provenance[{idx}]: 'ocsf_field' must be a non-empty string")
            if not isinstance(raw_field, str) or not raw_field.strip():
                errors.append(f"Provenance[{idx}]: 'raw_field' must be a non-empty string")

    def _validate_no_duplicates(
        self, provenance: List[Any], errors: List[str]
    ) -> None:
        seen: Dict[str, List[int]] = {}
        for idx, entry in enumerate(provenance):
            if not isinstance(entry, dict):
                continue
            ocsf_field = entry.get("ocsf_field")
            if not isinstance(ocsf_field, str):
                continue
            seen.setdefault(ocsf_field, []).append(idx)

        for ocsf_field, indices in seen.items():
            if len(indices) > 1:
                errors.append(
                    f"Duplicate provenance entry for '{ocsf_field}' "
                    f"(indices {indices})"
                )

    def _validate_ocsf_paths(
        self, provenance: List[Any], errors: List[str]
    ) -> None:
        for entry in provenance:
            if not isinstance(entry, dict):
                continue
            ocsf_field = entry.get("ocsf_field")
            if not isinstance(ocsf_field, str):
                continue
            if not self._is_valid_ocsf_path(ocsf_field):
                errors.append(
                    f"Provenance references unknown OCSF field '{ocsf_field}'"
                )

    def _is_valid_ocsf_path(self, path: str) -> bool:
        parts = path.split(".")
        if len(parts) == 1:
            return path in self.registry.base_fields
        # Nested path: e.g. src_endpoint.ip, actor.user.name
        if parts[0] not in self.registry.complex_objects:
            return False
        remaining = ".".join(parts[1:])
        # For deeply nested (actor.user.name), check progressively
        spec = self.registry.complex_objects[parts[0]]
        current = parts[1]
        if current not in spec:
            return False
        sub_spec = spec[current]
        nested_name = sub_spec.get("nested")
        if len(parts) == 2:
            return True
        if not nested_name:
            return False
        # Recurse into the nested object for deeper paths
        nested_obj = self.registry.complex_objects.get(nested_name)
        if nested_obj is None:
            return False
        deeper = ".".join(parts[2:])
        return self._valid_in_object(nested_obj, deeper)

    def _valid_in_object(
        self, obj_spec: Dict[str, Dict[str, Any]], path: str
    ) -> bool:
        parts = path.split(".")
        if not parts:
            return False
        if parts[0] not in obj_spec:
            return False
        if len(parts) == 1:
            return True
        sub_spec = obj_spec[parts[0]]
        nested_name = sub_spec.get("nested")
        if not nested_name:
            return False
        nested_obj = self.registry.complex_objects.get(nested_name)
        if nested_obj is None:
            return False
        return self._valid_in_object(nested_obj, ".".join(parts[1:]))

    def _validate_completeness(
        self,
        provenance: List[Any],
        ocsf_event: Dict[str, Any],
        errors: List[str],
    ) -> None:
        """
        Every non-default OCSF field populated on the event should have a
        provenance entry.  Computed fields (class_uid etc.) are skipped because
        they are always present and provenance is not expected for them.
        """
        recorded = set()
        for entry in provenance:
            if isinstance(entry, dict) and isinstance(entry.get("ocsf_field"), str):
                recorded.add(entry["ocsf_field"])

        for field, value in ocsf_event.items():
            if field == "metadata":
                continue
            if field in COMPUTED_FIELDS:
                continue
            if value is None:
                continue
            # Only require provenance for scalar base fields and populated
            # complex objects here; nested object fields are covered by the
            # presence of a top-level object path (e.g. src_endpoint.ip).
            if field in self.registry.base_fields and field not in recorded:
                errors.append(
                    f"Missing provenance for OCSF field '{field}'"
                )
            elif field in self.registry.complex_objects and isinstance(value, dict):
                if field not in recorded and not any(
                    r.startswith(field + ".") for r in recorded
                ):
                    errors.append(
                        f"Missing provenance for complex object '{field}'"
                    )

    def _validate_raw_fields(
        self,
        provenance: List[Any],
        raw_event: Dict[str, Any],
        errors: List[str],
    ) -> None:
        """
        (Strict mode) Every referenced ``raw_field`` must exist in the raw
        vendor payload.  Supports nested raw paths via dot-notation.
        """
        if raw_event is None:
            return
        for entry in provenance:
            if not isinstance(entry, dict):
                continue
            raw_field = entry.get("raw_field")
            if not isinstance(raw_field, str):
                continue
            if not self._raw_field_exists(raw_event, raw_field):
                errors.append(
                    f"Provenance references absent raw field '{raw_field}'"
                )

    def _raw_field_exists(self, raw_event: Dict[str, Any], raw_field: str) -> bool:
        # Some vendors emit flat dotted keys (e.g. "source.ip" as a literal
        # dict key) while others nest them ({"source": {"ip": ...}}).  Check
        # the flat form first, then fall back to nested traversal.
        if raw_field in raw_event:
            return True
        parts = raw_field.split(".")
        curr: Any = raw_event
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return False
        return True
