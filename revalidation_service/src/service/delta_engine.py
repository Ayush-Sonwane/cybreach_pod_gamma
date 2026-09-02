"""
Delta comparison engine for before/after state differences.

Compares an original event against a (revalidated) updated event and reports
every difference at field-level granularity.  Nested dicts are traversed
recursively and reported using dot-notation paths (e.g. ``src_endpoint.ip``)
so a change deep inside a complex object is surfaced as its own entry rather
than being collapsed into the whole parent object.

Change entries keep the stable shape consumed by the delta endpoint::

    {"field": "<dot.notation.path>", "before": ..., "after": ...}

``calculate`` returns that flat list for backward compatibility.
``calculate_with_summary`` additionally buckets changes into structural, data,
and provenance changes (useful for auditing before/after state at a glance).
"""

from typing import Any, Dict, List, Optional, Tuple


# OCSF fields whose change affects the semantics/shape of the event, as opposed
# to a pure data value.  Sourced here so it can be adjusted without changing
# callers.
STRUCTURAL_FIELDS = {"class_uid", "category_uid", "activity_id"}

# Fields that describe lineage rather than event data.
PROVENANCE_FIELD = "provenance"


class DeltaChange:
    """Normalized representation of a single field-level difference."""

    __slots__ = ("field", "before", "after", "change_type")

    def __init__(self, field: str, before: Any, after: Any, change_type: str = "data"):
        self.field = field
        self.before = before
        self.after = after
        self.change_type = change_type

    def as_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "before": self.before,
            "after": self.after,
            "change_type": self.change_type,
        }


class DeltaEngine:
    """
    Compares the original event with the revalidated event.
    """

    @classmethod
    def calculate(
        cls,
        original: Dict[str, Any],
        updated: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Return the flat list of field-level changes (backward-compatible).

        Nested dictionaries are compared recursively and reported with
        dot-notation paths.  Each entry has ``field``/``before``/``after``.
        """
        changes = cls._collect_changes(original, updated, prefix="")
        return [c.as_dict() for c in changes]

    @classmethod
    def calculate_with_summary(
        cls,
        original: Dict[str, Any],
        updated: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Return a richer report: the change list plus a summary bucket of
        additions/removals/modifications and a change-type classification.
        """
        changes = cls._collect_changes(original, updated, prefix="")

        summary: Dict[str, int] = {"added": 0, "removed": 0, "modified": 0}
        classification: Dict[str, int] = {
            "data": 0,
            "structural": 0,
            "provenance": 0,
        }

        for c in changes:
            if c.before is None and c.after is not None:
                summary["added"] += 1
            elif c.before is not None and c.after is None:
                summary["removed"] += 1
            else:
                summary["modified"] += 1
            classification[c.change_type] = classification.get(c.change_type, 0) + 1

        return {
            "changes": [c.as_dict() for c in changes],
            "summary": summary,
            "classification": classification,
        }

    # -- internal ----------------------------------------------------------

    @classmethod
    def _collect_changes(
        cls,
        original: Dict[str, Any],
        updated: Dict[str, Any],
        prefix: str,
    ) -> List[DeltaChange]:
        changes: List[DeltaChange] = []

        original = original or {}
        updated = updated or {}

        all_keys = set(original.keys()) | set(updated.keys())

        for key in sorted(all_keys):
            path = f"{prefix}.{key}" if prefix else key
            old_val = original.get(key, None)
            new_val = updated.get(key, None)

            # Recurse into nested dicts for the logical "field" granularity,
            # unless they are explicit marker dicts we treat atomically (e.g.
            # an empty/absent complex object becoming present).
            if isinstance(old_val, dict) and isinstance(new_val, dict):
                changes.extend(
                    cls._collect_changes(old_val, new_val, path)
                )
                continue

            if old_val == new_val:
                continue

            change_type = cls._classify(path)
            changes.append(
                DeltaChange(path, old_val, new_val, change_type)
            )

        return changes

    @staticmethod
    def _classify(path: str) -> str:
        leaf = path.split(".")[-1]
        if leaf == PROVENANCE_FIELD or PROVENANCE_FIELD in path.split("."):
            return "provenance"
        if path in STRUCTURAL_FIELDS or path.split(".")[0] in STRUCTURAL_FIELDS:
            return "structural"
        return "data"
