from typing import Any, Dict, List


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

        changes = []

        all_fields = set(original.keys()) | set(updated.keys())

        for field in sorted(all_fields):

            before = original.get(field)
            after = updated.get(field)

            if before != after:
                changes.append(
                    {
                        "field": field,
                        "before": before,
                        "after": after,
                    }
                )

        return changes
