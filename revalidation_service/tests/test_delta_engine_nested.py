"""
DeltaEngine nested-comparison tests.

Verifies that before/after state differences are captured accurately —
including nested complex objects surfaced via dot-notation paths — and that
the summary/classification report buckets add/remove/modify and
structural/data/provenance changes correctly.
"""
from src.service.delta_engine import DeltaEngine

FLAT_ORIGINAL = {
    "class_uid": 3002,
    "category_uid": 3,
    "status_id": 1,
    "time": 1000,
}


class TestFlatComparison:
    def test_no_changes_when_identical(self):
        assert DeltaEngine.calculate(
            dict(FLAT_ORIGINAL), dict(FLAT_ORIGINAL)
        ) == []

    def test_modified_value_reported(self):
        changes = DeltaEngine.calculate(
            FLAT_ORIGINAL,
            {**FLAT_ORIGINAL, "status_id": 2},
        )
        assert len(changes) == 1
        assert changes[0]["field"] == "status_id"
        assert changes[0]["before"] == 1
        assert changes[0]["after"] == 2

    def test_added_field_reported(self):
        updated = {**FLAT_ORIGINAL, "message": "hello"}
        changes = DeltaEngine.calculate(FLAT_ORIGINAL, updated)
        added = [c for c in changes if c["field"] == "message"]
        assert len(added) == 1
        assert added[0]["before"] is None
        assert added[0]["after"] == "hello"

    def test_removed_field_reported(self):
        original = {**FLAT_ORIGINAL, "severity_id": 4}
        changes = DeltaEngine.calculate(original, FLAT_ORIGINAL)
        removed = [c for c in changes if c["field"] == "severity_id"]
        assert len(removed) == 1
        assert removed[0]["before"] == 4
        assert removed[0]["after"] is None


class TestNestedComparison:
    ORIGINAL = {
        "class_uid": 3002,
        "category_uid": 3,
        "time": 1000,
        "src_endpoint": {"ip": "10.0.0.1", "port": 443},
        "actor": {"user": {"name": "jdoe"}},
    }

    def test_nested_ip_change_surfaced_with_dot_path(self):
        updated = {
            **self.ORIGINAL,
            "src_endpoint": {"ip": "10.0.0.9", "port": 443},
        }
        changes = DeltaEngine.calculate(self.ORIGINAL, updated)
        ip_changes = [c for c in changes if c["field"] == "src_endpoint.ip"]
        assert len(ip_changes) == 1
        assert ip_changes[0]["before"] == "10.0.0.1"
        assert ip_changes[0]["after"] == "10.0.0.9"
        # port is unchanged, so no separate change for it
        assert not [c for c in changes if c["field"] == "src_endpoint.port"]

    def test_deeply_nested_change_surfaced(self):
        updated = {
            **self.ORIGINAL,
            "actor": {"user": {"name": "admin"}},
        }
        changes = DeltaEngine.calculate(self.ORIGINAL, updated)
        name_changes = [c for c in changes if c["field"] == "actor.user.name"]
        assert len(name_changes) == 1
        assert name_changes[0]["before"] == "jdoe"
        assert name_changes[0]["after"] == "admin"

    def test_nested_dicts_are_not_collapsed_to_parent(self):
        updated = {
            **self.ORIGINAL,
            "src_endpoint": {"ip": "10.0.0.1", "port": 8080},
        }
        changes = DeltaEngine.calculate(self.ORIGINAL, updated)
        fields = {c["field"] for c in changes}
        # The inner port difference must be its own entry, not a whole-object one.
        assert "src_endpoint.port" in fields
        assert "src_endpoint" not in fields


class TestSummaryAndClassification:
    def test_summary_add_remove_modify_counts(self):
        original = {
            "class_uid": 3002,
            "category_uid": 3,
            "time": 1000,
            "status_id": 1,
            "severity_id": 4,
        }
        updated = {
            "class_uid": 3002,
            "category_uid": 3,
            "time": 2000,
            "status_id": 2,
            "message": "new",
        }
        report = DeltaEngine.calculate_with_summary(original, updated)

        assert report["summary"]["modified"] >= 2  # time, status_id
        assert report["summary"]["added"] == 1      # message
        assert report["summary"]["removed"] == 1    # severity_id
        assert report["classification"]["data"] >= 1

    def test_structural_classification(self):
        original = {"class_uid": 3002, "category_uid": 3, "time": 1}
        updated = {"class_uid": 4001, "category_uid": 4, "time": 1}
        report = DeltaEngine.calculate_with_summary(original, updated)
        assert report["classification"]["structural"] == 2
        structural_fields = {
            c["field"] for c in report["changes"]
            if c["change_type"] == "structural"
        }
        assert structural_fields == {"class_uid", "category_uid"}

    def test_provenance_classification(self):
        original = {
            "time": 1,
            "metadata": {"provenance": [{"ocsf_field": "time", "raw_field": "a"}]},
        }
        updated = {
            "time": 1,
            "metadata": {"provenance": [{"ocsf_field": "time", "raw_field": "b"}]},
        }
        report = DeltaEngine.calculate_with_summary(original, updated)
        provenance_changes = [
            c for c in report["changes"] if c["change_type"] == "provenance"
        ]
        assert provenance_changes
        assert report["classification"]["provenance"] == len(provenance_changes)

    def test_changes_entries_include_change_type(self):
        changes = DeltaEngine.calculate(
            {"time": 1}, {"time": 2}
        )
        assert "change_type" in changes[0]
