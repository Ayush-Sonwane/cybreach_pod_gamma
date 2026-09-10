"""
DeltaEngine ground-truth oracle (QA: verify accuracy of delta reports).

For each (original, updated) pair the EXPECTED change list is written by hand
from the documented semantics (recursive dict traversal, dot paths, sorted keys,
atomic list handling, change_type classification).  An exact-match assertion
catches any drift in what a delta report actually contains.

Semantics under test (mirrors src/service/delta_engine.py):
  - identical value -> no change entry
  - 1 == 1.0  -> no change (Python value equality)
  - keys sorted -> deterministic, stable ordering
  - a dict vs a non-dict value -> ONE atomic whole-object entry (no recursion)
  - explicit None and an absent key are indistinguishable (documented nuance)
  - lists are compared atomically with order-sensitive equality
"""
from src.service.delta_engine import DeltaEngine


def _report(original, updated):
    return DeltaEngine.calculate_with_summary(original, updated)


def _changes(original, updated):
    return _report(original, updated)["changes"]


def _no_change(original, updated):
    assert DeltaEngine.calculate(original, updated) == []
    assert _changes(original, updated) == []
    summary = _report(original, updated)["summary"]
    assert summary == {"added": 0, "removed": 0, "modified": 0}


# --------------------------------------------------------------------------- #
# No-op cases - a delta report must never report false positives
# --------------------------------------------------------------------------- #

def test_identical_flat_events():
    event = {"class_uid": 3002, "category_uid": 3, "time": 1000}
    _no_change(dict(event), dict(event))


def test_identical_nested_events():
    event = {"src_endpoint": {"ip": "10.0.0.1", "port": 443},
             "actor": {"user": {"name": "jdoe"}}}
    _no_change(dict(event), dict(event))


def test_int_vs_float_equal_is_not_a_change():
    # 1000 == 1000.0 -> the delta report must NOT flag this.
    _no_change({"time": 1000}, {"time": 1000.0})


def test_key_order_does_not_matter():
    _no_change({"a": 1, "b": 2}, {"b": 2, "a": 1})


def test_empty_vs_empty_objects():
    _no_change({"x": {}}, {"x": {}})
    _no_change({}, {})


def test_explicit_none_vs_absent_key_is_not_a_change():
    # Documented nuance: original.get(key, None) makes an explicit null value
    # and a missing key indistinguishable, so neither direction is reported.
    _no_change({"a": 1}, {"a": 1, "b": None})
    _no_change({"a": 1, "b": None}, {"a": 1})


# --------------------------------------------------------------------------- #
# Single changes - exact field / before / after / change_type
# --------------------------------------------------------------------------- #

def test_top_level_modify():
    assert _changes({"time": 1000}, {"time": 2000}) == [
        {"field": "time", "before": 1000, "after": 2000, "change_type": "data"},
    ]


def test_nested_modify():
    assert _changes(
        {"src_endpoint": {"ip": "10.0.0.1", "port": 443}},
        {"src_endpoint": {"ip": "10.0.0.9", "port": 443}},
    ) == [
        {"field": "src_endpoint.ip", "before": "10.0.0.1",
         "after": "10.0.0.9", "change_type": "data"},
    ]


def test_deeply_nested_modify():
    assert _changes(
        {"actor": {"user": {"name": "jdoe"}}},
        {"actor": {"user": {"name": "admin"}}},
    ) == [
        {"field": "actor.user.name", "before": "jdoe",
         "after": "admin", "change_type": "data"},
    ]


def test_nested_add():
    assert _changes(
        {"src_endpoint": {"ip": "10.0.0.1"}},
        {"src_endpoint": {"ip": "10.0.0.1", "port": 443}},
    ) == [
        {"field": "src_endpoint.port", "before": None,
         "after": 443, "change_type": "data"},
    ]


def test_nested_remove():
    assert _changes(
        {"src_endpoint": {"ip": "10.0.0.1", "port": 443}},
        {"src_endpoint": {"ip": "10.0.0.1"}},
    ) == [
        {"field": "src_endpoint.port", "before": 443,
         "after": None, "change_type": "data"},
    ]


def test_added_field_reported():
    assert _changes({"time": 1}, {"time": 1, "message": "hello"}) == [
        {"field": "message", "before": None,
         "after": "hello", "change_type": "data"},
    ]


def test_removed_field_reported():
    assert _changes({"time": 1, "message": "hello"}, {"time": 1}) == [
        {"field": "message", "before": "hello",
         "after": None, "change_type": "data"},
    ]


# --------------------------------------------------------------------------- #
# Whole-object (dict vs non-dict) transitions - atomic single entry
# --------------------------------------------------------------------------- #

def test_whole_object_added_is_a_single_entry():
    assert _changes(
        {"time": 1},
        {"time": 1, "src_endpoint": {"ip": "1.2.3.4", "port": 443}},
    ) == [
        {"field": "src_endpoint", "before": None,
         "after": {"ip": "1.2.3.4", "port": 443}, "change_type": "data"},
    ]


def test_whole_object_removed_is_a_single_entry():
    assert _changes(
        {"time": 1, "src_endpoint": {"ip": "1.2.3.4", "port": 443}},
        {"time": 1},
    ) == [
        {"field": "src_endpoint", "before": {"ip": "1.2.3.4", "port": 443},
         "after": None, "change_type": "data"},
    ]


def test_object_to_none_and_back():
    assert _changes(
        {"src_endpoint": {"ip": "1.2.3.4"}},
        {"src_endpoint": None},
    ) == [
        {"field": "src_endpoint", "before": {"ip": "1.2.3.4"},
         "after": None, "change_type": "data"},
    ]
    assert _changes(
        {"src_endpoint": None},
        {"src_endpoint": {"ip": "1.2.3.4"}},
    ) == [
        {"field": "src_endpoint", "before": None,
         "after": {"ip": "1.2.3.4"}, "change_type": "data"},
    ]


def test_empty_object_to_populated_recurses():
    assert _changes(
        {"src_endpoint": {}},
        {"src_endpoint": {"ip": "1.2.3.4"}},
    ) == [
        {"field": "src_endpoint.ip", "before": None,
         "after": "1.2.3.4", "change_type": "data"},
    ]


# --------------------------------------------------------------------------- #
# Type changes
# --------------------------------------------------------------------------- #

def test_int_to_string_type_change():
    assert _changes({"time": 1000}, {"time": "1000"}) == [
        {"field": "time", "before": 1000,
         "after": "1000", "change_type": "data"},
    ]


def test_string_to_object_type_change():
    assert _changes({"src_endpoint": "flat"}, {"src_endpoint": {"ip": "1.2.3.4"}}) == [
        {"field": "src_endpoint", "before": "flat",
         "after": {"ip": "1.2.3.4"}, "change_type": "data"},
    ]


def test_bool_flip_is_a_change():
    assert _changes({"flag": True}, {"flag": False}) == [
        {"field": "flag", "before": True, "after": False, "change_type": "data"},
    ]


# --------------------------------------------------------------------------- #
# List handling - atomic, order-sensitive
# --------------------------------------------------------------------------- #

def test_list_change_is_single_atomic_entry():
    assert _changes({"tags": ["a", "b"]}, {"tags": ["a", "b", "c"]}) == [
        {"field": "tags", "before": ["a", "b"],
         "after": ["a", "b", "c"], "change_type": "data"},
    ]


def test_list_order_difference_is_a_change():
    # Lists compare with order-sensitive equality.
    assert len(_changes({"tags": ["a", "b"]}, {"tags": ["b", "a"]})) == 1


# --------------------------------------------------------------------------- #
# change_type classification
# --------------------------------------------------------------------------- #

def test_provenance_change_classified():
    before = {"metadata": {"provenance": [{"ocsf_field": "time", "raw_field": "a"}]}}
    after = {"metadata": {"provenance": [{"ocsf_field": "time", "raw_field": "b"}]}}
    assert _changes(before, after) == [
        {"field": "metadata.provenance",
         "before": [{"ocsf_field": "time", "raw_field": "a"}],
         "after": [{"ocsf_field": "time", "raw_field": "b"}],
         "change_type": "provenance"},
    ]


def test_provenance_unchanged_produces_no_entry():
    before = {"metadata": {"provenance": [{"ocsf_field": "time", "raw_field": "a"}], "version": "1.1.0"}}
    after = {"metadata": {"provenance": [{"ocsf_field": "time", "raw_field": "a"}], "version": "1.2.0"}}
    fields = {c["field"]: c for c in _changes(before, after)}
    # provenance list is identical -> no entry; only version changed -> data.
    assert list(fields) == ["metadata.version"]
    assert fields["metadata.version"]["change_type"] == "data"


def test_structural_fields_classified():
    before = {"class_uid": 3002, "category_uid": 3, "activity_id": 1, "time": 1}
    after = {"class_uid": 4001, "category_uid": 4, "activity_id": 2, "time": 1}
    result = _changes(before, after)
    structural = {c["field"] for c in result if c["change_type"] == "structural"}
    assert structural == {"class_uid", "category_uid", "activity_id"}
    # sorted path order: activity_id, category_uid, class_uid
    assert [c["field"] for c in result] == ["activity_id", "category_uid", "class_uid"]


def test_structural_first_segment_classified():
    # A nested path whose FIRST segment is a structural field is classified
    # structurally too (classifier checks the root segment).
    result = _changes({"class_uid": {"nested": 1}}, {"class_uid": {"nested": 2}})
    assert result[0]["change_type"] == "structural"


def test_every_entry_has_change_type():
    result = _changes(
        {"class_uid": 3002, "time": 1, "src_endpoint": {"ip": "1.1.1.1"}},
        {"class_uid": 4001, "time": 9, "src_endpoint": {"ip": "2.2.2.2"}, "x": 0},
    )
    assert all("change_type" in entry for entry in result)


# --------------------------------------------------------------------------- #
# Compound scenario - exact full report incl. summary/classification
# --------------------------------------------------------------------------- #

def test_compound_delta_exact_report():
    original = {
        "class_uid": 3002, "category_uid": 3, "time": 1,
        "status_id": 1,
        "src_endpoint": {"ip": "1.1.1.1", "port": 443},
    }
    updated = {
        "class_uid": 4001, "category_uid": 4, "time": 2,
        "message": "hi",
        "src_endpoint": {"ip": "2.2.2.2", "port": 443},
    }
    report = _report(original, updated)

    assert report["changes"] == [
        {"field": "category_uid", "before": 3, "after": 4, "change_type": "structural"},
        {"field": "class_uid", "before": 3002, "after": 4001, "change_type": "structural"},
        {"field": "message", "before": None, "after": "hi", "change_type": "data"},
        {"field": "src_endpoint.ip", "before": "1.1.1.1", "after": "2.2.2.2", "change_type": "data"},
        {"field": "status_id", "before": 1, "after": None, "change_type": "data"},
        {"field": "time", "before": 1, "after": 2, "change_type": "data"},
    ]
    assert report["summary"] == {"added": 1, "removed": 1, "modified": 4}
    assert report["classification"] == {"data": 4, "structural": 2, "provenance": 0}


# --------------------------------------------------------------------------- #
# Determinism & scalability
# --------------------------------------------------------------------------- #

def test_delta_is_deterministic_across_runs():
    original = {"b": {"x": 1, "y": {"z": 1}}, "a": 5, "src_endpoint": {"ip": "1.1.1.1"}}
    updated = {"b": {"x": 2, "y": {"z": 1}}, "a": 6, "src_endpoint": {"ip": "1.1.1.1"}}
    first = DeltaEngine.calculate(original, updated)
    for _ in range(3):
        assert DeltaEngine.calculate(original, updated) == first


def test_delta_independent_of_submission_key_order():
    original = {"src_endpoint": {"ip": "1.1.1.1", "port": 443}, "time": 1}
    updated = {"time": 9, "src_endpoint": {"port": 443, "ip": "2.2.2.2"}}
    baseline = _changes(original, updated)
    reordered = _changes(
        {"time": 1, "src_endpoint": {"port": 443, "ip": "1.1.1.1"}},
        {"src_endpoint": {"ip": "2.2.2.2", "port": 443}, "time": 9},
    )
    assert baseline == reordered


def test_large_event_delta_completes_and_is_exact():
    import copy
    original = {f"field_{i}": i for i in range(1000)}
    original["nested"] = {"k": {"deep": {"leaf": "a"}}}
    updated = copy.deepcopy(original)  # must not alias original's nested dict
    updated["nested"]["k"]["deep"]["leaf"] = "b"
    for i in range(30):
        updated[f"field_{i}"] = i + 100
    changes = DeltaEngine.calculate(original, updated)
    assert len(changes) == 31
    leaf = [c for c in changes if c["field"] == "nested.k.deep.leaf"]
    assert leaf[0]["before"] == "a"
    assert leaf[0]["after"] == "b"