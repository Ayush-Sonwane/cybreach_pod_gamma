"""
OCSFValidator tests: mandatory fields, timestamp type, complex objects,
and class-specific rules (Pod Gamma, Module 2).
"""
from src.validator import OCSFValidator


def test_valid_authentication_event_passes():
    event = {
        "class_uid": 3002,
        "category_uid": 3,
        "time": 1711920000000,
        "user": {"name": "jdoe"},
    }
    is_valid, errors = OCSFValidator.validate_event(event)
    assert is_valid, errors


def test_missing_mandatory_fields_reported():
    is_valid, errors = OCSFValidator.validate_event({})
    assert not is_valid
    joined = " ".join(errors)
    assert "class_uid" in joined
    assert "category_uid" in joined
    assert "time" in joined


def test_invalid_time_type_reported():
    event = {"class_uid": 3002, "category_uid": 3, "time": "not-a-number"}
    is_valid, errors = OCSFValidator.validate_event(event)
    assert not is_valid
    assert any("'time'" in e for e in errors)


def test_class_3002_requires_user_or_actor():
    event = {"class_uid": 3002, "category_uid": 3, "time": 1}
    is_valid, errors = OCSFValidator.validate_event(event)
    assert not is_valid
    assert any("user" in e and "actor" in e for e in errors)


def test_class_4001_requires_src_and_dst_endpoints():
    event = {"class_uid": 4001, "category_uid": 4, "time": 1}
    is_valid, errors = OCSFValidator.validate_event(event)
    assert not is_valid
    joined = " ".join(errors)
    assert "src_endpoint" in joined
    assert "dst_endpoint" in joined


def test_invalid_endpoint_ip_type_reported():
    event = {
        "class_uid": 3002,
        "category_uid": 3,
        "time": 1,
        "user": {"name": "jdoe"},
        "src_endpoint": {"ip": 123},
    }
    is_valid, errors = OCSFValidator.validate_event(event)
    assert not is_valid
    assert any("src_endpoint.ip" in e for e in errors)


def test_complex_object_must_be_dict():
    event = {
        "class_uid": 3002,
        "category_uid": 3,
        "time": 1,
        "user": "not-a-dict",
    }
    is_valid, errors = OCSFValidator.validate_event(event)
    assert not is_valid
    assert any("'user'" in e for e in errors)
