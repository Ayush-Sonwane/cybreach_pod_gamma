import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

@pytest.fixture(scope="module")
def setup_test_class():
    """Ensures class 9001 exists in DB/Cache for normalization tests."""
    payload = {
        "organization_id": "org_sec_ops_01",
        "class_uid": 9001,
        "class_name": "Security Log",
        "category_uid": 1,
        "attributes": {
            "src_ip": "string",
            "dst_ip": "string",
            "severity": "string",
            "user": "string"
        },
        "version": 1
    }
    response = client.post("/api/v2/ocsf/classes", json=payload)
    # Print response detail if validation fails
    if response.status_code not in [200, 201, 409]:
        print(f"\n[SETUP ERROR DETAIL]: {response.json()}")
    assert response.status_code in [200, 201, 409]


def test_single_event_normalization(setup_test_class):
    """Tests single log event normalization and unmapped_data fallback."""
    payload = {
        "organization_id": "org_sec_ops_01",
        "class_uid": 9001,
        "raw_payload": {
            "src_ip": "10.0.0.5",
            "user": "alice",
            "severity": "HIGH",
            "custom_threat_score": 95
        }
    }
    response = client.post("/api/v2/normalize", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert data["organization_id"] == "org_sec_ops_01"
    assert data["class_uid"] == 9001
    assert data["normalized_data"]["src_ip"] == "10.0.0.5"
    assert data["unmapped_data"]["custom_threat_score"] == 95


def test_batch_event_normalization(setup_test_class):
    """Tests array payload processing via the batch normalization route."""
    payload = {
        "organization_id": "org_sec_ops_01",
        "class_uid": 9001,
        "raw_payloads": [
            {"src_ip": "10.0.0.5", "user": "alice"},
            {"src_ip": "10.0.0.6", "user": "bob", "unrecognized_field": True}
        ]
    }
    response = client.post("/api/v2/normalize/batch", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert data["total_processed"] == 2
    assert len(data["events"]) == 2
    assert data["events"][1]["unmapped_data"]["unrecognized_field"] is True


def test_normalize_nonexistent_class():
    """Verifies response when querying a non-existent class UID."""
    payload = {
        "organization_id": "org_sec_ops_01",
        "class_uid": 999999,
        "raw_payload": {"src_ip": "1.1.1.1"}
    }
    response = client.post("/api/v2/normalize", json=payload)
    assert response.status_code in [200, 404]


def test_unflatten_dict_nested():
    """Tests recursive dictionary unflattening helper function directly."""
    from app.services.normalizer import unflatten_dict

    raw = {
        "network": {
            "connection_info": {
                "src_ip": "10.0.0.1"
            }
        }
    }
    flattened = unflatten_dict(raw)
    assert flattened == {"network.connection_info.src_ip": "10.0.0.1"}


def test_nested_normalization_endpoint(setup_test_class):
    """Tests processing deeply nested payloads via API client."""
    payload = {
        "organization_id": "org_sec_ops_01",
        "class_uid": 9001,
        "raw_payload": {
            "network": {
                "connection_info": {
                    "src_ip": "192.168.1.50"
                }
            },
            "actor": {
                "user": {
                    "name": "alice"
                }
            },
            "custom_nested_metric": {"score": 99}
        }
    }
    response = client.post("/api/v2/normalize", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert data["normalized_data"]["src_ip"] == "192.168.1.50"
    assert data["unmapped_data"]["custom_nested_metric.score"] == 99


def test_normalize_empty_payload():
    """Verifies service level failure return on empty raw payload."""
    from app.services.normalizer import normalize_log

    result = normalize_log(db=None, org_id="org_sec_ops_01", class_uid=9001, raw_payload={})
    assert result["status"] == "failed"
    assert "Payload must be a non-empty JSON object" in result["error"]