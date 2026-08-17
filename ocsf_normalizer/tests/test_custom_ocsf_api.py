import pytest
from fastapi.testclient import TestClient

from src.main import app


client = TestClient(app)


def test_register_custom_ocsf_class():
    response = client.post(
        "/api/v2/ocsf/classes",
        json={
            "organization": "APITestOrg",
            "class_name": "CustomFirewallEvent",
            "class_uid": 9100,
            "category_uid": 9,
            "version": "1.0",
            "schema": {
                "type": "object",
                "properties": {
                    "source_ip": {
                        "type": "string"
                    },
                    "action": {
                        "type": "string"
                    }
                },
                "required": [
                    "source_ip",
                    "action"
                ]
            }
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["organization"] == "APITestOrg"
    assert data["class_name"] == "CustomFirewallEvent"
    assert data["class_uid"] == 9100
    assert data["category_uid"] == 9
    assert data["version"] == "1.0"
    assert data["status"] == "registered"

    assert data["schema"]["type"] == "object"


def test_list_custom_ocsf_classes():
    response = client.get("/api/v2/ocsf/classes")

    assert response.status_code == 200

    data = response.json()

    assert "classes" in data
    assert isinstance(data["classes"], list)


def test_filter_custom_ocsf_classes_by_organization():
    response = client.get(
        "/api/v2/ocsf/classes",
        params={
            "organization": "APITestOrg"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["classes"]) >= 1

    for custom_class in data["classes"]:
        assert custom_class["organization"] == "APITestOrg"


def test_duplicate_custom_ocsf_class_rejected():
    response = client.post(
        "/api/v2/ocsf/classes",
        json={
            "organization": "APITestOrg",
            "class_name": "DuplicateFirewallEvent",
            "class_uid": 9100,
            "category_uid": 9,
            "version": "1.0",
            "schema": {
                "type": "object"
            }
        },
    )

    assert response.status_code == 409

    data = response.json()

    assert data["detail"]["code"] == "CUSTOM_CLASS_EXISTS"


def test_get_custom_ocsf_class():
    list_response = client.get(
        "/api/v2/ocsf/classes",
        params={
            "organization": "APITestOrg"
        },
    )

    assert list_response.status_code == 200

    classes = list_response.json()["classes"]

    assert len(classes) >= 1

    class_id = classes[0]["id"]

    response = client.get(
        f"/api/v2/ocsf/classes/{class_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == class_id
    assert data["organization"] == "APITestOrg"


def test_nonexistent_custom_ocsf_class_returns_404():
    response = client.get(
        "/api/v2/ocsf/classes/nonexistent-id"
    )

    assert response.status_code == 404

    data = response.json()

    assert data["detail"]["code"] == "CUSTOM_CLASS_NOT_FOUND"