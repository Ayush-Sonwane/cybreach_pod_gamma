from src.ocsf_registry.repository import CustomOCSFClassRepository


def test_create_and_get_custom_class(tmp_path):
    database_path = tmp_path / "test.db"

    repository = CustomOCSFClassRepository(str(database_path))

    schema = {
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

    created = repository.create_class(
        class_id="cls_test_001",
        organization="TestOrg",
        class_name="TestFirewallEvent",
        class_uid=9001,
        category_uid=9,
        version="1.0",
        schema=schema,
    )

    assert created["id"] == "cls_test_001"
    assert created["organization"] == "TestOrg"
    assert created["class_name"] == "TestFirewallEvent"
    assert created["class_uid"] == 9001
    assert created["schema"] == schema

    result = repository.get_class("cls_test_001")

    assert result is not None
    assert result["id"] == "cls_test_001"
    assert result["schema"] == schema