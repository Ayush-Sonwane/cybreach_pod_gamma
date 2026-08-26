"""API tests for re-validation schedule management endpoints."""

import pytest


@pytest.fixture()
def created(client):
    response = client.post(
        "/api/v2/revalidate/schedules",
        json={
            "name": "nightly auth check",
            "event_id": "evt-123",
            "interval": "6h",
        },
    )
    assert response.status_code == 201
    return response.json()


class TestCreateSchedule:

    def test_create_returns_201_with_parsed_interval(self, client):
        response = client.post(
            "/api/v2/revalidate/schedules",
            json={
                "name": "hourly check",
                "event_id": "evt-1",
                "interval": "1h30m",
            },
        )

        assert response.status_code == 201
        body = response.json()

        assert body["schedule_id"].startswith("sched-")
        assert body["interval_seconds"] == 5400
        assert body["missed_run_policy"] == "run_once"
        assert body["enabled"] is True
        assert body["has_request_template"] is False
        assert body["next_run_at"] is None

    def test_default_interval_is_24h(self, client):
        response = client.post(
            "/api/v2/revalidate/schedules",
            json={"name": "daily", "event_id": "evt-2"},
        )

        assert response.status_code == 201
        assert response.json()["interval_seconds"] == 86400

    def test_invalid_interval_rejected(self, client):
        response = client.post(
            "/api/v2/revalidate/schedules",
            json={
                "name": "bad interval",
                "event_id": "evt-3",
                "interval": "every 5 minutes",
            },
        )

        assert response.status_code == 422

    def test_below_minimum_rejected(self, client):
        response = client.post(
            "/api/v2/revalidate/schedules",
            json={
                "name": "too fast",
                "event_id": "evt-4",
                "interval": "30s",
            },
        )

        assert response.status_code == 422

    def test_missing_required_fields_rejected(self, client):
        response = client.post(
            "/api/v2/revalidate/schedules",
            json={"interval": "1h"},
        )

        assert response.status_code == 422

    def test_invalid_policy_rejected(self, client):
        response = client.post(
            "/api/v2/revalidate/schedules",
            json={
                "name": "bad policy",
                "event_id": "evt-5",
                "missed_run_policy": "explode",
            },
        )

        assert response.status_code == 422


class TestListSchedules:

    def test_list_includes_created_schedule(self, client, created):
        response = client.get("/api/v2/revalidate/schedules")

        assert response.status_code == 200
        body = response.json()

        assert body["count"] == 1
        assert body["schedules"][0]["schedule_id"] == created["schedule_id"]

    def test_enabled_filter(self, client, created):
        schedule_id = created["schedule_id"]
        client.patch(
            f"/api/v2/revalidate/schedules/{schedule_id}",
            json={"enabled": False},
        )

        enabled = client.get(
            "/api/v2/revalidate/schedules?enabled=true"
        ).json()
        disabled = client.get(
            "/api/v2/revalidate/schedules?enabled=false"
        ).json()

        assert enabled["count"] == 0
        assert disabled["count"] == 1


class TestGetUpdateDelete:

    def test_get_by_id(self, client, created):
        schedule_id = created["schedule_id"]

        response = client.get(f"/api/v2/revalidate/schedules/{schedule_id}")

        assert response.status_code == 200
        assert response.json()["event_id"] == "evt-123"

    def test_get_missing_returns_404_code(self, client):
        response = client.get("/api/v2/revalidate/schedules/sched-nope")

        assert response.status_code == 404
        assert response.json()["detail"]["code"] == "SCHEDULE_NOT_FOUND"

    def test_patch_updates_interval_and_policy(self, client, created):
        schedule_id = created["schedule_id"]

        response = client.patch(
            f"/api/v2/revalidate/schedules/{schedule_id}",
            json={"interval": "15m", "missed_run_policy": "skip"},
        )

        assert response.status_code == 200
        body = response.json()

        assert body["interval_seconds"] == 900
        assert body["missed_run_policy"] == "skip"

    def test_patch_can_clear_request_template(self, client):
        create = client.post(
            "/api/v2/revalidate/schedules",
            json={
                "name": "with template",
                "event_id": "evt-9",
                "request_template": {"event_id": "evt-9"},
            },
        )
        schedule_id = create.json()["schedule_id"]

        response = client.patch(
            f"/api/v2/revalidate/schedules/{schedule_id}",
            json={"request_template": None},
        )

        assert response.status_code == 200
        assert response.json()["has_request_template"] is False

    def test_patch_empty_body_rejected(self, client, created):
        schedule_id = created["schedule_id"]

        response = client.patch(
            f"/api/v2/revalidate/schedules/{schedule_id}",
            json={},
        )

        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "EMPTY_SCHEDULE_UPDATE"

    def test_patch_missing_returns_404(self, client):
        response = client.patch(
            "/api/v2/revalidate/schedules/sched-nope",
            json={"enabled": False},
        )

        assert response.status_code == 404

    def test_delete_then_get_404(self, client, created):
        schedule_id = created["schedule_id"]

        deleted = client.delete(
            f"/api/v2/revalidate/schedules/{schedule_id}"
        )
        assert deleted.status_code == 200
        assert deleted.json()["deleted"] is True

        fetched = client.get(f"/api/v2/revalidate/schedules/{schedule_id}")
        assert fetched.status_code == 404

    def test_delete_missing_returns_404(self, client):
        response = client.delete("/api/v2/revalidate/schedules/sched-nope")

        assert response.status_code == 404


class TestExistingEndpointsUntouched:

    def test_home_still_works(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_health_still_works(self, client):
        response = client.get("/health")
        assert response.status_code == 200
