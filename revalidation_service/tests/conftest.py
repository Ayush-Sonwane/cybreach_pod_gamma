import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.scheduling.api import get_schedule_repository
from src.scheduling.repository import ScheduleRepository


@pytest.fixture()
def repository(tmp_path):
    return ScheduleRepository(
        database_path=str(tmp_path / "schedules_test.db")
    )


@pytest.fixture()
def client(repository):
    app.dependency_overrides[get_schedule_repository] = lambda: repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
