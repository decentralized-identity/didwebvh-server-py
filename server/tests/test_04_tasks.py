import pytest

from fastapi.testclient import TestClient

from app import app


@pytest.mark.asyncio
async def test_create_tasks():
    with TestClient(app) as test_client:
        response = test_client.post(
            "/admin/tasks?task_type=sync_records", headers={"X-API-KEY": "webvh"}
        )
    assert response.status_code == 201
    assert response.json().get("task_id")


@pytest.mark.asyncio
async def test_list_tasks():
    with TestClient(app) as test_client:
        response = test_client.get("/admin/tasks", headers={"X-API-KEY": "webvh"})
    assert response.status_code == 200
    assert len(response.json().get("tasks")) == 1


@pytest.mark.asyncio
async def test_query_tasks():
    with TestClient(app) as test_client:
        response = test_client.get(
            "/admin/tasks?task_type=sync_records", headers={"X-API-KEY": "webvh"}
        )
    assert response.status_code == 200
    assert len(response.json().get("tasks")) == 1

    with TestClient(app) as test_client:
        response = test_client.get(
            "/admin/tasks?task_type=set_policy", headers={"X-API-KEY": "webvh"}
        )
    assert response.status_code == 200
    assert len(response.json().get("tasks")) == 0
