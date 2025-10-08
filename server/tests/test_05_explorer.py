import pytest

from fastapi.testclient import TestClient

from app import app


@pytest.mark.asyncio
async def test_dids_explorer():
    with TestClient(app) as test_client:
        response = test_client.get("/explorer/dids", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert isinstance(response.json().get("results"), list)


@pytest.mark.asyncio
async def test_resources_explorer():
    with TestClient(app) as test_client:
        response = test_client.get("/explorer/resources", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert isinstance(response.json().get("results"), list)
