"""Unit tests for the admin routes."""

import pytest
from fastapi.testclient import TestClient

from app import app
from app.plugins.storage import StorageManager
from tests.fixtures import (
    TEST_POLICY,
    TEST_WITNESS_KEY,
    TEST_WITNESS_REGISTRY,
)
from tests.helpers import assert_error_response
from config import settings

# Setup test environment
storage = StorageManager()

# Test API key
TEST_API_KEY = settings.API_KEY


@pytest.fixture(autouse=True)
async def setup_database():
    """Ensure database is provisioned before each test."""
    await storage.provision(recreate=True)

    # Store initial policy and registry in database
    storage.create_or_update_policy("active", TEST_POLICY)
    storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=TEST_WITNESS_REGISTRY,
        meta={"created": "2024-01-01T00:00:00Z", "updated": "2024-01-01T00:00:00Z"},
    )
    yield


class TestPolicyEndpoints:
    """Test cases for policy management endpoints."""

    @pytest.mark.asyncio
    async def test_get_active_policy_success(self):
        """Test retrieving the active policy."""
        with TestClient(app) as test_client:
            response = test_client.get("/admin/policy", headers={"x-api-key": TEST_API_KEY})

            assert response.status_code == 200
            policy = response.json()
            assert policy["version"] is not None
            assert "witness" in policy
            assert "portability" in policy

    @pytest.mark.asyncio
    async def test_get_active_policy_unauthorized(self):
        """Test getting policy without API key."""
        with TestClient(app) as test_client:
            response = test_client.get("/admin/policy")

            assert response.status_code == 401
            assert "Invalid or missing API Key" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_get_active_policy_invalid_key(self):
        """Test getting policy with invalid API key."""
        with TestClient(app) as test_client:
            response = test_client.get("/admin/policy", headers={"x-api-key": "invalid-key"})

            assert_error_response(response, 401, "Invalid or missing API Key")


class TestWitnessRegistryEndpoints:
    """Test cases for witness registry management endpoints."""

    @pytest.mark.asyncio
    async def test_get_known_witnesses_success(self):
        """Test retrieving known witnesses registry."""
        with TestClient(app) as test_client:
            response = test_client.get(
                "/admin/policy/known-witnesses", headers={"x-api-key": TEST_API_KEY}
            )

            assert response.status_code == 200
            registry_data = response.json()
            assert "registry" in registry_data
            assert "meta" in registry_data

    @pytest.mark.asyncio
    async def test_get_known_witnesses_unauthorized(self):
        """Test getting witnesses without API key."""
        with TestClient(app) as test_client:
            response = test_client.get("/admin/policy/known-witnesses")

            assert_error_response(response, 401, "Invalid or missing API Key")

    @pytest.mark.asyncio
    async def test_add_known_witness_success(self):
        """Test adding a new witness to the registry."""
        with TestClient(app) as test_client:
            # Generate a valid ed25519 multikey
            new_witness_key = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

            response = test_client.post(
                "/admin/policy/known-witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={"multikey": new_witness_key, "label": "New Test Witness"},
            )

            assert response.status_code == 200
            registry_data = response.json()
            assert "registry" in registry_data
            witness_did = f"did:key:{new_witness_key}"
            assert witness_did in registry_data["registry"]
            assert registry_data["registry"][witness_did]["name"] == "New Test Witness"

    @pytest.mark.asyncio
    async def test_add_known_witness_duplicate(self):
        """Test adding a duplicate witness (should fail)."""
        with TestClient(app) as test_client:
            # Try to add the same witness key again (fixture already added it)
            response = test_client.post(
                "/admin/policy/known-witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={"multikey": TEST_WITNESS_KEY, "label": "Duplicate Witness"},
            )

            assert_error_response(response, 409, "Witness already exists")

    @pytest.mark.asyncio
    async def test_add_known_witness_invalid_key(self):
        """Test adding an invalid multikey."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/admin/policy/known-witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={"multikey": "invalid-key-12345", "label": "Invalid Witness"},
            )

            assert_error_response(response, 400, "Invalid multikey")

    @pytest.mark.asyncio
    async def test_add_known_witness_unauthorized(self):
        """Test adding witness without API key."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/admin/policy/known-witnesses",
                json={
                    "multikey": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "label": "Unauthorized Witness",
                },
            )

            assert_error_response(response, 401, "Invalid or missing API Key")

    @pytest.mark.asyncio
    async def test_remove_known_witness_success(self):
        """Test removing a witness from the registry."""
        with TestClient(app) as test_client:
            # First add a witness
            new_witness_key = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"

            test_client.post(
                "/admin/policy/known-witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={"multikey": new_witness_key, "label": "Witness to Remove"},
            )

            # Now remove it
            response = test_client.delete(
                f"/admin/policy/known-witnesses/{new_witness_key}",
                headers={"x-api-key": TEST_API_KEY},
            )

            assert response.status_code == 200
            registry_data = response.json()
            witness_did = f"did:key:{new_witness_key}"
            assert witness_did not in registry_data["registry"]

    @pytest.mark.asyncio
    async def test_remove_known_witness_not_found(self):
        """Test removing a non-existent witness."""
        with TestClient(app) as test_client:
            # Use a valid multikey format that doesn't exist in registry
            nonexistent_key = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"

            response = test_client.delete(
                f"/admin/policy/known-witnesses/{nonexistent_key}",
                headers={"x-api-key": TEST_API_KEY},
            )

            # Could be 404 (not found) or 400 (invalid key format)
            assert response.status_code in [400, 404]
            if response.status_code == 404:
                assert "Witness not found" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_remove_known_witness_invalid_key(self):
        """Test removing with invalid multikey format."""
        with TestClient(app) as test_client:
            response = test_client.delete(
                "/admin/policy/known-witnesses/invalid-key", headers={"x-api-key": TEST_API_KEY}
            )

            assert_error_response(response, 400, "Invalid multikey")

    @pytest.mark.asyncio
    async def test_remove_known_witness_unauthorized(self):
        """Test removing witness without API key."""
        with TestClient(app) as test_client:
            response = test_client.delete(f"/admin/policy/known-witnesses/{TEST_WITNESS_KEY}")

            assert_error_response(response, 401, "Invalid or missing API Key")


class TestTaskEndpoints:
    """Test cases for administrative task endpoints."""

    @pytest.mark.asyncio
    async def test_sync_storage_task_set_policy(self):
        """Test creating a set policy task."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/admin/tasks?task_type=set_policy", headers={"x-api-key": TEST_API_KEY}
            )

            assert response.status_code == 201
            task_data = response.json()
            assert "task_id" in task_data

    @pytest.mark.asyncio
    async def test_sync_storage_task_unauthorized(self):
        """Test creating task without API key."""
        with TestClient(app) as test_client:
            response = test_client.post("/admin/tasks?task_type=set_policy")

            assert_error_response(response, 401, "Invalid or missing API Key")

    @pytest.mark.asyncio
    async def test_fetch_tasks_success(self):
        """Test fetching administrative tasks."""
        with TestClient(app) as test_client:
            response = test_client.get("/admin/tasks", headers={"x-api-key": TEST_API_KEY})

            assert response.status_code == 200
            tasks_data = response.json()
            assert "tasks" in tasks_data

    @pytest.mark.asyncio
    async def test_fetch_tasks_unauthorized(self):
        """Test fetching tasks without API key."""
        with TestClient(app) as test_client:
            response = test_client.get("/admin/tasks")

            assert_error_response(response, 401, "Invalid or missing API Key")

    @pytest.mark.asyncio
    async def test_check_task_status_unauthorized(self):
        """Test checking task status without API key."""
        with TestClient(app) as test_client:
            response = test_client.get("/admin/tasks/fake-task-id")

            assert_error_response(response, 401, "Invalid or missing API Key")
