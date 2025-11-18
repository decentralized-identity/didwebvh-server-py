"""Unit tests for the admin routes."""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from app import app
from app.plugins.storage import StorageManager
from tests.fixtures import (
    TEST_POLICY,
    TEST_WITNESS_INVITATION_PAYLOAD,
    TEST_WITNESS_INVITATION_URL,
    TEST_WITNESS_KEY,
    TEST_WITNESS_REGISTRY,
)
from tests.helpers import assert_error_response
from config import settings

# Setup test environment
storage = StorageManager()


def build_invitation(label: str, goal: str = "witness-service") -> tuple[dict, str]:
    """Construct a sample DIDComm invitation payload and encoded URL."""
    payload = {
        "@type": "https://didcomm.org/out-of-band/1.1/invitation",
        "@id": f"inv-{label.replace(' ', '-').lower()}",
        "label": label,
        "goal_code": goal,
        "services": [
            {
                "id": "#inline",
                "type": "did-communication",
                "serviceEndpoint": "https://witness.example.com/agent",
                "recipientKeys": [
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#recipient"
                ],
            }
        ],
    }
    encoded = (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    )
    return payload, f"https://witness.example.com/invite?oob={encoded}"


# Test API key
TEST_API_KEY = settings.WEBVH_ADMIN_API_KEY


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
    storage.create_or_update_witness_invitation(
        witness_did=f"did:key:{TEST_WITNESS_KEY}",
        invitation_url=TEST_WITNESS_INVITATION_URL,
        invitation_payload=TEST_WITNESS_INVITATION_PAYLOAD,
        invitation_id=TEST_WITNESS_INVITATION_PAYLOAD["@id"],
        label=TEST_WITNESS_INVITATION_PAYLOAD["label"],
    )
    yield


class TestWitnessRegistryEndpoints:
    """Test cases for witness registry management endpoints."""

    @pytest.mark.asyncio
    async def test_add_known_witness_success(self):
        """Test adding a new witness to the registry."""
        with TestClient(app) as test_client:
            new_witness_key = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            invitation_payload, service_endpoint = build_invitation("New Test Witness")

            response = test_client.post(
                "/admin/witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={
                    "id": f"did:key:{new_witness_key}",
                    "label": "New Test Witness",
                    "invitationUrl": service_endpoint,
                },
            )

            assert response.status_code == 200
            registry_data = response.json()
            assert "registry" in registry_data
            witness_did = f"did:key:{new_witness_key}"
            assert witness_did in registry_data["registry"]
            expected_short_url = f"https://{settings.DOMAIN}/api/invitations?_oobid={new_witness_key}"
            assert registry_data["registry"][witness_did]["name"] == invitation_payload["label"]
            assert registry_data["registry"][witness_did]["serviceEndpoint"] == expected_short_url
            stored_invitation = storage.get_witness_invitation(witness_did)
            assert stored_invitation is not None
            assert stored_invitation.invitation_url == service_endpoint
            assert stored_invitation.invitation_payload == invitation_payload

    @pytest.mark.asyncio
    async def test_add_known_witness_duplicate(self):
        """Test adding a duplicate witness (should fail)."""
        with TestClient(app) as test_client:
            # Try to add the same witness key again (fixture already added it)
            response = test_client.post(
                "/admin/witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={
                    "id": f"did:key:{TEST_WITNESS_KEY}",
                    "label": "Duplicate Witness",
                    "invitationUrl": build_invitation("Duplicate Witness")[1],
                },
            )

            assert_error_response(response, 409, "Witness already exists")

    @pytest.mark.asyncio
    async def test_add_known_witness_invalid_key(self):
        """Test adding an invalid multikey."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/admin/witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={
                    "id": "invalid-key-12345",
                    "label": "Invalid Witness",
                    "invitationUrl": build_invitation("Invalid Witness")[1],
                },
            )

            assert_error_response(response, 400, "Witness id must be a did:key identifier.")

    @pytest.mark.asyncio
    async def test_add_known_witness_unauthorized(self):
        """Test adding witness without API key."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/admin/witnesses",
                json={
                    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "label": "Unauthorized Witness",
                    "invitationUrl": build_invitation("Unauthorized Witness")[1],
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
                "/admin/witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={
                    "id": f"did:key:{new_witness_key}",
                    "label": "Witness to Remove",
                    "invitationUrl": build_invitation("Witness to Remove")[1],
                },
            )

            # Now remove it
            response = test_client.delete(
                f"/admin/witnesses/{new_witness_key}",
                headers={"x-api-key": TEST_API_KEY},
            )

            assert response.status_code == 200
            registry_data = response.json()
            witness_did = f"did:key:{new_witness_key}"
            assert witness_did not in registry_data["registry"]
            assert storage.get_witness_invitation(witness_did) is None

    @pytest.mark.asyncio
    async def test_remove_known_witness_not_found(self):
        """Test removing a non-existent witness."""
        with TestClient(app) as test_client:
            # Use a valid multikey format that doesn't exist in registry
            nonexistent_key = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"

            response = test_client.delete(
                f"/admin/witnesses/{nonexistent_key}",
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
                "/admin/witnesses/invalid-key", headers={"x-api-key": TEST_API_KEY}
            )

            assert_error_response(response, 400, "Invalid multikey")

    @pytest.mark.asyncio
    async def test_remove_known_witness_unauthorized(self):
        """Test removing witness without API key."""
        with TestClient(app) as test_client:
            response = test_client.delete(f"/admin/witnesses/{TEST_WITNESS_KEY}")

            assert_error_response(response, 401, "Invalid or missing API Key")

    @pytest.mark.asyncio
    async def test_add_known_witness_missing_oob(self):
        """Reject invitation URL without oob parameter."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/admin/witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={
                    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "label": "No OOB",
                    "invitationUrl": "https://witness.example.com/invite",
                },
            )

            assert_error_response(response, 400, "Invitation URL must include an 'oob' parameter.")

    @pytest.mark.asyncio
    async def test_add_known_witness_invalid_oob_payload(self):
        """Reject malformed base64 encoded invitations."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/admin/witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={
                    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "label": "Bad Payload",
                    "invitationUrl": "https://witness.example.com/invite?oob=!!!",
                },
            )

            assert_error_response(response, 400, "Invitation URL contained an invalid payload.")

    @pytest.mark.asyncio
    async def test_add_known_witness_missing_invitation_url(self):
        """Reject witness creation when invitation URL is omitted."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/admin/witnesses",
                headers={"x-api-key": TEST_API_KEY},
                json={
                    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "label": "No Invitation",
                },
            )

            assert_error_response(response, 400, "Invitation URL is required.")


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
