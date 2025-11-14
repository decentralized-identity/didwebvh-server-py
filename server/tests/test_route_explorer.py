"""Unit tests for the explorer router endpoints."""

import pytest
from fastapi.testclient import TestClient

from app import app
from app.plugins.storage import StorageManager
from app.db.models import KnownWitnessRegistry
from tests.fixtures import (
    TEST_POLICY,
    TEST_WITNESS_REGISTRY,
    TEST_WITNESS_SERVICE_ENDPOINT,
    TEST_WITNESS_KEY,
)
from tests.helpers import (
    create_unique_did,
    setup_controller_with_verification_method,
    create_test_resource,
    create_test_namespace_and_identifier,
)
from tests.mock_agents import ControllerAgent
from config import settings


@pytest.fixture(autouse=True)
async def setup_database():
    """Set up the database before each test."""
    storage = StorageManager()
    await storage.provision(recreate=True)

    # Store policy and registry in database
    storage.create_or_update_policy("active", TEST_POLICY)
    storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=TEST_WITNESS_REGISTRY,
        meta={"created": "2024-01-01T00:00:00Z", "updated": "2024-01-01T00:00:00Z"},
    )
    yield


def create_did_for_explorer(test_client: TestClient, test_name: str):
    """Helper to create a DID and return all necessary info for explorer tests."""
    namespace, identifier = create_test_namespace_and_identifier(test_name)
    did_webvh_id, doc_state = create_unique_did(test_client, namespace, identifier)
    scid = did_webvh_id.split(":")[2]  # Extract SCID from did:webvh:SCID:...
    return namespace, identifier, did_webvh_id, scid, doc_state


# Setup controller agent for resource tests
controller = ControllerAgent()


class TestExplorerIndex:
    """Test cases for the explorer index page."""

    @pytest.mark.asyncio
    async def test_explorer_index_html(self):
        """Test explorer index returns HTML template."""
        with TestClient(app) as test_client:
            response = test_client.get("/explorer/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_explorer_index_content(self):
        """Test explorer index contains expected content."""
        with TestClient(app) as test_client:
            response = test_client.get("/explorer/")
        assert response.status_code == 200
        # Basic check that it's the explorer page
        assert b"<!DOCTYPE html>" in response.content or b"<html" in response.content


class TestExplorerDIDTable:
    """Test cases for the DID table explorer endpoint."""

    @pytest.mark.asyncio
    async def test_dids_explorer_empty(self):
        """Test DID explorer returns empty results when no DIDs exist."""
        with TestClient(app) as test_client:
            response = test_client.get("/explorer/dids", headers={"Accept": "application/json"})
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data.get("results"), list)
        assert len(data.get("results")) == 0
        assert "pagination" in data

    @pytest.mark.asyncio
    async def test_dids_explorer_with_data(self):
        """Test DID explorer returns DIDs when they exist."""
        with TestClient(app) as test_client:
            # Create a test DID
            namespace, identifier, did_webvh_id, scid, _ = create_did_for_explorer(
                test_client, "explorer_with_data"
            )

            response = test_client.get("/explorer/dids", headers={"Accept": "application/json"})

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data.get("results"), list)
        assert len(data.get("results")) >= 1

        # Find our DID in results
        did_result = next((r for r in data["results"] if r["scid"] == scid), None)
        assert did_result is not None
        assert did_result["did"] == did_webvh_id
        assert did_result["namespace"] == namespace
        assert did_result["identifier"] == identifier
        assert "links" in did_result
        assert "logs" in did_result

    @pytest.mark.asyncio
    async def test_dids_explorer_filter_by_namespace(self):
        """Test DID explorer filtering by namespace."""
        with TestClient(app) as test_client:
            # Create DIDs in different namespaces
            namespace1, identifier1, did_id1, scid1, _ = create_did_for_explorer(
                test_client, "explorer_ns1"
            )
            namespace2, identifier2, did_id2, scid2, _ = create_did_for_explorer(
                test_client, "explorer_ns2"
            )

            # Filter by first namespace
            response = test_client.get(
                f"/explorer/dids?namespace={namespace1}", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        results = data.get("results", [])

        # All results should be from namespace1
        for result in results:
            assert result["namespace"] == namespace1

    @pytest.mark.asyncio
    async def test_dids_explorer_filter_by_scid(self):
        """Test DID explorer filtering by SCID."""
        with TestClient(app) as test_client:
            # Create a test DID
            namespace, identifier, did_id, scid, _ = create_did_for_explorer(
                test_client, "explorer_scid"
            )

            response = test_client.get(
                f"/explorer/dids?scid={scid}", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        results = data.get("results", [])
        assert len(results) == 1
        assert results[0]["scid"] == scid

    @pytest.mark.asyncio
    async def test_dids_explorer_filter_by_identifier(self):
        """Test DID explorer filtering by identifier."""
        with TestClient(app) as test_client:
            # Create a test DID
            namespace, identifier, did_id, scid, _ = create_did_for_explorer(
                test_client, "explorer_identifier"
            )

            response = test_client.get(
                f"/explorer/dids?identifier={identifier}", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        results = data.get("results", [])
        assert len(results) >= 1

        # Find our DID
        did_result = next((r for r in results if r["identifier"] == identifier), None)
        assert did_result is not None

    @pytest.mark.asyncio
    async def test_dids_explorer_filter_by_status_active(self):
        """Test DID explorer filtering by active status."""
        with TestClient(app) as test_client:
            # Create an active DID
            namespace, identifier, did_id, scid, _ = create_did_for_explorer(
                test_client, "explorer_active"
            )

            response = test_client.get(
                "/explorer/dids?status=active", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        results = data.get("results", [])

        # All results should be active (not deactivated)
        for result in results:
            assert result["active"] is True
            assert result["deactivated"] == "False"

    @pytest.mark.asyncio
    async def test_dids_explorer_pagination(self):
        """Test DID explorer pagination."""
        with TestClient(app) as test_client:
            # Create multiple DIDs
            for i in range(3):
                create_did_for_explorer(test_client, f"explorer_page_{i}")

            # Get first page with limit 2
            response = test_client.get(
                "/explorer/dids?page=1&limit=2", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()

        assert "pagination" in data
        pagination = data["pagination"]
        assert pagination["page"] == 1
        assert pagination["limit"] == 2
        assert pagination["total"] >= 3
        assert len(data["results"]) <= 2

    @pytest.mark.asyncio
    async def test_dids_explorer_html_response(self):
        """Test DID explorer returns HTML when Accept header is not JSON."""
        with TestClient(app) as test_client:
            response = test_client.get("/explorer/dids")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]


class TestExplorerResourceTable:
    """Test cases for the resource table explorer endpoint."""

    @pytest.mark.asyncio
    async def test_resources_explorer_empty(self):
        """Test resource explorer returns empty results when no resources exist."""
        with TestClient(app) as test_client:
            response = test_client.get(
                "/explorer/resources", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data.get("results"), list)
        assert len(data.get("results")) == 0
        assert "pagination" in data

    @pytest.mark.asyncio
    async def test_resources_explorer_with_data(self):
        """Test resource explorer returns resources when they exist."""
        with TestClient(app) as test_client:
            # Create a DID with a verification method and upload a resource
            namespace, identifier, did_webvh_id, scid, doc_state = create_did_for_explorer(
                test_client, "resource_explorer"
            )
            controller_agent, _ = controller_agent, _ = setup_controller_with_verification_method(
                test_client, namespace, identifier, doc_state
            )

            # Upload a resource
            resource_data, _ = create_test_resource(controller_agent, "TestSchema")
            response = test_client.post(
                f"/{namespace}/{identifier}/resources", json={"attestedResource": resource_data}
            )
            assert response.status_code == 201

            # Get resources from explorer
            response = test_client.get(
                "/explorer/resources", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data.get("results"), list)
        assert len(data.get("results")) >= 1

        # Find our resource
        resource_result = next((r for r in data["results"] if r["scid"] == scid), None)
        assert resource_result is not None
        assert resource_result["resource_type"] == "TestSchema"
        assert "author" in resource_result
        assert resource_result["author"]["scid"] == scid

    @pytest.mark.asyncio
    async def test_resources_explorer_filter_by_scid(self):
        """Test resource explorer filtering by SCID."""
        with TestClient(app) as test_client:
            # Create a DID with a verification method and upload a resource
            namespace, identifier, did_webvh_id, scid, doc_state = create_did_for_explorer(
                test_client, "resource_scid"
            )
            controller_agent, _ = setup_controller_with_verification_method(
                test_client, namespace, identifier, doc_state
            )

            # Upload a resource
            resource_data, _ = create_test_resource(controller_agent, "TestSchema")
            response = test_client.post(
                f"/{namespace}/{identifier}/resources", json={"attestedResource": resource_data}
            )
            assert response.status_code == 201

            # Filter by SCID
            response = test_client.get(
                f"/explorer/resources?scid={scid}", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        results = data.get("results", [])
        assert len(results) >= 1

        # All results should belong to this SCID
        for result in results:
            assert result["scid"] == scid

    @pytest.mark.asyncio
    async def test_resources_explorer_filter_by_resource_type(self):
        """Test resource explorer filtering by resource type."""
        with TestClient(app) as test_client:
            # Create a DID with a verification method and upload resources
            namespace, identifier, did_webvh_id, scid, doc_state = create_did_for_explorer(
                test_client, "resource_type"
            )
            controller_agent, _ = setup_controller_with_verification_method(
                test_client, namespace, identifier, doc_state
            )

            # Upload resources of different types
            resource1, _ = create_test_resource(
                controller_agent, "SchemaType1", {"name": "Schema1"}
            )
            test_client.post(
                f"/{namespace}/{identifier}/resources", json={"attestedResource": resource1}
            )

            resource2, _ = create_test_resource(
                controller_agent, "SchemaType2", {"name": "Schema2"}
            )
            test_client.post(
                f"/{namespace}/{identifier}/resources", json={"attestedResource": resource2}
            )

            # Filter by resource type
            response = test_client.get(
                "/explorer/resources?resource_type=SchemaType1",
                headers={"Accept": "application/json"},
            )

        assert response.status_code == 200
        data = response.json()
        results = data.get("results", [])

        # All results should be of the specified type
        for result in results:
            assert result["resource_type"] == "SchemaType1"

    @pytest.mark.asyncio
    async def test_resources_explorer_pagination(self):
        """Test resource explorer pagination."""
        with TestClient(app) as test_client:
            # Create a DID and upload multiple resources
            namespace, identifier, did_webvh_id, scid, doc_state = create_did_for_explorer(
                test_client, "resource_pagination"
            )
            controller_agent, _ = setup_controller_with_verification_method(
                test_client, namespace, identifier, doc_state
            )

            # Upload 3 resources
            for i in range(3):
                resource, _ = create_test_resource(
                    controller_agent, f"Schema{i}", {"name": f"Resource{i}"}
                )
                test_client.post(
                    f"/{namespace}/{identifier}/resources", json={"attestedResource": resource}
                )

            # Get first page with limit 2
            response = test_client.get(
                "/explorer/resources?page=1&limit=2", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()

        assert "pagination" in data
        pagination = data["pagination"]
        assert pagination["page"] == 1
        assert pagination["limit"] == 2
        assert pagination["total"] >= 3
        assert len(data["results"]) <= 2

    @pytest.mark.asyncio
    async def test_resources_explorer_html_response(self):
        """Test resource explorer returns HTML when Accept header is not JSON."""
        with TestClient(app) as test_client:
            response = test_client.get("/explorer/resources")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]


class TestExplorerIntegration:
    """Integration tests for explorer functionality."""

    @pytest.mark.asyncio
    async def test_explorer_did_with_resources(self):
        """Test explorer shows DIDs with their associated resources."""
        with TestClient(app) as test_client:
            # Create a DID with resources
            namespace, identifier, did_webvh_id, scid, doc_state = create_did_for_explorer(
                test_client, "integration_did_resources"
            )
            controller_agent, _ = setup_controller_with_verification_method(
                test_client, namespace, identifier, doc_state
            )

            # Upload a resource
            resource_data, _ = create_test_resource(controller_agent, "AnonCredsSchema")
            response = test_client.post(
                f"/{namespace}/{identifier}/resources", json={"attestedResource": resource_data}
            )
            assert response.status_code == 201

            # Get DID from explorer
            response = test_client.get(
                f"/explorer/dids?scid={scid}", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        results = data.get("results", [])
        assert len(results) == 1

        did_result = results[0]
        assert "resources" in did_result
        # Resources are not included in list view (loaded on-demand in detail modal)
        # This is a performance optimization to avoid N+1 queries
        assert isinstance(did_result["resources"], list)

    @pytest.mark.asyncio
    async def test_explorer_resource_links_to_did(self):
        """Test explorer resource links back to its DID."""
        with TestClient(app) as test_client:
            # Create a DID with a resource
            namespace, identifier, did_webvh_id, scid, doc_state = create_did_for_explorer(
                test_client, "integration_resource_did"
            )
            controller_agent, _ = setup_controller_with_verification_method(
                test_client, namespace, identifier, doc_state
            )

            # Upload a resource
            resource_data, _ = create_test_resource(controller_agent, "TestResource")
            response = test_client.post(
                f"/{namespace}/{identifier}/resources", json={"attestedResource": resource_data}
            )
            assert response.status_code == 201

            # Get resource from explorer
            response = test_client.get(
                f"/explorer/resources?scid={scid}", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        results = data.get("results", [])
        assert len(results) >= 1

        resource_result = results[0]
        assert "author" in resource_result
        assert resource_result["author"]["scid"] == scid
        assert resource_result["author"]["namespace"] == namespace
        assert resource_result["author"]["alias"] == identifier


class TestExplorerWitnessRegistry:
    """Test cases for the witness registry explorer endpoint."""

    @pytest.mark.asyncio
    async def test_witnesses_page_html(self):
        """Witness page should render with registry content."""
        with TestClient(app) as test_client:
            response = test_client.get("/explorer/witnesses")

        assert response.status_code == 200
        assert "Known Witness Registry" in response.text
        assert f"did:key:{TEST_WITNESS_KEY}" in response.text

    @pytest.mark.asyncio
    async def test_witnesses_json_response(self):
        """Witness endpoint should return structured JSON when requested."""
        with TestClient(app) as test_client:
            response = test_client.get(
                "/explorer/witnesses", headers={"Accept": "application/json"}
            )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == len(TEST_WITNESS_REGISTRY)
        assert "meta" in data
        assert data["meta"]["created"]

        witness_entry = data["results"][0]
        assert witness_entry["service_endpoint"] == TEST_WITNESS_SERVICE_ENDPOINT
        assert witness_entry["resolver_url"].startswith("https://")
        assert witness_entry["id"].startswith("did:key:")


class TestWellKnownWitnessRegistry:
    """Test cases for the well-known witness registry endpoint."""

    @pytest.mark.asyncio
    async def test_well_known_witness_registry_success(self):
        with TestClient(app) as test_client:
            response = test_client.get("/.well-known/witness.json")

        assert response.status_code == 200
        data = response.json()
        assert "registry" in data
        assert f"did:key:{TEST_WITNESS_KEY}" in data["registry"]

    @pytest.mark.asyncio
    async def test_well_known_witness_registry_not_found(self):
        storage = StorageManager()
        with storage.get_session() as session:
            registry = session.query(KnownWitnessRegistry).filter(
                KnownWitnessRegistry.registry_id == "knownWitnesses"
            ).first()
            if registry:
                session.delete(registry)
                session.commit()

        with TestClient(app) as test_client:
            response = test_client.get("/.well-known/witness.json")

        assert response.status_code == 404
        assert "Witness registry not found." in response.json().get("detail", "")


class TestWellKnownDidDocument:
    """Test cases for the well-known DID document endpoint."""

    @pytest.mark.asyncio
    async def test_well_known_did_success(self):
        with TestClient(app) as test_client:
            response = test_client.get("/.well-known/did.json")

        assert response.status_code == 200
        data = response.json()
        assert data.get("@context") == "https://www.w3.org/ns/did/v1"
        assert data.get("id") == f"did:web:{settings.DOMAIN}"
        assert len(data.get("service", [])) > 0
