"""Unit tests for SQLAlchemy database operations via StorageManager."""

import json
import time
import pytest

from app.plugins.storage import StorageManager
from app.db.models import (
    DidControllerRecord,
    AttestedResourceRecord,
    AdminBackgroundTask,
    ServerPolicy,
    KnownWitnessRegistry,
)
from tests.fixtures import (
    TEST_DID_IDENTIFIER,
    TEST_DID_NAMESPACE,
    TEST_VERSION_TIME,
    TEST_UPDATE_TIME,
    TEST_POLICY,
    TEST_WITNESS_KEY,
    TEST_WITNESS_REGISTRY,
    TEST_UPDATE_KEY,
)
from tests.mock_agents import WitnessAgent, ControllerAgent, sign, digest_multibase
from did_webvh.core.state import DocumentState
from config import settings

# Note: Policy and registry are now stored in SQLAlchemy database
# The setup_storage() helper will provision the database and add them

witness = WitnessAgent()
controller = ControllerAgent()


# Helper functions for database tests
async def setup_storage():
    """Helper to create and provision a StorageManager instance."""

    storage = StorageManager()
    await storage.provision(recreate=True)

    # Set up policy and registry in database
    storage.create_or_update_policy("active", TEST_POLICY)
    storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=TEST_WITNESS_REGISTRY,
        meta={"created": "2024-01-01T00:00:00Z", "updated": "2024-01-01T00:00:00Z"},
    )

    return storage


def create_test_did_logs(namespace=TEST_DID_NAMESPACE, identifier=TEST_DID_IDENTIFIER):
    """Helper to create test DID log entries."""
    placeholder_id = f"did:webvh:{{SCID}}:{settings.DOMAIN}:{namespace}:{identifier}"
    document = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": placeholder_id,
    }

    parameters = {
        "method": "did:webvh:0.3",
        "updateKeys": [TEST_UPDATE_KEY],
        "witness": {
            "threshold": 1,
            "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
        },
    }

    initial_state = DocumentState.initial(
        timestamp=TEST_VERSION_TIME,
        params=parameters,
        document=document,
    )
    initial_log_entry = sign(initial_state.history_line())

    return [initial_log_entry]


async def create_test_did_controller(storage=None, namespace=None, identifier=None):
    """Helper to create a test DID controller with unique identifier."""
    if storage is None:
        storage = await setup_storage()

    # Generate unique identifier if not provided
    if namespace is None or identifier is None:
        timestamp = str(int(time.time() * 1000))[-6:]
        namespace = namespace or f"{TEST_DID_NAMESPACE}-{timestamp}"
        identifier = identifier or f"{TEST_DID_IDENTIFIER}-{timestamp}"

    logs = create_test_did_logs(namespace, identifier)
    return storage.create_did_controller(logs)


def create_test_attested_resource(did, resource_id, content=None):
    """Helper to create a test attested resource structure."""
    if content is None:
        content = {"name": "Test Resource", "value": 42}

    return {
        "@context": [
            "https://identity.foundation/didwebvh/contexts/v1",
            "https://w3id.org/security/data-integrity/v2",
        ],
        "type": ["AttestedResource"],
        "id": f"{did}/resources/{resource_id}",
        "content": content,
        "metadata": {
            "resourceId": resource_id,
            "resourceType": "testResource",
        },
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{did}#key-0",
            "proofValue": "z" + "5" * 87,
        },
    }


class TestDatabaseProvisioning:
    """Test cases for database setup and teardown."""

    @pytest.mark.asyncio
    async def test_provision_database(self):
        """Test database provisioning creates all tables."""
        storage = await setup_storage()

        # Verify tables exist by attempting to query them
        session = storage.get_session()
        try:
            # Should not raise an error if tables exist
            session.query(DidControllerRecord).count()
            session.query(AttestedResourceRecord).count()
            session.query(AdminBackgroundTask).count()
            session.query(ServerPolicy).count()
            session.query(KnownWitnessRegistry).count()
        finally:
            session.close()

    def test_singleton_pattern(self):
        """Test StorageManager follows singleton pattern."""
        storage1 = StorageManager()
        storage2 = StorageManager()

        assert storage1 is storage2
        assert storage1.engine is storage2.engine

    def test_session_management(self):
        """Test session creation and management."""
        storage = StorageManager()
        session = storage.get_session()

        assert session is not None
        # Session should be usable
        assert session.bind is not None

        session.close()


class TestDidControllerOperations:
    """Test cases for DID Controller CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_did_controller(self):
        """Test creating a DID controller record."""
        storage = await setup_storage()

        # Use explicit namespace/identifier for this test
        logs = create_test_did_logs(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
        controller = storage.create_did_controller(logs)

        assert controller is not None
        assert controller.scid is not None
        assert controller.did is not None
        assert controller.namespace == TEST_DID_NAMESPACE
        assert controller.alias == TEST_DID_IDENTIFIER
        assert controller.logs == logs
        assert controller.deactivated is False

    @pytest.mark.asyncio
    async def test_get_did_controller_by_scid(self):
        """Test retrieving DID controller by SCID."""
        storage = await setup_storage()

        created = await create_test_did_controller(storage)

        fetched = storage.get_did_controller_by_scid(created.scid)

        assert fetched is not None
        assert fetched.scid == created.scid
        assert fetched.did == created.did
        assert fetched.namespace == created.namespace

    @pytest.mark.asyncio
    async def test_get_did_controller_by_alias(self):
        """Test retrieving DID controller by namespace and alias."""
        storage = await setup_storage()

        # Use explicit namespace/identifier for this test
        created = await create_test_did_controller(storage, TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)

        fetched = storage.get_did_controller_by_alias(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)

        assert fetched is not None
        assert fetched.scid == created.scid
        assert fetched.namespace == TEST_DID_NAMESPACE
        assert fetched.alias == TEST_DID_IDENTIFIER

    @pytest.mark.asyncio
    async def test_update_did_controller(self):
        """Test updating a DID controller record."""
        storage = await setup_storage()

        logs = create_test_did_logs()
        created = storage.create_did_controller(logs)

        # Create updated logs
        doc_state = DocumentState.load_history_json(json.dumps(logs[0]), None)
        updated_document = doc_state.document.copy()
        updated_document["@context"].append("https://www.w3.org/ns/cid/v1")

        new_state = doc_state.create_next(
            timestamp=TEST_UPDATE_TIME,
            document=updated_document,
            params_update=None,
        )
        updated_logs = logs + [sign(new_state.history_line())]

        # Update the controller
        updated = storage.update_did_controller(created.scid, logs=updated_logs)

        assert updated is not None
        assert len(updated.logs) == 2
        assert updated.scid == created.scid

    @pytest.mark.asyncio
    async def test_get_did_controllers_with_filters(self):
        """Test retrieving DID controllers with filters."""
        storage = await setup_storage()

        # Create controller with explicit namespace for filtering
        controller1 = await create_test_did_controller(
            storage, TEST_DID_NAMESPACE, "filter-test-01"
        )

        # Get with namespace filter
        results = storage.get_did_controllers(filters={"namespace": TEST_DID_NAMESPACE})

        assert len(results) > 0
        assert all(c.namespace == TEST_DID_NAMESPACE for c in results)

    @pytest.mark.asyncio
    async def test_count_did_controllers(self):
        """Test counting DID controllers."""
        storage = await setup_storage()

        # Use explicit namespace for filtering test
        await create_test_did_controller(storage, TEST_DID_NAMESPACE, "count-test-01")

        count = storage.count_did_controllers()
        assert count >= 1

        count_with_filter = storage.count_did_controllers(filters={"namespace": TEST_DID_NAMESPACE})
        assert count_with_filter >= 1

    @pytest.mark.asyncio
    async def test_did_controller_pagination(self):
        """Test DID controller pagination."""
        storage = await setup_storage()

        # Create multiple controllers with unique identifiers
        for i in range(5):
            # Create unique placeholder_id for each controller
            placeholder_id = (
                f"did:webvh:{{SCID}}:{settings.DOMAIN}:{TEST_DID_NAMESPACE}:pagination-{i:02d}"
            )
            document = {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": placeholder_id,
            }

            parameters = {
                "method": "did:webvh:0.3",
                "updateKeys": [TEST_UPDATE_KEY],
                "witness": {
                    "threshold": 1,
                    "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
                },
            }

            initial_state = DocumentState.initial(
                timestamp=f"2025-06-19T03:{i:02d}:19Z",  # Unique timestamp
                params=parameters,
                document=document,
            )
            initial_log_entry = sign(initial_state.history_line())
            storage.create_did_controller([initial_log_entry])

        # Test pagination
        page1 = storage.get_did_controllers(limit=2, offset=0)
        page2 = storage.get_did_controllers(limit=2, offset=2)

        assert len(page1) <= 2
        assert len(page2) <= 2

        # Ensure pages don't overlap
        if len(page1) > 0 and len(page2) > 0:
            assert page1[0].scid != page2[0].scid


class TestResourceOperations:
    """Test cases for Resource CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_resource(self):
        """Test creating an attested resource."""
        storage = await setup_storage()

        # Create a DID controller first
        did_controller = await create_test_did_controller(storage)

        # Create resource content and calculate digest
        content = {"name": "Test Resource", "value": 42}
        resource_digest = digest_multibase(content)

        # Create resource using helper
        attested_resource = create_test_attested_resource(
            did_controller.did, resource_digest, content
        )

        resource = storage.create_resource(did_controller.scid, attested_resource)

        assert resource is not None
        assert resource.resource_id == resource_digest
        assert resource.scid == did_controller.scid
        assert resource.resource_type == "testResource"

    @pytest.mark.asyncio
    async def test_get_resource(self):
        """Test retrieving a resource by ID."""
        storage = await setup_storage()

        # Create DID and resource
        did_controller = await create_test_did_controller(storage)

        # Create resource with proper digest
        content = {"test": "data"}
        resource_digest = digest_multibase(content)

        attested_resource = create_test_attested_resource(
            did_controller.did, resource_digest, content
        )

        created = storage.create_resource(did_controller.scid, attested_resource)
        fetched = storage.get_resource(resource_digest)

        assert fetched is not None
        assert fetched.resource_id == created.resource_id
        assert fetched.scid == created.scid

    @pytest.mark.asyncio
    async def test_get_resources_with_filters(self):
        """Test retrieving resources with filters."""
        storage = await setup_storage()

        # Create DID and resources
        did_controller = await create_test_did_controller(storage)

        # Create multiple resources with proper digests
        for i in range(3):
            content = {"index": i}
            resource_digest = digest_multibase(content)

            attested_resource = create_test_attested_resource(
                did_controller.did, resource_digest, content
            )
            storage.create_resource(did_controller.scid, attested_resource)

        # Get resources by SCID
        resources = storage.get_resources(filters={"scid": did_controller.scid})

        assert len(resources) == 3
        assert all(r.scid == did_controller.scid for r in resources)

    @pytest.mark.asyncio
    async def test_update_resource(self):
        """Test updating a resource."""
        storage = await setup_storage()

        # Create DID and resource
        did_controller = await create_test_did_controller(storage)

        # Create resource with proper digest
        content = {"version": 1}
        resource_digest = digest_multibase(content)

        attested_resource = create_test_attested_resource(
            did_controller.did, resource_digest, content
        )

        created = storage.create_resource(did_controller.scid, attested_resource)

        # Update resource (add links - content stays same so digest unchanged)
        attested_resource["links"] = [
            {"id": f"{did_controller.did}/resources/related", "type": "related"}
        ]

        updated = storage.update_resource(attested_resource)

        assert updated is not None
        assert updated.resource_id == created.resource_id
        assert "links" in updated.attested_resource

    @pytest.mark.asyncio
    async def test_delete_resource(self):
        """Test deleting a resource."""
        storage = await setup_storage()

        # Create DID and resource
        did_controller = await create_test_did_controller(storage)

        # Create resource with proper digest
        content = {"test": "data"}
        resource_digest = digest_multibase(content)

        attested_resource = create_test_attested_resource(
            did_controller.did, resource_digest, content
        )

        storage.create_resource(did_controller.scid, attested_resource)

        # Delete resource
        result = storage.delete_resource(resource_digest)
        assert result is True

        # Verify deletion
        fetched = storage.get_resource(resource_digest)
        assert fetched is None


class TestTaskOperations:
    """Test cases for Task CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_task(self):
        """Test creating a background task."""
        storage = await setup_storage()

        task = storage.create_task(
            task_id="task001",
            task_type="test_task",
            status="pending",
            progress={"test": "data"},
            message="Test task created",
        )

        assert task is not None
        assert task.task_id == "task001"
        assert task.task_type == "test_task"
        assert task.status == "pending"
        assert task.progress == {"test": "data"}
        assert task.message == "Test task created"

    @pytest.mark.asyncio
    async def test_get_task(self):
        """Test retrieving a task by ID."""
        storage = await setup_storage()

        created = storage.create_task(
            task_id="task002",
            task_type="test_task",
            status="running",
        )

        fetched = storage.get_task("task002")

        assert fetched is not None
        assert fetched.task_id == created.task_id
        assert fetched.status == "running"

    @pytest.mark.asyncio
    async def test_update_task(self):
        """Test updating a task status."""
        storage = await setup_storage()

        task = storage.create_task(
            task_id="task003",
            task_type="test_task",
            status="pending",
        )

        # Update status
        updated = storage.update_task("task003", status="completed")

        assert updated is not None
        assert updated.status == "completed"

    @pytest.mark.asyncio
    async def test_get_tasks_with_filters(self):
        """Test retrieving tasks with filters."""
        storage = await setup_storage()

        # Create multiple tasks
        storage.create_task("task004", "type1", "pending")
        storage.create_task("task005", "type1", "completed")
        storage.create_task("task006", "type2", "pending")

        # Filter by status
        pending_tasks = storage.get_tasks(filters={"status": "pending"})
        assert len(pending_tasks) >= 2
        assert all(t.status == "pending" for t in pending_tasks)

        # Filter by type
        type1_tasks = storage.get_tasks(filters={"task_type": "type1"})
        assert len(type1_tasks) >= 2
        assert all(t.task_type == "type1" for t in type1_tasks)

    @pytest.mark.asyncio
    async def test_delete_task(self):
        """Test deleting a task."""
        storage = await setup_storage()

        storage.create_task("task007", "test_task", "pending")

        result = storage.delete_task("task007")
        assert result is True

        fetched = storage.get_task("task007")
        assert fetched is None


class TestPolicyAndRegistryOperations:
    """Test cases for Policy and Registry operations."""

    @pytest.mark.asyncio
    async def test_create_or_update_policy(self):
        """Test creating and updating a policy."""
        storage = await setup_storage()

        policy_data = {
            "version": "1.0",
            "witness": True,
            "portability": False,
        }

        # Create policy
        policy = storage.create_or_update_policy("test_policy", policy_data)

        assert policy is not None
        assert policy.policy_id == "test_policy"
        assert policy.version == "1.0"
        assert policy.witness is True
        assert policy.portability is False

        # Update policy
        policy_data["version"] = "2.0"
        updated = storage.create_or_update_policy("test_policy", policy_data)

        assert updated.version == "2.0"

    @pytest.mark.asyncio
    async def test_get_policy(self):
        """Test retrieving a policy."""
        storage = await setup_storage()

        policy_data = {"version": "1.0", "witness": True}
        storage.create_or_update_policy("policy001", policy_data)

        fetched = storage.get_policy("policy001")

        assert fetched is not None
        assert fetched.policy_id == "policy001"
        assert fetched.version == "1.0"
        assert fetched.witness is True

    @pytest.mark.asyncio
    async def test_create_or_update_registry(self):
        """Test creating and updating a witness registry."""
        storage = await setup_storage()

        registry_data = {"did:key:z6Mktest": {"name": "Test Witness", "url": "https://example.com"}}

        # Create registry
        registry = storage.create_or_update_registry("test_registry", "witness", registry_data)

        assert registry is not None
        assert registry.registry_id == "test_registry"
        assert registry.registry_type == "witness"
        assert "did:key:z6Mktest" in registry.registry_data

        # Update registry
        registry_data["did:key:z6Mktest"]["name"] = "Updated Witness"
        updated = storage.create_or_update_registry("test_registry", "witness", registry_data)

        assert updated.registry_data["did:key:z6Mktest"]["name"] == "Updated Witness"

    @pytest.mark.asyncio
    async def test_get_registry(self):
        """Test retrieving a registry."""
        storage = await setup_storage()

        registry_data = {"did:key:z6Mktest": {"name": "Test Witness"}}
        storage.create_or_update_registry("reg001", "witness", registry_data)

        fetched = storage.get_registry("reg001")

        assert fetched is not None
        assert fetched.registry_id == "reg001"
        assert fetched.registry_type == "witness"
        assert fetched.registry_data["did:key:z6Mktest"]["name"] == "Test Witness"


class TestWitnessAndWhoisOperations:
    """Test cases for witness file and WHOIS operations."""

    @pytest.mark.asyncio
    async def test_create_or_update_witness_file(self):
        """Test creating/updating witness file."""
        storage = await setup_storage()

        # Create DID first
        did_controller = await create_test_did_controller(storage)

        witness_proofs = [
            {
                "versionId": "test_version_1",
                "proof": [
                    {
                        "type": "DataIntegrityProof",
                        "verificationMethod": f"did:key:{TEST_WITNESS_KEY}",
                        "proofValue": "z" + "5" * 87,
                    }
                ],
            }
        ]

        updated = storage.create_or_update_witness_file(did_controller.scid, witness_proofs)

        assert updated is not None
        assert updated.witness_file == witness_proofs

    @pytest.mark.asyncio
    async def test_get_witness_file(self):
        """Test retrieving witness file."""
        storage = await setup_storage()

        did_controller = await create_test_did_controller(storage)

        witness_proofs = [{"test": "witness"}]
        storage.create_or_update_witness_file(did_controller.scid, witness_proofs)

        fetched = storage.get_witness_file(did_controller.scid)

        assert fetched is not None
        assert fetched.witness_file == witness_proofs

    @pytest.mark.asyncio
    async def test_create_or_update_whois(self):
        """Test creating/updating WHOIS presentation."""
        storage = await setup_storage()

        did_controller = await create_test_did_controller(storage)

        whois_presentation = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": did_controller.did,
            "verifiableCredential": [],
            "proof": [
                {
                    "type": "DataIntegrityProof",
                    "verificationMethod": f"{did_controller.did}#key-0",
                    "proofValue": "z" + "5" * 87,
                }
            ],
        }

        updated = storage.create_or_update_whois(did_controller.scid, whois_presentation)

        assert updated is not None
        assert updated.whois_presentation == whois_presentation

    @pytest.mark.asyncio
    async def test_get_whois(self):
        """Test retrieving WHOIS presentation."""
        storage = await setup_storage()

        did_controller = await create_test_did_controller(storage)

        whois_presentation = {"test": "whois"}
        storage.create_or_update_whois(did_controller.scid, whois_presentation)

        fetched = storage.get_whois(did_controller.scid)

        assert fetched is not None
        assert fetched.whois_presentation == whois_presentation

    @pytest.mark.asyncio
    async def test_get_whois_by_identifier(self):
        """Test retrieving WHOIS by namespace and identifier."""
        storage = await setup_storage()

        did_controller = await create_test_did_controller(storage)

        whois_presentation = {"test": "whois"}
        storage.create_or_update_whois(did_controller.scid, whois_presentation)

        fetched = storage.get_whois_by_identifier(did_controller.namespace, did_controller.alias)

        assert fetched is not None
        assert fetched.whois_presentation == whois_presentation
