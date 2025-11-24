"""Unit tests for the new_log_entry route in identifiers router."""

import pytest
from fastapi.testclient import TestClient

from app import app
from app.models.did_log import LogEntry
from app.plugins.storage import StorageManager

from tests.fixtures import (
    TEST_DID_NAMESPACE,
    TEST_VERSION_TIME,
    TEST_UPDATE_TIME,
    TEST_POLICY,
    TEST_WITNESS_REGISTRY,
    TEST_UPDATE_KEY,
    TEST_VERIFICATION_METHOD,
)
from tests.mock_agents import WitnessAgent, ControllerAgent
from tests.mock_agents import sign
from tests.helpers import (
    create_unique_did,
    setup_controller_with_verification_method,
    create_test_namespace_and_alias,
    assert_error_response,
)
from did_webvh.core.state import DocumentState

# Setup test agents
witness = WitnessAgent()
controller = ControllerAgent()


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


class TestNewLogEntryCreate:
    """Test cases for creating a new DID via new_log_entry route."""

    @pytest.mark.asyncio
    async def test_create_did_success(self):
        """Test successful creation of a new DID."""
        test_namespace, test_alias = create_test_namespace_and_alias("create01")

        with TestClient(app) as test_client:
            # Create DID (the helper returns the created DID, but we need to verify the creation response)
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Verify the DID was created successfully
            assert did_id is not None
            assert doc_state is not None
            assert doc_state.document.get("id") == did_id

            # Verify we can retrieve the DID log
            response = test_client.get(f"/{test_namespace}/{test_alias}/did.jsonl")
            assert response.status_code == 200
            log_entries = response.text.split("\n")[:-1]
            assert len(log_entries) == 1

    @pytest.mark.asyncio
    async def test_create_did_without_witness_signature(self):
        """Test creating a DID without witness signature (should fail policy)."""
        test_namespace, test_alias = create_test_namespace_and_alias("create02")

        with TestClient(app) as test_client:
            # Get DID template
            response = test_client.get(f"?namespace={test_namespace}&alias={test_alias}")
            assert response.status_code == 200

            document = response.json().get("state")
            parameters = response.json().get("parameters")
            parameters["updateKeys"] = [TEST_UPDATE_KEY]

            # Create log entry without witness configuration
            initial_state = DocumentState.initial(
                timestamp=TEST_VERSION_TIME,
                params=parameters,
                document=document,
            )
            initial_log_entry = sign(initial_state.history_line())

            # Try to create without witness signature (policy requires it)
            response = test_client.post(
                f"/{test_namespace}/{test_alias}",
                json={
                    "logEntry": initial_log_entry,
                    "witnessSignature": None,
                },
            )

            # Should fail policy check
            assert_error_response(response, 400, "Policy infraction")

    @pytest.mark.asyncio
    async def test_create_did_invalid_log_entry(self):
        """Test creating a DID with invalid log entry format."""
        test_namespace, test_alias = create_test_namespace_and_alias("create03")

        with TestClient(app) as test_client:
            # Try to create with malformed log entry
            response = test_client.post(
                f"/{test_namespace}/{test_alias}",
                json={
                    "logEntry": {"invalid": "data"},
                    "witnessSignature": None,
                },
            )

            # Should return error
            assert response.status_code in [400, 422]


class TestNewLogEntryUpdate:
    """Test cases for updating an existing DID via new_log_entry route."""

    @pytest.mark.asyncio
    async def test_update_did_success(self):
        """Test successful update of an existing DID."""
        test_namespace, test_alias = create_test_namespace_and_alias("update01")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Prepare updated document
            updated_document = doc_state.document.copy()
            updated_document["@context"].append("https://www.w3.org/ns/cid/v1")
            updated_document["assertionMethod"] = [TEST_VERIFICATION_METHOD.get("id")]
            updated_document["verificationMethod"] = [TEST_VERIFICATION_METHOD]

            new_state = doc_state.create_next(
                timestamp=TEST_UPDATE_TIME,
                document=updated_document,
                params_update=None,
            )

            next_log_entry = sign(new_state.history_line())
            witness_signature = witness.create_log_entry_proof(next_log_entry)

            # Update the DID
            response = test_client.post(
                f"/{test_namespace}/{test_alias}",
                json={
                    "logEntry": next_log_entry,
                    "witnessSignature": witness_signature,
                },
            )

            assert response.status_code == 200
            assert LogEntry.model_validate(response.json())

            # Verify the log now has 2 entries
            response = test_client.get(f"/{test_namespace}/{test_alias}/did.jsonl")
            log_entries = response.text.split("\n")[:-1]
            assert len(log_entries) == 2

    @pytest.mark.asyncio
    async def test_update_did_invalid_proof(self):
        """Test updating a DID with invalid proof should fail."""
        test_namespace, test_alias = create_test_namespace_and_alias("update-invalid-proof")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Create an update with invalid/tampered proof
            updated_document = doc_state.document.copy()
            new_state = doc_state.create_next(
                timestamp=TEST_UPDATE_TIME,
                document=updated_document,
                params_update=None,
            )

            next_log_entry = sign(new_state.history_line())
            # Tamper with the proof
            next_log_entry["proof"][0]["proofValue"] = "z" + "1" * 87

            witness_signature = witness.create_log_entry_proof(next_log_entry)

            # Try to update with invalid proof
            response = test_client.post(
                f"/{test_namespace}/{test_alias}",
                json={
                    "logEntry": next_log_entry,
                    "witnessSignature": witness_signature,
                },
            )

            # Should fail validation
            assert response.status_code == 400


class TestNewLogEntryDeactivation:
    """Test cases for deactivating a DID via new_log_entry route."""

    @pytest.mark.asyncio
    async def test_deactivate_did(self):
        """Test deactivating a DID."""
        test_namespace, test_alias = create_test_namespace_and_alias("deactivate01")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Create deactivation update
            updated_document = doc_state.document.copy()
            params_update = {"deactivated": True}

            new_state = doc_state.create_next(
                timestamp=TEST_UPDATE_TIME,
                document=updated_document,
                params_update=params_update,
            )

            deactivate_log_entry = sign(new_state.history_line())
            witness_signature = witness.create_log_entry_proof(deactivate_log_entry)

            # Deactivate the DID
            response = test_client.post(
                f"/{test_namespace}/{test_alias}",
                json={
                    "logEntry": deactivate_log_entry,
                    "witnessSignature": witness_signature,
                },
            )

            # Should succeed
            assert response.status_code == 200
            # Verify deactivated parameter is set
            assert response.json().get("parameters", {}).get("deactivated") is True


class TestNewLogEntryValidation:
    """Test cases for request validation."""

    @pytest.mark.asyncio
    async def test_missing_log_entry_field(self):
        """Test request with missing logEntry field."""
        with TestClient(app) as test_client:
            response = test_client.post(
                f"/{TEST_DID_NAMESPACE}/test99",
                json={"witnessSignature": None},
            )
            # Should return validation error
            assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_empty_request_body(self):
        """Test request with empty body."""
        with TestClient(app) as test_client:
            response = test_client.post(
                f"/{TEST_DID_NAMESPACE}/test99",
                json={},
            )
            # Should return validation error
            assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_namespace_path_parameters(self):
        """Test that namespace and alias are properly extracted from path."""
        test_namespace, test_alias = create_test_namespace_and_alias("params01")

        with TestClient(app) as test_client:
            # Create DID and verify namespace/identifier are in the DID state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Verify the DID contains the correct namespace and identifier
            assert test_namespace in did_id or test_alias in did_id
            assert doc_state is not None


class TestUpdateWhois:
    """Test cases for updating WHOIS verifiable presentation."""

    def create_whois_presentation(self, did_id: str, verification_method_id: str):
        """Helper method to create a valid WHOIS verifiable presentation."""
        # Create the verifiable credential first (self-signed)
        credential = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2",
            ],
            "type": ["VerifiableCredential", "WhoisCredential"],
            "issuer": did_id,
            "validFrom": "2025-01-01T00:00:00Z",
            "credentialSubject": {
                "id": did_id,
                "name": "Test Organization",
                "email": "contact@example.com",
                "website": "https://example.com",
            },
        }

        # Sign the credential with the DID's verification method
        signed_credential = sign(credential, verification_method=verification_method_id)

        # Create the presentation
        presentation = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": did_id,
            "verifiableCredential": [signed_credential],
        }

        # Sign the presentation with authentication purpose
        proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "authentication",  # Important: authentication for presentations
        }

        signed_vp = sign(
            presentation, options=proof_options, verification_method=verification_method_id
        )
        return signed_vp

    @pytest.mark.asyncio
    async def test_update_whois_success(self):
        """Test successful WHOIS update with valid verifiable presentation."""
        test_namespace, test_alias = create_test_namespace_and_alias("whois01")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Create WHOIS presentation
            whois_presentation = self.create_whois_presentation(did_id, verification_method_id)

            # Update WHOIS
            response = test_client.post(
                f"/{test_namespace}/{test_alias}/whois",
                json={"verifiablePresentation": whois_presentation},
            )
            assert response.status_code == 200

            # Verify WHOIS was stored
            response = test_client.get(f"/{test_namespace}/{test_alias}/whois.vp")
            assert response.status_code == 200
            stored_whois = response.json()
            assert stored_whois["type"] == ["VerifiablePresentation"]
            assert stored_whois["holder"] == did_id

    @pytest.mark.asyncio
    async def test_update_whois_invalid_holder(self):
        """Test WHOIS update with verification method from wrong DID."""
        test_namespace, test_alias = create_test_namespace_and_alias("whois02")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Create WHOIS presentation with wrong verification method
            wrong_verification_method = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            whois_vp = self.create_whois_presentation(did_id, wrong_verification_method)

            response = test_client.post(
                f"/{test_namespace}/{test_alias}/whois",
                json={"verifiablePresentation": whois_vp},
            )

            # Should fail with invalid holder
            assert_error_response(response, 400, "Invalid holder.")

    @pytest.mark.asyncio
    async def test_update_whois_invalid_verification_method(self):
        """Test WHOIS update with verification method not in DID document."""
        test_namespace, test_alias = create_test_namespace_and_alias("whois-invalid-vm")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Create WHOIS VP with a DIFFERENT non-existent verification method
            nonexistent_vm = f"{did_id}#nonExistentKey123"
            whois_vp = self.create_whois_presentation(did_id, nonexistent_vm)

            response = test_client.post(
                f"/{test_namespace}/{test_alias}/whois",
                json={"verifiablePresentation": whois_vp},
            )

            # Should fail with invalid verification method
            assert_error_response(response, 400, "Invalid verification method.")

    @pytest.mark.asyncio
    async def test_update_whois_verification_failed(self):
        """Test WHOIS update with invalid proof signature."""
        test_namespace, test_alias = create_test_namespace_and_alias("whois04")

        with TestClient(app) as test_client:
            # Create DID and get document state
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Set up controller with verification method
            controller, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_alias, doc_state
            )

            # Create WHOIS VP with correct structure but invalid signature
            whois_vp = self.create_whois_presentation(did_id, verification_method_id)

            # Tamper with the proof to make verification fail
            whois_vp["proof"][0]["proofValue"] = "z" + "1" * 87

            response = test_client.post(
                f"/{test_namespace}/{test_alias}/whois",
                json={"verifiablePresentation": whois_vp},
            )

            # Should fail verification
            assert response.status_code == 400
            # The verifier raises HTTPException with 'detail' key, not 'Reason'
            error_message = response.json().get("detail", "")
            assert (
                "Error verifying proof" in error_message or "Verification failed" in error_message
            )

    @pytest.mark.asyncio
    async def test_update_whois_missing_fields(self):
        """Test WHOIS update with missing required fields."""
        test_namespace, test_alias = create_test_namespace_and_alias("whois05")

        with TestClient(app) as test_client:
            # Create DID
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_alias)

            # Try to update WHOIS with missing verifiablePresentation
            response = test_client.post(
                f"/{test_namespace}/{test_alias}/whois",
                json={},
            )

            # Should return validation error
            assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_update_whois_nonexistent_did(self):
        """Test WHOIS update for non-existent DID."""
        with TestClient(app) as test_client:
            whois_vp = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": "did:webvh:nonexistent",
                "verifiableCredential": [],
                "proof": [
                    {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-jcs-2022",
                        "proofPurpose": "authentication",
                        "verificationMethod": "did:webvh:nonexistent#key-1",
                        "proofValue": "z" + "5" * 87,
                    }
                ],
            }

            response = test_client.post(
                f"/{TEST_DID_NAMESPACE}/nonexistent999/whois",
                json={"verifiablePresentation": whois_vp},
            )

            # Should return 404 or 400 for non-existent DID
            assert response.status_code in [404, 400]
