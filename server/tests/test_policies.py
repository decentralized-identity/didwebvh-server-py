"""Tests for policy validation and enforcement.

This file focuses on testing policy validation logic, particularly witness policy.
Policy CRUD operations are tested in test_route_admin.py.
"""

import pytest
from fastapi.testclient import TestClient
from did_webvh.core.state import DocumentState

from aries_askar import Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from multiformats import multibase

from tests.fixtures import (
    TEST_POLICY,
    TEST_WITNESS_KEY,
    TEST_UNKNOWN_WITNESS_SEED,
    TEST_UNKNOWN_WITNESS_KEY,
    TEST_WITNESS_REGISTRY,
    TEST_UPDATE_KEY,
    TEST_VERSION_TIME,
    TEST_UPDATE_TIME,
)
from tests.mock_agents import WitnessAgent, sign, transform
from tests.helpers import create_test_namespace_and_identifier
from app.plugins.storage import StorageManager


@pytest.fixture
def witness_policy_client(test_client: TestClient):
    """Test client with witness policy enforced and known witness registered."""
    storage = StorageManager()

    # Set up policy requiring witness
    policy_data = {
        "version": "1.0",
        "witness": True,
        "watcher": None,
        "portability": True,
        "prerotation": True,
        "endorsement": False,
        "validity": 0,
        "witness_registry_url": None,
    }
    storage.create_or_update_policy("active", policy_data)

    # Register known witness
    meta = {"created": TEST_VERSION_TIME, "updates": TEST_VERSION_TIME}
    storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=TEST_WITNESS_REGISTRY,
        meta=meta,
    )

    yield test_client

    # Cleanup: restore default test policy
    storage.create_or_update_policy("active", TEST_POLICY)


class TestWitnessPolicy:
    """Test witness policy enforcement."""

    def test_create_did_with_witness_signature(self, witness_policy_client: TestClient):
        """Test that DID can be created with valid witness signature."""
        namespace, identifier = create_test_namespace_and_identifier("witness_valid")

        # Get DID template
        response = witness_policy_client.get(f"?namespace={namespace}&identifier={identifier}")
        assert response.status_code == 200

        document = response.json().get("state")
        parameters = response.json().get("parameters")

        # Configure with witness
        parameters["updateKeys"] = [TEST_UPDATE_KEY]
        parameters["witness"] = {
            "threshold": 1,
            "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
        }

        # Create initial state and log entry
        initial_state = DocumentState.initial(
            timestamp=TEST_VERSION_TIME,
            params=parameters,
            document=document,
        )
        initial_log_entry = sign(initial_state.history_line())

        # Create witness signature
        witness = WitnessAgent()
        witness_signature = witness.create_log_entry_proof(initial_log_entry)

        # Submit DID creation with witness signature
        response = witness_policy_client.post(
            f"/{namespace}/{identifier}",
            json={
                "logEntry": initial_log_entry,
                "witnessSignature": witness_signature,
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert "state" in data
        assert "id" in data["state"]
        assert "did:webvh:" in data["state"]["id"]

    def test_create_did_with_unknown_witness_signature_fails(
        self, witness_policy_client: TestClient
    ):
        """Test that DID creation fails when witness is not in the known registry."""
        namespace, identifier = create_test_namespace_and_identifier("unknown_witness")

        # Get DID template
        response = witness_policy_client.get(f"?namespace={namespace}&identifier={identifier}")
        assert response.status_code == 200

        document = response.json().get("state")
        parameters = response.json().get("parameters")

        # Use TEST_UNKNOWN_WITNESS_KEY (not in registry)
        unknown_witness_did = f"did:key:{TEST_UNKNOWN_WITNESS_KEY}"

        # Configure with the UNKNOWN witness
        parameters["updateKeys"] = [TEST_UPDATE_KEY]
        parameters["witness"] = {
            "threshold": 1,
            "witnesses": [{"id": unknown_witness_did}],
        }

        # Create initial state and log entry
        initial_state = DocumentState.initial(
            timestamp=TEST_VERSION_TIME,
            params=parameters,
            document=document,
        )
        initial_log_entry = sign(initial_state.history_line())

        # Create witness signature using the unknown witness key
        unknown_key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_UNKNOWN_WITNESS_SEED)

        proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{unknown_witness_did}#{TEST_UNKNOWN_WITNESS_KEY}",
        }

        version_id_doc = {"versionId": initial_log_entry.get("versionId")}
        proof = proof_options.copy()
        proof["proofValue"] = multibase.encode(
            unknown_key.sign_message(transform(version_id_doc, proof_options)), "base58btc"
        )

        witness_signature = version_id_doc | {"proof": [proof]}

        # Submit DID creation with unknown witness
        response = witness_policy_client.post(
            f"/{namespace}/{identifier}",
            json={
                "logEntry": initial_log_entry,
                "witnessSignature": witness_signature,
            },
        )

        # Should fail because witness is not in the known registry
        assert response.status_code in [400, 403]
        assert "Unknown witness" in response.json().get("detail", "")

    def test_create_did_without_witness_signature_fails(self, witness_policy_client: TestClient):
        """Test that DID creation fails without witness signature when required."""
        namespace, identifier = create_test_namespace_and_identifier("no_witness")

        # Get DID template
        response = witness_policy_client.get(f"?namespace={namespace}&identifier={identifier}")
        assert response.status_code == 200

        document = response.json().get("state")
        parameters = response.json().get("parameters")

        parameters["updateKeys"] = [TEST_UPDATE_KEY]
        # Note: Not adding witness configuration

        # Create initial state
        initial_state = DocumentState.initial(
            timestamp=TEST_VERSION_TIME,
            params=parameters,
            document=document,
        )
        initial_log_entry = sign(initial_state.history_line())

        # Submit WITHOUT witness signature (should fail)
        response = witness_policy_client.post(
            f"/{namespace}/{identifier}",
            json={
                "logEntry": initial_log_entry,
                # No witnessSignature field
            },
        )

        # Should fail when witness is required
        assert response.status_code in [400, 422]

    def test_update_did_with_witness_signature(self, witness_policy_client: TestClient):
        """Test that DID updates work with valid witness signature."""
        namespace, identifier = create_test_namespace_and_identifier("witness_update")

        # First create a DID
        response = witness_policy_client.get(f"?namespace={namespace}&identifier={identifier}")
        assert response.status_code == 200

        document = response.json().get("state")
        parameters = response.json().get("parameters")

        parameters["updateKeys"] = [TEST_UPDATE_KEY]
        parameters["witness"] = {
            "threshold": 1,
            "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
        }

        initial_state = DocumentState.initial(
            timestamp=TEST_VERSION_TIME,
            params=parameters,
            document=document,
        )
        initial_log_entry = sign(initial_state.history_line())

        witness = WitnessAgent()
        witness_signature = witness.create_log_entry_proof(initial_log_entry)

        # Create DID
        response = witness_policy_client.post(
            f"/{namespace}/{identifier}",
            json={
                "logEntry": initial_log_entry,
                "witnessSignature": witness_signature,
            },
        )
        assert response.status_code == 201

        # Now update the DID
        updated_doc = initial_state.document.copy()
        updated_doc["@context"].append("https://www.w3.org/ns/cid/v1")

        next_state = initial_state.create_next(
            timestamp=TEST_UPDATE_TIME,
            document=updated_doc,
            params_update=None,
        )

        next_log_entry = sign(next_state.history_line())
        next_witness_sig = witness.create_log_entry_proof(next_log_entry)

        # Submit update with witness signature
        response = witness_policy_client.post(
            f"/{namespace}/{identifier}",
            json={
                "logEntry": next_log_entry,
                "witnessSignature": next_witness_sig,
            },
        )

        assert response.status_code == 200
