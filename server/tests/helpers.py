"""
Test helper functions for DID WebVH server tests.

This module provides reusable functions to reduce code duplication
across test files.
"""

import time
from typing import Dict, Any, Tuple, Optional
from fastapi.testclient import TestClient
from did_webvh.core.state import DocumentState
from tests.mock_agents import ControllerAgent, WitnessAgent
from tests.signer import sign
from tests.fixtures import TEST_UPDATE_KEY, TEST_WITNESS_KEY


def create_unique_did(
    test_client: TestClient, namespace: str, identifier: str
) -> Tuple[str, DocumentState]:
    """
    Create a unique DID and return the DID ID and document state.

    Args:
        test_client: FastAPI test client
        namespace: DID namespace
        identifier: DID identifier

    Returns:
        Tuple of (did_id, document_state)
    """
    # Get DID template
    response = test_client.get(f"?namespace={namespace}&identifier={identifier}")
    assert response.status_code == 200

    document = response.json().get("state")
    parameters = response.json().get("parameters")

    parameters["updateKeys"] = [TEST_UPDATE_KEY]
    parameters["witness"] = {
        "threshold": 1,
        "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}],
    }

    # Create initial state and log entry
    initial_state = DocumentState.initial(
        timestamp="2024-01-01T00:00:00Z",
        params=parameters,
        document=document,
    )
    initial_log_entry = sign(initial_state.history_line())
    witness = WitnessAgent()
    witness_signature = witness.create_log_entry_proof(initial_log_entry)

    # Create DID
    response = test_client.post(
        f"/{namespace}/{identifier}",
        json={
            "logEntry": initial_log_entry,
            "witnessSignature": witness_signature,
        },
    )
    assert response.status_code == 201

    # Get DID log and extract document state
    response = test_client.get(f"/{namespace}/{identifier}/did.jsonl")
    log_entries_text = response.text.split("\n")[:-1]
    doc_state = None

    for log_entry in log_entries_text:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)

    return doc_state.document.get("id"), doc_state


def setup_controller_with_verification_method(
    test_client: TestClient, namespace: str, identifier: str, doc_state: DocumentState
) -> Tuple[ControllerAgent, str]:
    """
    Set up a controller agent and add its verification method to the DID document.

    Args:
        test_client: FastAPI test client
        namespace: DID namespace
        identifier: DID identifier
        doc_state: Current document state

    Returns:
        Tuple of (controller_agent, verification_method_id)
    """
    # Create controller
    controller = ControllerAgent()
    current_did_id = doc_state.document.get("id")
    controller.issuer_id = current_did_id
    controller.signing_key_id = f"{current_did_id}#{controller.signing_multikey}"

    # Create verification method
    verification_method = {
        "id": controller.signing_key_id,
        "type": "Multikey",
        "controller": current_did_id,
        "publicKeyMultibase": controller.signing_multikey,
    }

    # Update DID document with verification method
    updated_document = doc_state.document.copy()
    updated_document["assertionMethod"] = [verification_method["id"]]
    updated_document["verificationMethod"] = [verification_method]

    # Create new state and sign
    new_state = doc_state.create_next(
        timestamp="2024-01-01T00:00:00Z",
        document=updated_document,
        params_update=None,
    )

    next_log_entry = sign(new_state.history_line())
    witness = WitnessAgent()
    witness_signature = witness.create_log_entry_proof(next_log_entry)

    # Submit update
    response = test_client.post(
        f"/{namespace}/{identifier}",
        json={
            "logEntry": next_log_entry,
            "witnessSignature": witness_signature,
        },
    )
    assert response.status_code == 200

    return controller, verification_method["id"]


def create_test_resource(
    controller: ControllerAgent,
    resource_name: str = "testResource",
    resource_data: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], str]:
    """
    Create a test resource using the controller.

    Args:
        controller: Controller agent for signing
        resource_name: Name of the resource
        resource_data: Optional resource data (defaults to {"name": "Test"})

    Returns:
        Tuple of (attested_resource, resource_id)
    """
    if resource_data is None:
        resource_data = {"name": "Test"}

    return controller.attest_resource(resource_data, resource_name)


def get_current_doc_state(
    test_client: TestClient, namespace: str, identifier: str
) -> DocumentState:
    """
    Get the current document state for a DID.

    Args:
        test_client: FastAPI test client
        namespace: DID namespace
        identifier: DID identifier

    Returns:
        Current document state
    """
    response = test_client.get(f"/{namespace}/{identifier}/did.jsonl")
    log_entries_text = response.text.split("\n")[:-1]
    doc_state = None

    for log_entry in log_entries_text:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)

    return doc_state


def create_unique_identifier(base: str, suffix: str = "") -> str:
    """
    Create a unique identifier for testing.

    Args:
        base: Base identifier
        suffix: Optional suffix

    Returns:
        Unique identifier
    """
    timestamp = str(int(time.time() * 1000))[-6:]  # Last 6 digits of timestamp
    return f"{base}-{timestamp}{suffix}"


def assert_error_response(response, expected_status: int, expected_detail: Optional[str] = None):
    """
    Assert that a response is an error response with expected status and detail.

    Args:
        response: Response object
        expected_status: Expected HTTP status code
        expected_detail: Optional expected error detail message
    """
    assert response.status_code == expected_status
    if expected_detail:
        response_data = response.json()
        # Check both "detail" and "Reason" fields for error messages
        detail_text = response_data.get("detail", "") + response_data.get("Reason", "")
        assert expected_detail in detail_text


def create_test_namespace_and_identifier(test_name: str) -> Tuple[str, str]:
    """
    Create unique namespace and identifier for a test.

    Args:
        test_name: Name of the test

    Returns:
        Tuple of (namespace, identifier)
    """
    namespace = f"test-{test_name.lower().replace('_', '-')}"
    identifier = create_unique_identifier(f"{test_name.lower()}")
    return namespace, identifier
