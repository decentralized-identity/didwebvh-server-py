import asyncio

import pytest

from fastapi.testclient import TestClient

from app import app
from app.models.did_log import LogEntry
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from tests.fixtures import (
    TEST_DID_IDENTIFIER,
    TEST_DID_NAMESPACE,
    TEST_VERSION_TIME,
    TEST_UPDATE_TIME,
    TEST_POLICY,
    TEST_PLACEHOLDER_ID,
    TEST_WITNESS_KEY,
    TEST_WITNESS_REGISTRY,
    TEST_VERIFICATION_METHOD,
    TEST_UPDATE_KEY,
)
from tests.mock_agents import WitnessAgent, ControllerAgent
from tests.signer import sign
from did_webvh.core.state import DocumentState

askar = AskarStorage()
asyncio.run(askar.provision(recreate=True))
asyncio.run(askar.store("registry", "knownWitnesses", {"registry": TEST_WITNESS_REGISTRY}))
asyncio.run(askar.store("policy", "active", TEST_POLICY))

verifier = AskarVerifier()
webvh = DidWebVH()

witness = WitnessAgent()
controller = ControllerAgent()


@pytest.mark.asyncio
async def test_request_did():
    with TestClient(app) as test_client:
        response = test_client.get(
            f"?namespace={TEST_DID_NAMESPACE}&identifier={TEST_DID_IDENTIFIER}"
        )
    assert response.status_code == 200
    assert response.json().get("state").get("id") == TEST_PLACEHOLDER_ID


@pytest.mark.asyncio
async def test_create_did():
    with TestClient(app) as test_client:
        response = test_client.get(
            f"?namespace={TEST_DID_NAMESPACE}&identifier={TEST_DID_IDENTIFIER}"
        )

    document = response.json().get("state")
    parameters = response.json().get("parameters")
    parameters["updateKeys"] = [TEST_UPDATE_KEY]
    parameters["witness"] = {"threshold": 1, "witnesses": [{"id": f"did:key:{TEST_WITNESS_KEY}"}]}

    initial_state = DocumentState.initial(
        timestamp=TEST_VERSION_TIME,
        params=parameters,
        document=document,
    )
    initial_log_entry = sign(initial_state.history_line())

    witness_signature = witness.create_log_entry_proof(initial_log_entry)

    with TestClient(app) as test_client:
        response = test_client.post(
            f"/{TEST_DID_NAMESPACE}/{TEST_DID_IDENTIFIER}",
            json={"logEntry": initial_log_entry, "witnessSignature": witness_signature},
        )
    assert response.status_code == 201
    assert LogEntry.model_validate(response.json())


@pytest.mark.asyncio
async def test_resolve_did():
    with TestClient(app) as test_client:
        response = test_client.get(f"/{TEST_DID_NAMESPACE}/{TEST_DID_IDENTIFIER}/did.json")
    did_doc = response.json()
    assert did_doc.get("alsoKnownAs")


@pytest.mark.asyncio
async def test_resolve_initial_did_log():
    with TestClient(app) as test_client:
        response = test_client.get(f"/{TEST_DID_NAMESPACE}/{TEST_DID_IDENTIFIER}/did.jsonl")
    log_entries = response.text.split("\n")[:-1]
    assert len(log_entries) == 1
    doc_state = None
    for log_entry in log_entries:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)
    assert doc_state


@pytest.mark.asyncio
async def test_update_did():
    with TestClient(app) as test_client:
        response = test_client.get(f"/{TEST_DID_NAMESPACE}/{TEST_DID_IDENTIFIER}/did.jsonl")
    log_entries = response.text.split("\n")[:-1]
    doc_state = None

    for log_entry in log_entries:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)

    document = doc_state.document.copy()
    document["@context"].append("https://www.w3.org/ns/cid/v1")
    document["assertionMethod"] = [TEST_VERIFICATION_METHOD.get("id")]
    document["verificationMethod"] = [TEST_VERIFICATION_METHOD]
    new_state = doc_state.create_next(
        timestamp=TEST_UPDATE_TIME, document=document, params_update=None
    )

    next_log_entry = sign(new_state.history_line())

    witness_signature = witness.create_log_entry_proof(next_log_entry)

    with TestClient(app) as test_client:
        response = test_client.post(
            f"/{TEST_DID_NAMESPACE}/{TEST_DID_IDENTIFIER}",
            json={
                "logEntry": next_log_entry,
                "witnessSignature": witness_signature,
            },
        )
    LogEntry.model_validate(response.json())


@pytest.mark.asyncio
async def test_resolve_updated_did_log():
    with TestClient(app) as test_client:
        response = test_client.get(f"/{TEST_DID_NAMESPACE}/{TEST_DID_IDENTIFIER}/did.jsonl")
    log_entries = response.text.split("\n")[:-1]
    assert len(log_entries) == 2
    doc_state = None
    for log_entry in log_entries:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)
    assert doc_state
