import asyncio
import json
from datetime import datetime, timezone

import pytest

from app.models.did_log import LogEntry
from app.models.web_schemas import NewLogEntry
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from app.routers.identifiers import new_log_entry, read_did, read_did_log, request_did
from tests.fixtures import (
    TEST_DID_IDENTIFIER,
    TEST_DID_NAMESPACE,
    TEST_VERSION_TIME,
    TEST_UPDATE_TIME,
    TEST_DOMAIN,
    TEST_DID,
    TEST_DID_DOCUMENT,
    TEST_LOG_ENTRY,
    TEST_POLICY,
    TEST_PLACEHOLDER_ID,
    TEST_PROOF_OPTIONS,
    TEST_WITNESS_REGISTRY,
    TEST_VERIFICATION_METHOD,
    TEST_NEXT_KEY_HASH,
    TEST_UPDATE_KEY,
)
from tests.mock_agents import WitnessAgent, ControllerAgent
import json
import asyncio
from tests.signer import sign, verify
from did_webvh.core.state import DocumentState

askar = AskarStorage()
asyncio.run(askar.provision(recreate=True))

verifier = AskarVerifier()
webvh = DidWebVH()

witness = WitnessAgent()
controller = ControllerAgent()


@pytest.mark.asyncio
async def test_request_did():
    response = await request_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_request = json.loads(response.body.decode())
    assert did_request.get("state").get("id") == TEST_PLACEHOLDER_ID


@pytest.mark.asyncio
async def test_create_did():
    await askar.update("registry", "knownWitnesses", {"registry": TEST_WITNESS_REGISTRY})
    await askar.update("policy", "active", TEST_POLICY)

    response = await request_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_request = json.loads(response.body.decode())

    parameters = did_request.get("parameters")
    parameters["updateKeys"] = [TEST_UPDATE_KEY]

    if parameters.get("nextKeyHashes") == []:
        parameters["nextKeyHashes"] = [TEST_NEXT_KEY_HASH]

    if parameters.get("witness"):
        pass

    initial_state = DocumentState.initial(
        timestamp=TEST_VERSION_TIME,
        params=parameters,
        document=did_request.get("state"),
    )
    initial_log_entry = sign(initial_state.history_line())

    witness_signature = witness.create_log_entry_proof(initial_log_entry)

    response = await new_log_entry(
        TEST_DID_NAMESPACE,
        TEST_DID_IDENTIFIER,
        NewLogEntry.model_validate(
            {"logEntry": initial_log_entry, "witnessSignature": witness_signature}
        ),
    )

    assert LogEntry.model_validate(json.loads(response.body.decode()))


@pytest.mark.asyncio
async def test_resolve_did():
    response = await read_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_doc = json.loads(response.body.decode())
    assert did_doc.get("alsoKnownAs")


@pytest.mark.asyncio
async def test_resolve_initial_did_log():
    response = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    log_entries = response.body.decode().split("\n")[:-1]
    assert len(log_entries) == 1
    doc_state = None
    for log_entry in log_entries:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)
    assert doc_state


@pytest.mark.asyncio
async def test_update_did():
    response = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    log_entries = response.body.decode().split("\n")[:-1]
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

    log_request = NewLogEntry.model_validate(
        {
            "logEntry": next_log_entry,
            "witnessSignature": witness_signature,
        }
    )
    response = await new_log_entry(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, log_request)
    LogEntry.model_validate(json.loads(response.body.decode()))


@pytest.mark.asyncio
async def test_resolve_updated_did_log():
    response = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    log_entries = response.body.decode().split("\n")[:-1]
    assert len(log_entries) == 2
    doc_state = None
    for log_entry in log_entries:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)
    assert doc_state
