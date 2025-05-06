import asyncio
import json
from datetime import datetime, timezone

import pytest

from app.models.did_log import LogEntry
from app.models.web_schemas import NewLogEntry
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from app.routers.identifiers import new_webvh_log_entry, read_did, read_did_log, request_did
from tests.fixtures import (
    TEST_DID_IDENTIFIER,
    TEST_DID_NAMESPACE,
    TEST_DOMAIN,
    TEST_DID,
    TEST_DID_DOCUMENT,
    TEST_PROOF_OPTIONS,
    TEST_REGISTRATION_KEY,
)
from tests.mock_agents import WitnessAgent, ControllerAgent
import json
import asyncio
from tests.signer import sign, verify
from did_webvh.core.state import DocumentState

askar = AskarStorage()
asyncio.run(askar.provision(recreate=True))

verifier = AskarVerifier()
didwebvh = DidWebVH()

witness = WitnessAgent()
controller = ControllerAgent()


@pytest.mark.asyncio
async def test_request_did():
    did_request = await request_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_request = json.loads(did_request.body.decode())
    assert did_request.get("didDocument").get("id") == TEST_DID
    assert did_request.get("proofOptions").get("type") == TEST_PROOF_OPTIONS["type"]
    assert did_request.get("proofOptions").get("cryptosuite") == TEST_PROOF_OPTIONS["cryptosuite"]
    assert did_request.get("proofOptions").get("proofPurpose") == TEST_PROOF_OPTIONS["proofPurpose"]
    assert did_request.get("proofOptions").get("domain") == TEST_DOMAIN
    assert did_request.get("proofOptions").get("challenge")
    assert datetime.fromisoformat(did_request.get("proofOptions").get("expires")) > datetime.now(
        timezone.utc
    )


@pytest.mark.asyncio
async def test_register_did():
    did_request = await request_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_request = json.loads(did_request.body.decode())
    await askar.store("didDocument", TEST_DID, TEST_DID_DOCUMENT)
    await askar.store("registrationKey", TEST_DID, TEST_REGISTRATION_KEY)


@pytest.mark.asyncio
async def test_resolve_did():
    did_doc = await read_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_doc = json.loads(did_doc.body.decode())
    assert did_doc == TEST_DID_DOCUMENT
    assert did_doc.get("id") == TEST_DID


@pytest.mark.asyncio
async def test_register_log_entry():
    did_document = await askar.fetch("didDocument", TEST_DID)
    initial_state = DocumentState.initial(
        params={"method": "did:webvh:0.5", "updateKeys": [TEST_REGISTRATION_KEY]},
        document=json.loads(json.dumps(did_document).replace("did:web:", r"did:webvh:{SCID}:")),
    )
    log_entry = sign(initial_state.history_line())
    log_request = NewLogEntry.model_validate({"logEntry": log_entry})
    response = await new_webvh_log_entry(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, log_request)
    log_entry = response.body.decode()
    LogEntry.model_validate(json.loads(log_entry))


@pytest.mark.asyncio
async def test_resolve_did_log():
    did_logs = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_logs = json.loads(did_logs.body.decode())


@pytest.mark.asyncio
async def test_update_log_entry():
    client_id = f"{TEST_DID_NAMESPACE}:{TEST_DID_IDENTIFIER}"
    log_entries = await askar.fetch("logEntries", client_id)
    log_state = didwebvh.get_document_state(log_entries)
    next_entry = log_state.create_next()
    log_entry = sign(next_entry.history_line())
    log_request = NewLogEntry.model_validate({"logEntry": log_entry})
    response = await new_webvh_log_entry(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, log_request)
    log_entry = response.body.decode()
    LogEntry.model_validate(json.loads(log_entry))
