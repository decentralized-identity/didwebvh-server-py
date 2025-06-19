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
    TEST_DOMAIN,
    TEST_DID,
    TEST_DID_DOCUMENT,
    TEST_LOG_ENTRY,
    TEST_PLACEHOLDER_ID,
    TEST_PROOF_OPTIONS,
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
didwebvh = DidWebVH()

witness = WitnessAgent()
controller = ControllerAgent()


@pytest.mark.asyncio
async def test_request_did():
    response = await request_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_request = json.loads(response.body.decode())
    assert did_request.get('state').get('id') == TEST_PLACEHOLDER_ID



@pytest.mark.asyncio
async def test_create_did():
    response = await request_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_request = json.loads(response.body.decode())
    
    parameters = did_request.get('parameters')
    parameters['updateKeys'] = [TEST_UPDATE_KEY]
    # parameters['nextKeyHashes'] = [TEST_NEXT_KEY_HASH]
    
    initial_state = DocumentState.initial(
        params=parameters,
        document=did_request.get('state'),
    )
    
    initial_log_entry = sign(initial_state.history_line())
    print(json.dumps(initial_log_entry, indent=2))
    # print(initial_state)
    initial_state = DocumentState.initial(
        params={"method": "did:webvh:1.0", "updateKeys": [TEST_UPDATE_KEY]},
        document={
            '@context': ['https://www.w3.org/ns/did/v1'],
            'id': TEST_PLACEHOLDER_ID
        },
    )
    
    initial_log_entry = sign(initial_state.history_line())
    # print(json.dumps(initial_log_entry, indent=2))
    response = await new_log_entry(
        TEST_DID_NAMESPACE, 
        TEST_DID_IDENTIFIER, 
        NewLogEntry.model_validate({
            "logEntry": initial_log_entry,
            # 'witnessSignature': None
        })
    )
    
    log_entry = json.loads(response.body.decode())
    assert LogEntry.model_validate(log_entry)


@pytest.mark.asyncio
async def test_resolve_did():
    response = await read_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_doc = json.loads(response.body.decode())
    assert did_doc.get('alsoKnownAs')


@pytest.mark.asyncio
async def test_resolve_initial_did_log():
    response = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    log_entries = response.body.decode().split('\n')[:-1]
    assert len(log_entries) == 1
    doc_state = None
    for log_entry in log_entries:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)
    assert doc_state


@pytest.mark.asyncio
async def test_update_did():
    response = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    log_entries = response.body.decode().split('\n')[:-1]
    doc_state = None
    for log_entry in log_entries:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)
        
    new_state = doc_state.create_next(
        document=None,
        params_update=None
    )
    log_entry = sign(new_state.history_line())
    log_request = NewLogEntry.model_validate({"logEntry": log_entry})
    response = await new_log_entry(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, log_request)
    log_entry = response.body.decode()
    LogEntry.model_validate(json.loads(log_entry))


@pytest.mark.asyncio
async def test_resolve_updated_did_log():
    response = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    log_entries = response.body.decode().split('\n')[:-1]
    assert len(log_entries) == 2
    doc_state = None
    for log_entry in log_entries:
        doc_state = DocumentState.load_history_json(log_entry, doc_state)
    assert doc_state
