from app.routers.identifiers import request_did
from app.routers.resolvers import get_did_document
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from datetime import datetime, timezone
from tests.fixtures import (
    TEST_DOMAIN,
    TEST_DID_NAMESPACE,
    TEST_DID_IDENTIFIER,
    TEST_DID,
    TEST_DID_DOCUMENT,
    TEST_DID_DOCUMENT_SIGNED,
    TEST_AUTHORISED_KEY,
    TEST_PROOF_OPTIONS
)
import asyncio
import json
import uuid

def test_storage():
    askar = AskarStorage()
    asyncio.run(askar.provision(recreate=True))
    
    category = 'test'
    key = '01'
    data = {'value': None}
    value_1 = 'value_1'
    value_2 = 'value_2'
    
    data['value'] = value_1
    asyncio.run(askar.store(category, key, data))
    fetched_data = asyncio.run(askar.fetch(category, key))
    assert fetched_data['value'] == value_1
    
    data['value'] = value_2
    asyncio.run(askar.update(category, key, data))
    fetched_data = asyncio.run(askar.fetch(category, key))
    assert fetched_data['value'] == value_2

def test_request_did():
    did_request = asyncio.run(request_did(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER))
    did_request = json.loads(did_request.body.decode())
    assert did_request.get('didDocument').get('id') == TEST_DID
    assert did_request.get('proofOptions').get("type") == TEST_PROOF_OPTIONS['type']
    assert did_request.get('proofOptions').get("cryptosuite") == TEST_PROOF_OPTIONS['cryptosuite']
    assert did_request.get('proofOptions').get("proofPurpose") == TEST_PROOF_OPTIONS['proofPurpose']
    assert did_request.get('proofOptions').get("domain") == TEST_DOMAIN
    assert did_request.get('proofOptions').get("challenge")
    assert datetime.fromisoformat(
        did_request.get('proofOptions').get("expires")
        ) > datetime.now(timezone.utc)

def test_register_did():
    askar = AskarStorage()
    asyncio.run(askar.store("didDocument", TEST_DID, TEST_DID_DOCUMENT))
    asyncio.run(askar.store("authorizedKey", TEST_DID, TEST_AUTHORISED_KEY))

def test_resolve_did():
    did_doc = asyncio.run(get_did_document(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER))
    did_doc = json.loads(did_doc.body.decode())
    assert did_doc == TEST_DID_DOCUMENT
    assert did_doc.get('id') == TEST_DID

def test_create_log_entry():
    initial_log_entry = DidWebVH().create(TEST_DID_DOCUMENT, TEST_AUTHORISED_KEY)
    assert initial_log_entry.get('versionId')
    assert initial_log_entry.get('versionTime')
    assert initial_log_entry.get('parameters')
    assert initial_log_entry.get('state')
    
def test_verify_di_proof():
    document = TEST_DID_DOCUMENT_SIGNED
    proof = document.pop('proof')
    verifier = AskarVerifier()
    assert verifier.verify_proof(document, proof)
