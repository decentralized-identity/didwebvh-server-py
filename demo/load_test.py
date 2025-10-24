"""Load test script for DID WebVH Server.

This script creates multiple DIDs with log entries and WHOIS files to test server performance.

NOTE: This script must be run from the server directory to access dependencies:
    cd server
    uv run python ../demo/load_test.py [options]

Usage:
    uv run python ../demo/load_test.py --count 10 --server http://localhost:8000
    uv run python ../demo/load_test.py -c 50 -s http://localhost:8000 --namespace loadtest
    
Environment Variables:
    WEBVH_SERVER_URL - Default server URL (default: http://localhost:8000)
    WEBVH_NAMESPACE  - Default namespace (default: loadtest)
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests
import httpx
from aries_askar import Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from loguru import logger
from multiformats import multibase, multihash
import canonicaljson
import jcs
from hashlib import sha256

# Default configuration
DEFAULT_SERVER_URL = os.getenv("WEBVH_SERVER_URL", "http://localhost:8000")
DEFAULT_NAMESPACE = os.getenv("WEBVH_NAMESPACE", "loadtest")

# Configure logger
logger.remove()
logger.add(sys.stderr, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>")


class DidWebVHClient:
    """Client for interacting with DID WebVH Server."""

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")
        self.session = requests.Session()
        self.api_key = os.getenv("API_KEY", "webvh")

    def register_witness(self, witness_key: Key, label: str = "Load Test Witness") -> Dict:
        """Register a witness in the known witness registry."""
        witness_multikey = self.key_to_multikey(witness_key)
        
        response = self.session.post(
            f"{self.server_url}/admin/policy/known-witnesses",
            headers={"X-API-Key": self.api_key},
            json={
                "multikey": witness_multikey,
                "label": label,
            },
        )
        
        # Ignore 409 (already exists) - that's fine
        if response.status_code == 409:
            logger.info(f"Witness already registered: {witness_multikey[:20]}...")
            return {"status": "already_exists"}
        
        if response.status_code != 200:
            logger.warning(f"Failed to register witness: {response.status_code} - {response.text}")
            return {"status": "failed", "error": response.text}
        
        logger.success(f"✓ Registered witness: {witness_multikey[:20]}...")
        return response.json()

    def key_to_multikey(self, key: Key) -> str:
        """Convert Askar key to multikey format."""
        return multibase.encode(
            bytes.fromhex(f"ed01{key.get_public_bytes().hex()}"),
            "base58btc",
        )

    def sign_document(self, document: Dict, key: Key, verification_method: str, proof_purpose: str = "assertionMethod") -> Dict:
        """Sign a document with Data Integrity proof."""
        document = document.copy()
        document.pop("proof", None)
        
        proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": proof_purpose,
            "verificationMethod": verification_method,
        }
        
        hash_data = (
            sha256(canonicaljson.encode_canonical_json(proof_options)).digest()
            + sha256(canonicaljson.encode_canonical_json(document)).digest()
        )
        
        proof = proof_options.copy()
        proof["proofValue"] = multibase.encode(key.sign_message(hash_data), "base58btc")
        
        document["proof"] = [proof]
        return document

    def request_did(self, namespace: str, identifier: str) -> Dict:
        """Request DID creation template from server."""
        response = self.session.get(f"{self.server_url}/?namespace={namespace}&identifier={identifier}")
        response.raise_for_status()
        return response.json()

    def create_did(self, namespace: str, identifier: str, update_key: Key, witness_key: Key) -> Dict:
        """Create a new DID on the server."""
        # Get DID template
        template = self.request_did(namespace, identifier)
        
        document = template.get("state")
        parameters = template.get("parameters")
        
        # Configure parameters
        update_multikey = self.key_to_multikey(update_key)
        witness_multikey = self.key_to_multikey(witness_key)
        
        parameters["updateKeys"] = [update_multikey]
        parameters["witness"] = {
            "threshold": 1,
            "witnesses": [{"id": f"did:key:{witness_multikey}"}],
        }
        parameters["watchers"] = ["https://did.observer"]
        
        # Create initial state
        from did_webvh.core.state import DocumentState
        
        initial_state = DocumentState.initial(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            params=parameters,
            document=document,
        )
        
        # Sign log entry
        initial_log = initial_state.history_line()
        verification_method = f"did:key:{update_multikey}#{update_multikey}"
        initial_log_entry = self.sign_document(initial_log, update_key, verification_method)
        
        # Create witness signature
        witness_proof_doc = {"versionId": initial_log_entry.get("versionId")}
        witness_vm = f"did:key:{witness_multikey}#{witness_multikey}"
        witness_signature = self.sign_document(witness_proof_doc, witness_key, witness_vm)
        
        # Submit to server
        response = self.session.post(
            f"{self.server_url}/{namespace}/{identifier}",
            json={
                "logEntry": initial_log_entry,
                "witnessSignature": witness_signature,
            },
        )
        
        # Show error detail if request fails
        if response.status_code != 201:
            try:
                error_detail = response.json()
                logger.error(f"DID creation failed: {response.status_code} - {error_detail}")
            except:
                logger.error(f"DID creation failed: {response.status_code} - {response.text}")
        
        response.raise_for_status()
        return response.json()

    def get_did_log(self, namespace: str, identifier: str) -> List[Dict]:
        """Get DID log entries."""
        response = self.session.get(f"{self.server_url}/{namespace}/{identifier}/did.jsonl")
        response.raise_for_status()
        
        log_entries = []
        for line in response.text.strip().split("\n"):
            if line:
                log_entries.append(json.loads(line))
        return log_entries

    def update_did(
        self,
        namespace: str,
        identifier: str,
        update_key: Key,
        witness_key: Key,
        update_document: Optional[Dict] = None,
    ) -> Dict:
        """Update an existing DID."""
        from did_webvh.core.state import DocumentState
        
        # Get current log
        log_entries = self.get_did_log(namespace, identifier)
        
        # Reconstruct document state
        doc_state = None
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_json(json.dumps(log_entry), doc_state)
        
        # Create updated document
        if update_document is None:
            update_document = doc_state.document.copy()
            # Add a context to show this is an update
            if "https://www.w3.org/ns/cid/v1" not in update_document.get("@context", []):
                update_document["@context"].append("https://www.w3.org/ns/cid/v1")
        
        # Create next state
        new_state = doc_state.create_next(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            document=update_document,
            params_update=None,
        )
        
        # Sign log entry
        next_log = new_state.history_line()
        update_multikey = self.key_to_multikey(update_key)
        verification_method = f"did:key:{update_multikey}#{update_multikey}"
        next_log_entry = self.sign_document(next_log, update_key, verification_method)
        
        # Create witness signature
        witness_multikey = self.key_to_multikey(witness_key)
        witness_proof_doc = {"versionId": next_log_entry.get("versionId")}
        witness_vm = f"did:key:{witness_multikey}#{witness_multikey}"
        witness_signature = self.sign_document(witness_proof_doc, witness_key, witness_vm)
        
        # Submit to server
        response = self.session.post(
            f"{self.server_url}/{namespace}/{identifier}",
            json={
                "logEntry": next_log_entry,
                "witnessSignature": witness_signature,
            },
        )
        response.raise_for_status()
        return response.json()

    def add_verification_method_to_did(
        self,
        namespace: str,
        identifier: str,
        update_key: Key,
        witness_key: Key,
        signing_key: Key,
    ) -> Dict:
        """Add a verification method to a DID for signing WHOIS."""
        from did_webvh.core.state import DocumentState
        
        log_entries = self.get_did_log(namespace, identifier)
        
        doc_state = None
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_json(json.dumps(log_entry), doc_state)
        
        # Get DID ID
        did_id = doc_state.document.get("id")
        signing_multikey = self.key_to_multikey(signing_key)
        
        # Add verification method
        updated_document = doc_state.document.copy()
        verification_method = {
            "id": f"{did_id}#{signing_multikey}",
            "type": "Multikey",
            "controller": did_id,
            "publicKeyMultibase": signing_multikey,
        }
        
        updated_document["verificationMethod"] = updated_document.get("verificationMethod", []) + [
            verification_method
        ]
        updated_document["assertionMethod"] = updated_document.get("assertionMethod", []) + [
            verification_method["id"]
        ]
        updated_document["authentication"] = updated_document.get("authentication", []) + [
            verification_method["id"]
        ]
        
        return self.update_did(namespace, identifier, update_key, witness_key, updated_document)

    def upload_whois(
        self,
        namespace: str,
        identifier: str,
        signing_key: Key,
        issuer_did: str,
    ) -> Dict:
        """Upload WHOIS verifiable presentation."""
        # Get DID ID from the log (did:webvh version, not did:web)
        log_entries = self.get_did_log(namespace, identifier)
        from did_webvh.core.state import DocumentState
        
        doc_state = None
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_json(json.dumps(log_entry), doc_state)
        
        did_id = doc_state.document.get("id")  # This is the did:webvh version
        
        signing_multikey = self.key_to_multikey(signing_key)
        verification_method_id = f"{did_id}#{signing_multikey}"
        
        # Create verifiable credential
        credential = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2",
            ],
            "type": ["VerifiableCredential", "OrganizationCredential"],
            "issuer": {"id": issuer_did, "name": "Load Test Issuer"},
            "validFrom": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "credentialSubject": {
                "id": did_id,
                "name": f"Organization {identifier}",
                "email": f"contact-{identifier}@example.com",
                "website": f"https://{identifier}.example.com",
                "description": "Created by load test script",
            },
        }
        
        # Sign credential (in real scenario, this would be signed by issuer)
        credential = self.sign_document(credential, signing_key, verification_method_id, proof_purpose="assertionMethod")
        
        # Create verifiable presentation
        presentation = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": did_id,
            "verifiableCredential": [credential],
        }
        
        # Sign presentation with authentication purpose (required for WHOIS)
        presentation = self.sign_document(presentation, signing_key, verification_method_id, proof_purpose="authentication")
        
        # Upload to server
        response = self.session.post(
            f"{self.server_url}/{namespace}/{identifier}/whois",
            json={"verifiablePresentation": presentation},
        )
        
        # Show error detail if request fails
        if response.status_code != 200:
            try:
                error_detail = response.json()
                logger.error(f"WHOIS upload failed: {response.status_code} - {error_detail}")
            except:
                logger.error(f"WHOIS upload failed: {response.status_code} - {response.text}")
        
        response.raise_for_status()
        return response.json()

    def upload_resource(
        self,
        namespace: str,
        identifier: str,
        signing_key: Key,
        resource_content: Dict,
        resource_type: str = "genericResource",
    ) -> Dict:
        """Upload an attested resource."""
        # Get DID ID from the log
        log_entries = self.get_did_log(namespace, identifier)
        from did_webvh.core.state import DocumentState
        
        doc_state = None
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_json(json.dumps(log_entry), doc_state)
        
        did_id = doc_state.document.get("id")
        signing_multikey = self.key_to_multikey(signing_key)
        verification_method_id = f"{did_id}#{signing_multikey}"
        
        # Calculate content digest using multihash (same as server validation)
        resource_id = multibase.encode(
            multihash.digest(jcs.canonicalize(resource_content), "sha2-256"),
            "base58btc"
        )
        
        # Create attested resource
        attested_resource = {
            "@context": [
                "https://identity.foundation/did-attested-resources/context/v0.1",
                "https://w3id.org/security/data-integrity/v2"
            ],
            "type": ["AttestedResource"],
            "id": f"{did_id}/resources/{resource_id}",
            "content": resource_content,
            "metadata": {
                "resourceId": resource_id,
                "resourceType": resource_type,
            }
        }
        
        # Sign the resource
        attested_resource = self.sign_document(attested_resource, signing_key, verification_method_id, proof_purpose="assertionMethod")
        
        # Upload to server
        response = self.session.post(
            f"{self.server_url}/{namespace}/{identifier}/resources",
            json={"attestedResource": attested_resource},
        )
        
        # Show error detail if request fails
        if response.status_code != 201:
            try:
                error_detail = response.json()
                logger.error(f"Resource upload failed: {response.status_code} - {error_detail}")
            except:
                logger.error(f"Resource upload failed: {response.status_code} - {response.text}")
        
        response.raise_for_status()
        return response.json()


class DidWebVHAsyncClient:
    """Async client for interacting with DID WebVH Server (for concurrent requests)."""

    def __init__(self, server_url: str, session: httpx.AsyncClient):
        self.server_url = server_url.rstrip("/")
        self.session = session
        self.api_key = os.getenv("API_KEY", "webvh")

    # Copy all the signing methods from sync client (they don't use HTTP)
    def key_to_multikey(self, key: Key) -> str:
        """Convert Askar key to multikey format."""
        return multibase.encode(
            bytes.fromhex(f"ed01{key.get_public_bytes().hex()}"),
            "base58btc",
        )

    def sign_document(self, document: Dict, key: Key, verification_method: str, proof_purpose: str = "assertionMethod") -> Dict:
        """Sign a document with Data Integrity proof."""
        document = document.copy()
        document.pop("proof", None)
        
        proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": proof_purpose,
            "verificationMethod": verification_method,
        }
        
        hash_data = (
            sha256(canonicaljson.encode_canonical_json(proof_options)).digest()
            + sha256(canonicaljson.encode_canonical_json(document)).digest()
        )
        
        proof = proof_options.copy()
        proof["proofValue"] = multibase.encode(key.sign_message(hash_data), "base58btc")
        
        document["proof"] = [proof]
        return document

    async def register_witness(self, witness_key: Key, label: str = "Load Test Witness") -> Dict:
        """Register a witness in the known witness registry."""
        witness_multikey = self.key_to_multikey(witness_key)
        
        response = await self.session.post(
            f"{self.server_url}/admin/policy/known-witnesses",
            headers={"X-API-Key": self.api_key},
            json={"multikey": witness_multikey, "label": label},
        )
        
        # Ignore 409 (already exists)
        if response.status_code == 409:
            return {"status": "already_exists"}
        
        if response.status_code != 200:
            logger.warning(f"Failed to register witness: {response.status_code}")
            return {"status": "failed", "error": response.text}
        
        return response.json()

    async def request_did(self, namespace: str, identifier: str) -> Dict:
        """Request DID creation template from server."""
        response = await self.session.get(f"{self.server_url}/?namespace={namespace}&identifier={identifier}")
        response.raise_for_status()
        return response.json()

    async def create_did(self, namespace: str, identifier: str, update_key: Key, witness_key: Key) -> Dict:
        """Create a new DID on the server."""
        template = await self.request_did(namespace, identifier)
        
        document = template.get("state")
        parameters = template.get("parameters")
        
        update_multikey = self.key_to_multikey(update_key)
        witness_multikey = self.key_to_multikey(witness_key)
        
        parameters["updateKeys"] = [update_multikey]
        parameters["witness"] = {
            "threshold": 1,
            "witnesses": [{"id": f"did:key:{witness_multikey}"}],
        }
        parameters["watchers"] = ["https://did.observer"]
        
        from did_webvh.core.state import DocumentState
        
        initial_state = DocumentState.initial(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            params=parameters,
            document=document,
        )
        
        initial_log = initial_state.history_line()
        verification_method = f"did:key:{update_multikey}#{update_multikey}"
        initial_log_entry = self.sign_document(initial_log, update_key, verification_method)
        
        witness_proof_doc = {"versionId": initial_log_entry.get("versionId")}
        witness_vm = f"did:key:{witness_multikey}#{witness_multikey}"
        witness_signature = self.sign_document(witness_proof_doc, witness_key, witness_vm)
        
        response = await self.session.post(
            f"{self.server_url}/{namespace}/{identifier}",
            json={"logEntry": initial_log_entry, "witnessSignature": witness_signature},
        )
        
        if response.status_code != 201:
            try:
                error_detail = response.json()
                logger.error(f"DID creation failed: {response.status_code} - {error_detail}")
            except:
                logger.error(f"DID creation failed: {response.status_code} - {response.text}")
        
        response.raise_for_status()
        return response.json()

    async def get_did_log(self, namespace: str, identifier: str) -> List[Dict]:
        """Get DID log entries."""
        response = await self.session.get(f"{self.server_url}/{namespace}/{identifier}/did.jsonl")
        response.raise_for_status()
        
        log_entries = []
        for line in response.text.strip().split("\n"):
            if line:
                log_entries.append(json.loads(line))
        return log_entries

    async def update_did(self, namespace: str, identifier: str, update_key: Key, witness_key: Key, updated_document: Optional[Dict] = None) -> Dict:
        """Update an existing DID."""
        log_entries = await self.get_did_log(namespace, identifier)
        
        from did_webvh.core.state import DocumentState
        
        doc_state = None
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_json(json.dumps(log_entry), doc_state)
        
        if updated_document is None:
            updated_document = doc_state.document.copy()
            updated_document["@context"].append("https://www.w3.org/ns/cid/v1")
        
        new_state = doc_state.create_next(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            document=updated_document,
            params_update=None,
        )
        
        update_multikey = self.key_to_multikey(update_key)
        witness_multikey = self.key_to_multikey(witness_key)
        
        next_log = new_state.history_line()
        verification_method = f"did:key:{update_multikey}#{update_multikey}"
        next_log_entry = self.sign_document(next_log, update_key, verification_method)
        
        witness_proof_doc = {"versionId": next_log_entry.get("versionId")}
        witness_vm = f"did:key:{witness_multikey}#{witness_multikey}"
        witness_signature = self.sign_document(witness_proof_doc, witness_key, witness_vm)
        
        response = await self.session.post(
            f"{self.server_url}/{namespace}/{identifier}",
            json={"logEntry": next_log_entry, "witnessSignature": witness_signature},
        )
        response.raise_for_status()
        return response.json()

    async def add_verification_method_to_did(self, namespace: str, identifier: str, update_key: Key, witness_key: Key, signing_key: Key) -> Dict:
        """Add a verification method to a DID for signing WHOIS."""
        log_entries = await self.get_did_log(namespace, identifier)
        
        from did_webvh.core.state import DocumentState
        
        doc_state = None
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_json(json.dumps(log_entry), doc_state)
        
        did_id = doc_state.document.get("id")
        signing_multikey = self.key_to_multikey(signing_key)
        
        updated_document = doc_state.document.copy()
        verification_method = {
            "id": f"{did_id}#{signing_multikey}",
            "type": "Multikey",
            "controller": did_id,
            "publicKeyMultibase": signing_multikey,
        }
        
        updated_document["verificationMethod"] = updated_document.get("verificationMethod", []) + [verification_method]
        updated_document["assertionMethod"] = updated_document.get("assertionMethod", []) + [verification_method["id"]]
        updated_document["authentication"] = updated_document.get("authentication", []) + [verification_method["id"]]
        
        return await self.update_did(namespace, identifier, update_key, witness_key, updated_document)

    async def upload_whois(self, namespace: str, identifier: str, signing_key: Key, issuer_did: str) -> Dict:
        """Upload WHOIS verifiable presentation."""
        log_entries = await self.get_did_log(namespace, identifier)
        from did_webvh.core.state import DocumentState
        
        doc_state = None
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_json(json.dumps(log_entry), doc_state)
        
        did_id = doc_state.document.get("id")
        signing_multikey = self.key_to_multikey(signing_key)
        verification_method_id = f"{did_id}#{signing_multikey}"
        
        credential = {
            "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
            "type": ["VerifiableCredential", "OrganizationCredential"],
            "issuer": {"id": issuer_did, "name": "Load Test Issuer"},
            "validFrom": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "credentialSubject": {
                "id": did_id,
                "name": f"Organization {identifier}",
                "email": f"contact-{identifier}@example.com",
                "website": f"https://{identifier}.example.com",
                "description": "Created by load test script",
            },
        }
        
        credential = self.sign_document(credential, signing_key, verification_method_id, proof_purpose="assertionMethod")
        
        presentation = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": did_id,
            "verifiableCredential": [credential],
        }
        
        presentation = self.sign_document(presentation, signing_key, verification_method_id, proof_purpose="authentication")
        
        response = await self.session.post(
            f"{self.server_url}/{namespace}/{identifier}/whois",
            json={"verifiablePresentation": presentation},
        )
        
        if response.status_code != 200:
            try:
                error_detail = response.json()
                logger.error(f"WHOIS upload failed: {response.status_code} - {error_detail}")
            except:
                logger.error(f"WHOIS upload failed: {response.status_code} - {response.text}")
        
        response.raise_for_status()
        return response.json()

    async def upload_resource(self, namespace: str, identifier: str, signing_key: Key, resource_content: Dict, resource_type: str = "genericResource") -> Dict:
        """Upload an attested resource."""
        log_entries = await self.get_did_log(namespace, identifier)
        from did_webvh.core.state import DocumentState
        
        doc_state = None
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_json(json.dumps(log_entry), doc_state)
        
        did_id = doc_state.document.get("id")
        signing_multikey = self.key_to_multikey(signing_key)
        verification_method_id = f"{did_id}#{signing_multikey}"
        
        resource_id = multibase.encode(multihash.digest(jcs.canonicalize(resource_content), "sha2-256"), "base58btc")
        
        attested_resource = {
            "@context": ["https://identity.foundation/did-attested-resources/context/v0.1", "https://w3id.org/security/data-integrity/v2"],
            "type": ["AttestedResource"],
            "id": f"{did_id}/resources/{resource_id}",
            "content": resource_content,
            "metadata": {"resourceId": resource_id, "resourceType": resource_type}
        }
        
        attested_resource = self.sign_document(attested_resource, signing_key, verification_method_id, proof_purpose="assertionMethod")
        
        response = await self.session.post(
            f"{self.server_url}/{namespace}/{identifier}/resources",
            json={"attestedResource": attested_resource},
        )
        
        if response.status_code != 201:
            try:
                error_detail = response.json()
                logger.error(f"Resource upload failed: {response.status_code} - {error_detail}")
            except:
                logger.error(f"Resource upload failed: {response.status_code} - {response.text}")
        
        response.raise_for_status()
        return response.json()


def generate_keys() -> tuple[Key, Key, Key]:
    """Generate random keys for testing."""
    update_key = Key.generate(KeyAlg.ED25519)
    witness_key = Key.generate(KeyAlg.ED25519)
    signing_key = Key.generate(KeyAlg.ED25519)
    return update_key, witness_key, signing_key


def create_anoncreds_schema(issuer_id: str, schema_name: str) -> Dict:
    """Create an AnonCreds schema."""
    from anoncreds import Schema
    
    schema = Schema.create(
        name=schema_name,
        version="1.0",
        issuer_id=issuer_id,
        attr_names=["name", "email", "role", "timestamp"]
    )
    
    return schema.to_dict()


async def create_did_with_updates_async(
    client: "DidWebVHAsyncClient",
    namespace: str,
    identifier: str,
    num_updates: int = 2,
) -> Dict:
    """Create a DID and perform multiple updates (async version for concurrent execution)."""
    start_time = time.time()
    
    try:
        # Generate keys
        update_key, witness_key, signing_key = generate_keys()
        
        # Register witness first
        await client.register_witness(witness_key, label=f"Witness for {identifier}")
        
        # Create initial DID
        initial_log = await client.create_did(namespace, identifier, update_key, witness_key)
        did_id = initial_log.get("state", {}).get("id")
        logger.success(f"✓ [{identifier}] Created DID")
        
        # Perform updates
        for i in range(num_updates):
            await client.update_did(namespace, identifier, update_key, witness_key)
            logger.success(f"  [{identifier}] Update {i+1}/{num_updates}")
        
        # Add verification method
        await client.add_verification_method_to_did(
            namespace, identifier, update_key, witness_key, signing_key
        )
        logger.success(f"  [{identifier}] Verification method added")
        
        # Upload WHOIS
        await client.upload_whois(namespace, identifier, signing_key, did_id)
        logger.success(f"  [{identifier}] WHOIS uploaded")
        
        # Create and upload AnonCreds schema
        schema_content = create_anoncreds_schema(did_id, f"LoadTestSchema-{identifier}")
        schema_result = await client.upload_resource(
            namespace, identifier, signing_key, schema_content, "anonCredsSchema"
        )
        schema_id = schema_result.get("metadata", {}).get("resourceId", "unknown")
        logger.success(f"  [{identifier}] Schema uploaded: {schema_id[:20]}...")
        
        elapsed = time.time() - start_time
        
        return {
            "identifier": identifier,
            "did": did_id,
            "success": True,
            "elapsed": elapsed,
            "log_entries": num_updates + 2,
            "schema_id": schema_id,
        }
        
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"✗ [{identifier}] Failed: {e}")
        return {
            "identifier": identifier,
            "success": False,
            "error": str(e),
            "elapsed": elapsed,
        }


async def create_did_with_updates(
    client: DidWebVHClient,
    namespace: str,
    identifier: str,
    num_updates: int = 2,
) -> Dict:
    """Create a DID and perform multiple updates."""
    start_time = time.time()
    
    try:
        # Generate keys
        update_key, witness_key, signing_key = generate_keys()
        
        # Register witness first (required by policy)
        logger.info(f"Registering witness for {namespace}/{identifier}")
        client.register_witness(witness_key, label=f"Witness for {identifier}")
        
        logger.info(f"Creating DID {namespace}/{identifier}")
        
        # Create initial DID
        initial_log = client.create_did(namespace, identifier, update_key, witness_key)
        did_id = initial_log.get("state", {}).get("id")
        logger.success(f"✓ Created DID: {did_id}")
        
        # Perform updates
        for i in range(num_updates):
            logger.info(f"  Update {i+1}/{num_updates} for {identifier}")
            client.update_did(namespace, identifier, update_key, witness_key)
            logger.success(f"  ✓ Update {i+1} complete")
            time.sleep(0.1)  # Small delay between updates
        
        # Add verification method for WHOIS
        logger.info(f"  Adding verification method for {identifier}")
        client.add_verification_method_to_did(
            namespace, identifier, update_key, witness_key, signing_key
        )
        logger.success(f"  ✓ Verification method added")
        
        # Upload WHOIS
        logger.info(f"  Uploading WHOIS for {identifier}")
        whois_result = client.upload_whois(namespace, identifier, signing_key, did_id)
        logger.success(f"  ✓ WHOIS uploaded")
        
        # Create and upload AnonCreds schema
        logger.info(f"  Creating AnonCreds schema for {identifier}")
        schema_content = create_anoncreds_schema(did_id, f"LoadTestSchema-{identifier}")
        schema_result = client.upload_resource(
            namespace, identifier, signing_key, schema_content, "anonCredsSchema"
        )
        schema_id = schema_result.get("metadata", {}).get("resourceId", "unknown")
        logger.success(f"  ✓ Schema uploaded: {schema_id[:20]}...")
        
        elapsed = time.time() - start_time
        
        return {
            "identifier": identifier,
            "did": did_id,
            "success": True,
            "elapsed": elapsed,
            "log_entries": num_updates + 2,  # initial + updates + verification method
            "schema_id": schema_id,
        }
        
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"✗ Failed to create {namespace}/{identifier}: {e}")
        return {
            "identifier": identifier,
            "success": False,
            "error": str(e),
            "elapsed": elapsed,
        }


async def run_load_test(
    server_url: str,
    count: int,
    namespace: str,
    updates_per_did: int,
    concurrent: bool = False,
) -> Dict:
    """Run the load test."""
    logger.info("=" * 70)
    logger.info(f"Starting Load Test")
    logger.info(f"Server: {server_url}")
    logger.info(f"DIDs to create: {count}")
    logger.info(f"Namespace: {namespace}")
    logger.info(f"Updates per DID: {updates_per_did}")
    logger.info(f"Total log entries per DID: {updates_per_did + 2}")
    logger.info("=" * 70)
    
    client = DidWebVHClient(server_url)
    start_time = time.time()
    results = []
    
    # Generate unique identifiers using timestamp + counter to avoid conflicts
    import uuid
    run_id = uuid.uuid4().hex[:8]  # Short unique run ID
    identifiers = [f"{run_id}-{i:04d}" for i in range(count)]
    
    logger.info(f"Run ID: {run_id}")
    logger.info(f"First identifier: {identifiers[0]}")
    
    if concurrent:
        logger.info("Running tests concurrently...")
        
        # Create async client
        async with httpx.AsyncClient(timeout=60.0) as async_session:
            # Create async wrapper for the client
            async_client = DidWebVHAsyncClient(server_url, async_session)
            
            # Run with concurrency limit to avoid overwhelming server
            max_concurrent = min(10, count)  # Max 10 concurrent requests
            logger.info(f"Max concurrent DIDs: {max_concurrent}")
            
            # Process in batches
            for batch_start in range(0, count, max_concurrent):
                batch_end = min(batch_start + max_concurrent, count)
                batch_identifiers = identifiers[batch_start:batch_end]
                
                logger.info(f"\nBatch {batch_start//max_concurrent + 1}: Processing DIDs {batch_start} to {batch_end-1}")
                
                # Run batch concurrently
                batch_tasks = [
                    create_did_with_updates_async(
                        async_client, namespace, identifier, num_updates=updates_per_did
                    )
                    for identifier in batch_identifiers
                ]
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Process results
                for i, result in enumerate(batch_results):
                    if isinstance(result, Exception):
                        results.append({
                            "identifier": batch_identifiers[i],
                            "success": False,
                            "error": str(result),
                            "elapsed": 0,
                        })
                    else:
                        results.append(result)
                
                successful = sum(1 for r in results if r.get("success"))
                logger.info(f"Progress: {len(results)}/{count} completed ({successful} successful)")
    else:
        # Run sequentially
        for i, identifier in enumerate(identifiers, 1):
            logger.info(f"\n[{i}/{count}] Processing DID {identifier}")
            result = await create_did_with_updates(
                client, namespace, identifier, num_updates=updates_per_did
            )
            results.append(result)
            
            # Progress update
            if i % 10 == 0:
                successful = sum(1 for r in results if r.get("success"))
                logger.info(f"Progress: {i}/{count} completed ({successful} successful)")
    
    # Calculate statistics
    total_time = time.time() - start_time
    successful = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    
    schemas_created = sum(1 for r in successful if r.get("schema_id"))
    
    stats = {
        "total_dids": count,
        "successful": len(successful),
        "failed": len(failed),
        "total_time": total_time,
        "avg_time_per_did": total_time / count if count > 0 else 0,
        "total_log_entries": sum(r.get("log_entries", 0) for r in successful),
        "schemas_created": schemas_created,
        "dids_per_second": count / total_time if total_time > 0 else 0,
    }
    
    # Print summary
    logger.info("\n" + "=" * 70)
    logger.info("Load Test Summary")
    logger.info("=" * 70)
    logger.info(f"Total DIDs: {stats['total_dids']}")
    logger.success(f"✓ Successful: {stats['successful']}")
    if stats['failed'] > 0:
        logger.error(f"✗ Failed: {stats['failed']}")
    logger.info(f"Total Time: {stats['total_time']:.2f}s")
    logger.info(f"Avg Time per DID: {stats['avg_time_per_did']:.2f}s")
    logger.info(f"Total Log Entries Created: {stats['total_log_entries']}")
    logger.info(f"AnonCreds Schemas Created: {stats['schemas_created']}")
    logger.info(f"Throughput: {stats['dids_per_second']:.2f} DIDs/second")
    logger.info("=" * 70)
    
    if failed:
        logger.warning(f"\nFailed identifiers:")
        for r in failed:
            logger.error(f"  - {r['identifier']}: {r.get('error', 'Unknown error')}")
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Load test script for DID WebVH Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create 10 DIDs (default)
  uv run python ../demo/load_test.py
  
  # Create 50 DIDs with 3 updates each
  uv run python ../demo/load_test.py --count 50 --updates 3
  
  # Use custom server and namespace
  uv run python ../demo/load_test.py -c 20 -s http://localhost:8000 -n mytest
  
  # Create 100 DIDs with minimal updates
  uv run python ../demo/load_test.py -c 100 -u 1
  
  # Use environment variables for configuration
  export WEBVH_SERVER_URL=http://example.com:8000
  export WEBVH_NAMESPACE=production
  uv run python ../demo/load_test.py -c 50
        """,
    )
    
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=10,
        help="Number of DIDs to create (default: 10)",
    )
    
    parser.add_argument(
        "-s", "--server",
        type=str,
        default=DEFAULT_SERVER_URL,
        help=f"DID WebVH server URL (default: {DEFAULT_SERVER_URL}, env: WEBVH_SERVER_URL)",
    )
    
    parser.add_argument(
        "-n", "--namespace",
        type=str,
        default=DEFAULT_NAMESPACE,
        help=f"Namespace for test DIDs (default: {DEFAULT_NAMESPACE}, env: WEBVH_NAMESPACE)",
    )
    
    parser.add_argument(
        "-u", "--updates",
        type=int,
        default=2,
        help="Number of updates per DID (default: 2, minimum: 1)",
    )
    
    parser.add_argument(
        "--concurrent",
        action="store_true",
        help="Run tests concurrently (experimental)",
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.count < 1:
        logger.error("Count must be at least 1")
        sys.exit(1)
    
    if args.updates < 1:
        logger.error("Updates must be at least 1")
        sys.exit(1)
    
    # Run the load test
    try:
        stats = asyncio.run(
            run_load_test(
                args.server,
                args.count,
                args.namespace,
                args.updates,
                args.concurrent,
            )
        )
        
        # Exit with error code if any DIDs failed
        if stats['failed'] > 0:
            sys.exit(1)
        
    except KeyboardInterrupt:
        logger.warning("\nLoad test interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Load test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

