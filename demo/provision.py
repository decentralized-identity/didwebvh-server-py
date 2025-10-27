"""Provision script for DID WebVH server with sample data."""

import os
import requests
import uuid
import time
from loguru import logger

from operator import itemgetter

AGENT_ADMIN_API_URL = os.getenv("AGENT_ADMIN_API_URL", "http://witness-agent:8020")
AGENT_ADMIN_API_HEADERS = {"X-API-KEY": os.getenv("AGENT_ADMIN_API_KEY", "")}
WATCHER_API_HEADERS = {"X-API-KEY": os.getenv("WATCHER_API_KEY", "")}
WEBVH_SERVER_URL = os.getenv("WEBVH_SERVER_URL", None)
WATCHER_URL = os.getenv("WATCHER_URL", None)


def try_return(request):
    """Extract JSON from request with rate limiting delay."""
    # Sleep to avoid rate limiting
    time.sleep(1)
    try:
        return request.json()
    except requests.exceptions.JSONDecodeError:
        logger.warning("Unexpected response from agent:")
        logger.warning(request.text)
        raise requests.exceptions.JSONDecodeError


def configure_plugin(server_url=WEBVH_SERVER_URL):
    """Configure the DID WebVH plugin on the agent."""
    logger.info("Configuring plugin")
    r = requests.post(
        f"{AGENT_ADMIN_API_URL}/did/webvh/configuration",
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            "server_url": server_url,
            "notify_watchers": True,
            "witness": True,
            "auto_attest": True,
            "endorsement": False,
        },
    )
    return try_return(r)


def register_watcher(did):
    """Register a DID with the watcher service."""
    scid = itemgetter(2)(did.split(":"))
    logger.info(f"Registering watcher {scid}")
    r = requests.post(f"{WATCHER_URL}/scid?did={did}", headers=WATCHER_API_HEADERS)
    return try_return(r)


def notify_watcher(did):
    """Notify the watcher service about DID updates."""
    scid = itemgetter(2)(did.split(":"))
    logger.info(f"Notifying watcher {scid}")
    r = requests.post(f"{WATCHER_URL}/log?did={did}")
    return try_return(r)


def create_did(namespace):
    """Create a new DID in the specified namespace."""
    logger.info(f"Creating DID in {namespace}")
    r = requests.post(
        f"{AGENT_ADMIN_API_URL}/did/webvh/create",
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            "options": {
                "apply_policy": 1,
                "witnessThreshold": 1,
                "watchers": [WATCHER_URL],
                "namespace": namespace,
                "identifier": str(uuid.uuid4())[:6],
            }
        },
    )
    return try_return(r)


def update_did(scid):
    """Update an existing DID by SCID."""
    logger.info(f"Updating DID {scid}")
    r = requests.post(
        f"{AGENT_ADMIN_API_URL}/did/webvh/update?scid={scid}",
        headers=AGENT_ADMIN_API_HEADERS,
        json={},
    )
    return try_return(r)


def deactivate_did(scid):
    """Deactivate a DID by SCID."""
    logger.info(f"Deactivating DID {scid}")
    r = requests.post(
        f"{AGENT_ADMIN_API_URL}/did/webvh/deactivate?scid={scid}",
        headers=AGENT_ADMIN_API_HEADERS,
        json={"options": {}},
    )
    return try_return(r)


def sign_credential(issuer_id, subject_id):
    """Sign a verifiable credential for the subject."""
    scid = itemgetter(2)(subject_id.split(":"))
    logger.info(f"Signing credential {scid}")
    issuer_key = issuer_id.split(":")[-1]
    r = requests.post(
        f"{AGENT_ADMIN_API_URL}/vc/di/add-proof",
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            "document": {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://www.w3.org/ns/credentials/examples/v2",
                ],
                "type": ["VerifiableCredential", "ExampleIdentityCredential"],
                "issuer": {"id": issuer_id, "name": "Example Issuer"},
                "credentialSubject": {
                    "id": subject_id,
                    "description": "Sample VC for WHOIS.vp",
                },
            },
            "options": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod": f"{issuer_id}#{issuer_key}",
            },
        },
    )
    return try_return(r)


def sign_presentation(signing_key, credential):
    """Sign a verifiable presentation containing the credential."""
    holder_id = credential.get("credentialSubject").get("id")
    scid = itemgetter(2)(holder_id.split(":"))
    logger.info(f"Signing presentation {scid}")
    r = requests.post(
        f"{AGENT_ADMIN_API_URL}/vc/di/add-proof",
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            "document": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": holder_id,
                "verifiableCredential": [credential],
            },
            "options": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "authentication",
                "verificationMethod": f"{holder_id}#{signing_key}",
            },
        },
    )
    return try_return(r)


def upload_whois(vp):
    """Upload a WHOIS verifiable presentation to the server."""
    holder_id = vp.get("holder")
    scid, namespace, alias = itemgetter(2, 4, 5)(holder_id.split(":"))
    logger.info(f"Uploading whois {scid}")
    r = requests.post(
        f"{WEBVH_SERVER_URL}/{namespace}/{alias}/whois",
        json={"verifiablePresentation": vp},
    )
    return try_return(r)


def create_schema(issuer_id, name="Test Schema", version="1.0", attributes=None):
    """Create an AnonCreds schema."""
    if attributes is None:
        attributes = ["test_attribute"]
    scid = itemgetter(2)(issuer_id.split(":"))
    logger.info(f"Creating schema {scid}")
    r = requests.post(
        f"{AGENT_ADMIN_API_URL}/anoncreds/schema",
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            "schema": {
                "attrNames": attributes,
                "issuerId": issuer_id,
                "name": name,
                "version": version,
            }
        },
    )
    return try_return(r)


def create_cred_def(schema_id, tag="default", revocation_size=0):
    """Create an AnonCreds credential definition for the schema."""
    issuer_id = schema_id.split("/")[0]
    scid = itemgetter(2)(issuer_id.split(":"))
    logger.info(f"Creating cred def {scid}")
    r = requests.post(
        f"{AGENT_ADMIN_API_URL}/anoncreds/credential-definition",
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            "credential_definition": {
                "issuerId": issuer_id,
                "schemaId": schema_id,
                "tag": tag,
            },
            "options": {
                "revocation_registry_size": revocation_size,
                "support_revocation": True if revocation_size else False,
            },
        },
    )
    return try_return(r)


logger.info("Configuring Agent")
webvh_config = configure_plugin(WEBVH_SERVER_URL)
witness_id = webvh_config.get("witnesses")[0]
logger.info(f"Witness Configured: {witness_id}")
logger.info("Provisioning Server")

# Create DIDs in two namespaces
for namespace in ["ns-01", "ns-02"]:
    # Create 2 DIDs in each namespace
    for idx in range(2):
        log_entry = create_did(namespace)
        scid = log_entry.get("parameters", {}).get("scid")
        did = log_entry.get("state", {}).get("id")
        signing_key = (
            log_entry.get("state", {}).get("verificationMethod")[0].get("publicKeyMultibase")
        )
        logger.info(f"New signing key: {signing_key}")

        # Register with watcher if configured
        if WATCHER_URL:
            register_watcher(did)

        # NOTE, following lines depend on next plugin release
        # Update the DID twice to generate some log entries
        update_did(scid)
        update_did(scid)
        notify_watcher(did)

        # Create a sample whois VP
        vc = sign_credential(witness_id, did).get("securedDocument")
        vp = sign_presentation(signing_key, vc).get("securedDocument")
        whois = upload_whois(vp)

        # Create anoncreds schema and cred def
        schema = create_schema(did)
        schema_id = schema.get("schema_state", {}).get("schema_id", None)
        cred_def = create_cred_def(schema_id, revocation_size=10)
        cred_def_id = cred_def.get("credential_definition_state", {}).get(
            "credential_definition_id", None
        )

        # Deactivate every second DID to generate some activity
        if idx == 1:
            deactivate_did(scid)
