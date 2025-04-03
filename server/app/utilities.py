"""Utility functions for the DID Web server."""

from app.models.did_document import DidDocument
from config import settings
import jcs
import json
from multiformats import multibase, multihash
from datetime import datetime, timezone


def is_webvh_did(did):
    """Test for WebVH string."""
    try:
        assert did.split(":")[0] == "did"
        assert did.split(":")[1] == "webvh"
        assert did.split(":")[3]  # SCID
        assert did.split(":")[4] == settings.DOMAIN
        assert did.split(":")[5]  # namespace
        assert did.split(":")[6]  # identifier
        return True
    except AssertionError:
        return False


def digest_multibase(content):
    """Calculate digest multibase."""
    digest_multihash = multihash.digest(jcs.canonicalize(content), "sha2-256")
    digest_multibase = multibase.encode(digest_multihash, "base58btc")
    return digest_multibase


def to_did_web(namespace: str, identifier: str):
    """Convert namespace and identifier to a DID Web identifier."""
    return f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"


def derive_did(namespace, identifier):
    """Derive a DID from a namespace and identifier."""
    return f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"


def create_did_doc(did, multikey, kid="key-01"):
    """Create a DID document."""
    return DidDocument(
        id=did,
        verificationMethod=[
            {
                "id": kid,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multikey,
            }
        ],
        authentication=[kid],
        assertionMethod=[kid],
        service=[],
    ).model_dump()


def find_key(did_doc, kid):
    """Find a key in a DID document."""
    return next(
        (vm["publicKeyMultibase"] for vm in did_doc["verificationMethod"] if vm["id"] == kid),
        None,
    )


def find_proof(proof_set, kid):
    """Find a proof in a proof set."""
    return next(
        (proof for proof in proof_set if proof["verificationMethod"] == kid),
        None,
    )


def first_proof(proof):
    """Return the first proof from a proof set."""
    return proof if isinstance(proof, dict) else proof[0]


def timestamp():
    """Create timestamps."""
    return str(datetime.now(timezone.utc).isoformat("T", "seconds")).replace("+00:00", "Z")


def webvh_to_web_doc(did_document, scid):
    """Trasform did webvh doc to did web."""
    return json.loads(json.dumps(did_document).replace(f"did:webvh:{scid}:", "did:web:"))
