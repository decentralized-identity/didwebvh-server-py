from app.models.did_document import DidDocument
from config import settings
from app.plugins import AskarVerifier, AskarStorage
import jcs
from multiformats import multibase, multihash
from fastapi import HTTPException


def is_webvh_did(did):
    try:
        assert did.split(':')[0] == 'did'
        assert did.split(':')[1] == 'webvh'
        assert did.split(':')[3] # SCID
        assert did.split(':')[4] == settings.DOMAIN
        assert did.split(':')[5] # namespace
        assert did.split(':')[6] # identifier
        return True
    except:
        return False

def digest_multibase(content):
    digest_multihash = multihash.digest(
        jcs.canonicalize(content), "sha2-256"
    )
    digest_multibase = multibase.encode(digest_multihash, "base58btc")
    return digest_multibase
    

def to_did_web(namespace: str, identifier: str):
    return f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"


async def location_available(did: str):
    if await AskarStorage().fetch("didDocument", did):
        raise HTTPException(status_code=409, detail="Identifier unavailable.")


async def did_document_exists(did: str):
    if not await AskarStorage().fetch("didDocument", did):
        raise HTTPException(status_code=404, detail="Ressource not found.")


async def valid_did_registration(did_document):
    did_document
    proofs = did_document.pop("proof")
    try:
        # assert (
        #     did_document["id"] == f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"
        # ), "Id mismatch between DID Document and requested endpoint."
        assert (
            len(did_document["verificationMethod"]) >= 1
        ), "DID Documentmust contain at least 1 verificationMethod."
        assert (
            isinstance(proofs, list) and len(proofs) == 2
        ), "Insuficient proofs, must contain a client and an endorser proof."
    except AssertionError as msg:
        raise HTTPException(status_code=400, detail=str(msg))

    endorser_proof = find_proof(proofs, f"{settings.DID_WEB_BASE}#key-01")
    endorser_key = settings.ENDORSER_MULTIKEY
    AskarVerifier(endorser_key).verify_proof(did_document, endorser_proof)

    client_proof = find_proof(proofs, did_document["verificationMethod"][0]["id"])
    client_key = find_key(did_document, client_proof["verificationMethod"])
    AskarVerifier(client_key).verify_proof(did_document, client_proof)

    return did_document


async def identifier_available(identifier: str):
    if await AskarStorage().fetch("didDocument", identifier):
        raise HTTPException(status_code=409, detail="Identifier unavailable.")


def derive_did(namespace, identifier):
    return f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"


def create_did_doc(did, multikey, kid="key-01"):
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
    return next(
        (
            vm["publicKeyMultibase"]
            for vm in did_doc["verificationMethod"]
            if vm["id"] == kid
        ),
        None,
    )


def find_proof(proof_set, kid):
    return next(
        (proof for proof in proof_set if proof["verificationMethod"] == kid),
        None,
    )

def first_proof(proof):
    return proof if isinstance(proof, dict) else proof[0]