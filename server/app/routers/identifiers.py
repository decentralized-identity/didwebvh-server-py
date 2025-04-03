"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.models.did_document import DidDocument
from app.models.web_schemas import RegisterDID, NewLogEntry
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from config import settings

router = APIRouter(tags=["Identifiers"])
askar = AskarStorage()
verifier = AskarVerifier()
webvh = DidWebVH()


# DIDWeb
@router.get("/")
async def request_did(
    namespace: str = None,
    identifier: str = None,
):
    """Request a DID document and proof options for a given namespace and identifier."""
    if namespace in settings.RESERVED_NAMESPACES:
        raise HTTPException(status_code=400, detail=f"Reserved namespace {namespace}.")

    if namespace and identifier:
        client_id = f"{namespace}:{identifier}"
        did = f"{settings.DID_WEB_BASE}:{client_id}"

        if await askar.fetch("didDocument", did):
            raise HTTPException(status_code=409, detail="Identifier unavailable.")

        return JSONResponse(
            status_code=200,
            content={
                "didDocument": DidDocument(id=did).model_dump(),
                "proofOptions": AskarVerifier().create_proof_config(did),
            },
        )

    raise HTTPException(status_code=400, detail="Missing namespace or identifier query.")


@router.post("/")
async def register_did(
    request_body: RegisterDID,
):
    """Register a DID document and proof set."""
    did_document = request_body.model_dump()["didDocument"]
    did = did_document["id"]

    if await AskarStorage().fetch("didDocument", did):
        raise HTTPException(status_code=409, detail="Identifier unavailable.")

    # Assert proof set
    proof_set = did_document.pop("proof", None)
    if len(proof_set) != 2:
        raise HTTPException(
            status_code=400, detail="Expecting proof set from controller and endorser."
        )

    witness_registry = (await askar.fetch("registry", "knownWitnesses")).get("registry")
    if not witness_registry:
        raise HTTPException(status_code=500, detail="No witness registry.")

    # Find proof matching known witness
    witness_proof = next(
        (
            proof
            for proof in proof_set
            if witness_registry.get(proof["verificationMethod"].split("#")[0])
        ),
        None,
    )

    # Find proof matching client
    client_proof = next(
        (
            proof
            for proof in proof_set
            if proof["verificationMethod"] != witness_proof["verificationMethod"]
        ),
        None,
    )

    if client_proof and witness_proof:
        # Verify proofs
        # Witness proof
        verifier.validate_challenge(witness_proof, did_document["id"])
        verifier.verify_proof(did_document, witness_proof)

        # Controller proof
        verifier.validate_challenge(client_proof, did_document["id"])
        verifier.verify_proof(did_document, client_proof)

        registration_key = client_proof["verificationMethod"].split("#")[-1]

        # Store document and authorized key
        await askar.store("didDocument", did, did_document)
        await askar.store("registrationKey", did, registration_key)

        return JSONResponse(status_code=201, content={})

    raise HTTPException(status_code=400, detail="Bad Request, something went wrong.")


# DIDWebVH
@router.get("/{namespace}/{identifier}")
async def get_log_state(namespace: str, identifier: str):
    """Get the current state of the log for a given namespace and identifier."""
    client_id = f"{namespace}:{identifier}"
    did = f"{settings.DID_WEB_BASE}:{client_id}"
    did_document = await askar.fetch("didDocument", did)
    if not did_document:
        raise HTTPException(status_code=404, detail="Identifier not found")

    log_entry = await askar.fetch("logEntries", client_id)
    if not log_entry:
        registration_key = await askar.fetch("registrationKey", did)
        initial_log_entry = DidWebVH().create(did_document, registration_key)
        return JSONResponse(status_code=200, content={"logEntry": initial_log_entry})
    return JSONResponse(status_code=200, content={})


@router.post("/{namespace}/{identifier}")
async def new_webvh_log_entry(
    namespace: str,
    identifier: str,
    request_body: NewLogEntry,
):
    """Create a new log entry for a given namespace and identifier."""
    client_id = f"{namespace}:{identifier}"
    did = f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"

    new_log_entry = request_body.model_dump()["logEntry"]
    log_entries = await askar.fetch("logEntries", client_id)

    if not log_entries:
        # First log entry for DID creation
        registration_key = await askar.fetch("registrationKey", did)
        if not registration_key:
            raise HTTPException(status_code=401, detail="Unauthorized")

        document_state = webvh.get_document_state([new_log_entry])
        webvh.verify_state_proofs(document_state)
        # witness_rules = document_state.witness_rule

        if registration_key not in [
            proof["verificationMethod"].split("#")[-1] for proof in document_state.proofs
        ]:
            raise HTTPException(status_code=401, detail="Unauthorized")

        await askar.store("logEntries", client_id, [document_state.history_line()])

        return JSONResponse(status_code=201, content=document_state.history_line())

    prev_document_state = webvh.get_document_state(log_entries)
    if prev_document_state.params.get("deactivated"):
        return JSONResponse(status_code=400, content=prev_document_state.history_line())

    document_state = webvh.get_document_state([new_log_entry], prev_document_state)

    webvh.verify_state_proofs(document_state)

    if prev_document_state.next_key_hashes:
        document_state._validate_key_rotation(
            prev_document_state.next_key_hashes, document_state.update_keys
        )

    # TODO, check witness rules
    if prev_document_state.witness_rule:
        pass

    log_entries.append(document_state.history_line())
    await askar.update("logEntries", client_id, log_entries)
    return JSONResponse(status_code=201, content=document_state.history_line())


@router.get("/{namespace}/{identifier}/did.json", include_in_schema=False)
async def read_did(namespace: str, identifier: str):
    """See https://identity.foundation/didwebvh/next/#read-resolve."""
    client_id = f"{namespace}:{identifier}"
    log_entries = await askar.fetch("logEntries", client_id)
    if log_entries:
        document_state = webvh.get_document_state(log_entries)
        did_document = json.loads(
            json.dumps(document_state.document).replace(
                f"did:webvh:{document_state.scid}:", "did:web:"
            )
        )
        did_document["alsoKnownAs"] = [document_state.document_id]
        return Response(json.dumps(did_document), media_type="application/did+ld+json")

    did = f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"
    did_document = await askar.fetch("didDocument", did)

    if did_document:
        return Response(json.dumps(did_document), media_type="application/did+ld+json")

    raise HTTPException(status_code=404, detail="Not Found")


@router.get("/{namespace}/{identifier}/did.jsonl", include_in_schema=False)
async def read_did_log(namespace: str, identifier: str):
    """See https://identity.foundation/didwebvh/next/#read-resolve."""
    client_id = f"{namespace}:{identifier}"
    log_entries = await askar.fetch("logEntries", client_id)

    if not log_entries:
        raise HTTPException(status_code=404, detail="Not Found")

    log_entries = "\n".join([json.dumps(log_entry) for log_entry in log_entries])
    return Response(f"{log_entries}\n", media_type="text/jsonl")
