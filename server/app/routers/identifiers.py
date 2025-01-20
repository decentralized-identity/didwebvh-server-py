from app.dependencies import identifier_available
from app.models.web_schemas import RegisterDID, RegisterInitialLogEntry, UpdateLogEntry
from app.models.did_document import DidDocument
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from config import settings
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse
import json

router = APIRouter(tags=["Identifiers"])


# DIDWeb
@router.get("/")
async def request_did(
    namespace: str = None,
    identifier: str = None,
):
    if namespace and identifier:
        client_id = f"{namespace}:{identifier}"
        did = f"{settings.DID_WEB_BASE}:{client_id}"
        await identifier_available(did)
        return JSONResponse(
            status_code=200,
            content={
                "didDocument": DidDocument(id=did).model_dump(),
                "proofOptions": AskarVerifier().create_proof_config(did),
            },
        )

    raise HTTPException(
        status_code=400, detail="Missing namespace or identifier query."
    )


@router.post("/")
async def register_did(
    request_body: RegisterDID,
):
    did_document = request_body.model_dump()["didDocument"]
    did = did_document["id"]

    await identifier_available(did)

    # Assert proof set
    proof_set = did_document.pop("proof", None)
    if len(proof_set) != 2:
        raise HTTPException(
            status_code=400, detail="Expecting proof set from controller and endorser."
        )

    # Find proof matching endorser
    endorser_proof = next(
        (
            proof
            for proof in proof_set
            if proof["verificationMethod"]
            == f"did:key:{settings.ENDORSER_MULTIKEY}#{settings.ENDORSER_MULTIKEY}"
        ),
        None,
    )

    # Find proof matching client
    client_proof = next(
        (
            proof
            for proof in proof_set
            if proof["verificationMethod"]
            != f"did:key:{settings.ENDORSER_MULTIKEY}#{settings.ENDORSER_MULTIKEY}"
        ),
        None,
    )

    if client_proof and endorser_proof:
        # Verify proofs
        AskarVerifier().validate_challenge(client_proof, did_document["id"])
        AskarVerifier().verify_proof(did_document, client_proof)
        AskarVerifier().validate_challenge(endorser_proof, did_document["id"])
        AskarVerifier().verify_proof(did_document, endorser_proof)
        authorized_key = client_proof["verificationMethod"].split("#")[-1]

        # Store document and authorized key
        await AskarStorage().store("didDocument", did, did_document)
        await AskarStorage().store("authorizedKey", did, authorized_key)
        return JSONResponse(status_code=201, content={})

        initial_log_entry = DidWebVH().create(did_document, authorized_key)
        return JSONResponse(status_code=201, content={"logEntry": initial_log_entry})

    raise HTTPException(status_code=400, detail="Bad Request, something went wrong.")


# DIDWebVH
@router.get("/{namespace}/{identifier}")
async def get_log_state(namespace: str, identifier: str):
    client_id = f"{namespace}:{identifier}"
    did = f"{settings.DID_WEB_BASE}:{client_id}"
    did_doc = await AskarStorage().fetch("didDocument", did)
    if not did_doc:
        raise HTTPException(status_code=404, detail="Identifier not found")
    log_entry = await AskarStorage().fetch("logEntries", client_id)
    if not log_entry:
        did = f"{settings.DID_WEB_BASE}:{client_id}"
        did_document = await AskarStorage().fetch("didDocument", did)
        authorized_key = await AskarStorage().fetch("authorizedKey", did)
        initial_log_entry = DidWebVH().create(did_document, authorized_key)
        return JSONResponse(status_code=200, content={"logEntry": initial_log_entry})
    return JSONResponse(status_code=200, content={})


@router.post("/{namespace}/{identifier}")
async def create_didwebvh(
    namespace: str,
    identifier: str,
    request_body: RegisterInitialLogEntry,
):
    client_id = f"{namespace}:{identifier}"
    log_entry = request_body.model_dump()["logEntry"]
    did = f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"

    # Assert proof set
    proof = log_entry.pop("proof", None)
    proof = proof if isinstance(proof, list) else [proof]
    if len(proof) != 1:
        raise HTTPException(
            status_code=400, detail="Expecting singular proof from controller."
        )

    # Verify proofs
    proof = proof[0]
    authorized_key = proof["verificationMethod"].split("#")[-1]
    if (
        authorized_key != await AskarStorage().fetch("authorizedKey", did)
        or authorized_key != log_entry["parameters"]["updateKeys"][0]
    ):
        raise HTTPException(status_code=401, detail="Unauthorized")

    AskarVerifier().verify_proof(log_entry, proof)
    log_entry["proof"] = [proof]

    await AskarStorage().store("logEntries", client_id, [log_entry])

    did_document = await AskarStorage().fetch("didDocument", did)
    did_document["alsoKnownAs"] = [log_entry["state"]["id"]]
    await AskarStorage().update("didDocument", did, did_document)
    return JSONResponse(status_code=201, content=log_entry)


@router.get("/{namespace}/{identifier}/did.json", include_in_schema=False)
async def read_did(namespace: str, identifier: str):
    """
    https://identity.foundation/didwebvh/next/#read-resolve
    """
    client_id = f"{namespace}:{identifier}"
    did = f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"
    did_doc = await AskarStorage().fetch("didDocument", did)
    if did_doc:
        return Response(json.dumps(did_doc), media_type="application/did+ld+json")
    raise HTTPException(status_code=404, detail="Not Found")


@router.get("/{namespace}/{identifier}/did.jsonl", include_in_schema=False)
async def read_did_log(namespace: str, identifier: str):
    """
    https://identity.foundation/didwebvh/next/#read-resolve
    """
    client_id = f"{namespace}:{identifier}"
    log_entries = await AskarStorage().fetch("logEntries", client_id)
    if log_entries:
        log_entries = "\n".join([json.dumps(log_entry) for log_entry in log_entries])
        return Response(log_entries, media_type="text/jsonl")
    raise HTTPException(status_code=404, detail="Not Found")


@router.put("/{namespace}/{identifier}")
async def update_did(namespace: str, identifier: str, request_body: UpdateLogEntry):
    """
    https://identity.foundation/didwebvh/next/#update-rotate
    """
    client_id = f"{namespace}:{identifier}"
    raise HTTPException(status_code=501, detail="Not Implemented")


@router.delete("/{namespace}/{identifier}")
async def deactivate_did(namespace: str, identifier: str):
    """
    https://identity.foundation/didwebvh/next/#deactivate-revoke
    """
    client_id = f"{namespace}:{identifier}"
    raise HTTPException(status_code=501, detail="Not Implemented")
