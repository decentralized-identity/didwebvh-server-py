from app.dependencies import identifier_available
from app.models.web_schemas import RegisterDID, RegisterInitialLogEntry
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from config import settings
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter(tags=["Identifiers"])


@router.get("/")
async def request_did(
    namespace: str = None,
    identifier: str = None,
):
    if namespace and identifier:
        did = f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"
        await identifier_available(did)
        return JSONResponse(
            status_code=200,
            content={
                "didDocument": {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": did,
                },
                "proofOptions": AskarVerifier().create_proof_config(did),
            },
        )

    raise HTTPException(status_code=400, detail="Missing request information.")


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
        raise HTTPException(status_code=400, detail="Expecting proof set.")

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

        initial_log_entry = DidWebVH().create(did_document, authorized_key)
        return JSONResponse(status_code=201, content={"logEntry": initial_log_entry})

    raise HTTPException(status_code=400, detail="Missing expected proof.")


@router.post("/{namespace}/{identifier}")
async def initial_log_entry(
    namespace: str,
    identifier: str,
    request_body: RegisterInitialLogEntry,
):
    log_entry = request_body.model_dump()["logEntry"]
    did = f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"

    # Assert proof set
    proof = log_entry.pop("proof", None)
    if len(proof) != 1:
        raise HTTPException(status_code=400, detail="Expecting proof.")

    # Verify proofs
    proof = proof[0]
    authorized_key = proof["verificationMethod"].split("#")[-1]
    if (
        authorized_key != await AskarStorage().fetch("authorizedKey", did)
        or authorized_key != log_entry["parameters"]["updateKeys"][0]
    ):
        raise HTTPException(status_code=400, detail="Key unauthorized.")

    AskarVerifier().verify_proof(log_entry, proof)
    log_entry["proof"] = [proof]
    await AskarStorage().store("logEntries", did, [log_entry])
    did_document = await AskarStorage().fetch("didDocument", did)
    did_document["alsoKnownAs"] = [log_entry["state"]["id"]]
    await AskarStorage().update("didDocument", did, did_document)
    return JSONResponse(status_code=201, content=log_entry)
