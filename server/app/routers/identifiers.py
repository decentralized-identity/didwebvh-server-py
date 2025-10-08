"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse, RedirectResponse

from config import settings

from app.models.web_schemas import NewLogEntry, WhoisUpdate
from app.plugins import AskarStorage, AskarVerifier, DidWebVH, PolicyError
from app.utilities import (
    get_client_id,
    first_proof,
    find_verification_method,
    timestamp,
    sync_did_info,
)

router = APIRouter(tags=["Identifiers"])
askar = AskarStorage()
verifier = AskarVerifier()
webvh = DidWebVH()


@router.get("/")
async def request_did(
    namespace: str = None,
    identifier: str = None,
):
    """Request a DID document and proof options for a given namespace and identifier."""

    if not namespace and not identifier:
        return RedirectResponse(url="/explorer", status_code=302)

    if not namespace or not identifier:
        raise HTTPException(status_code=400, detail="Missing namespace or identifier query.")

    client_id = get_client_id(namespace, identifier)

    if await askar.fetch("logEntries", client_id):
        raise HTTPException(status_code=409, detail="Identifier unavailable.")

    if namespace in settings.RESERVED_NAMESPACES:
        raise HTTPException(status_code=400, detail=f"Unavailable namespace: {namespace}.")

    return JSONResponse(
        status_code=200,
        content={
            "versionId": webvh.scid_placeholder,
            "versionTime": timestamp(),
            "parameters": webvh.parameters(),
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": webvh.placeholder_id(namespace, identifier),
            },
            "proof": webvh.proof_options(),
        },
    )


@router.post("/{namespace}/{identifier}")
async def new_log_entry(
    namespace: str,
    identifier: str,
    request_body: NewLogEntry,
):
    """Create a new log entry for a given namespace and identifier."""

    client_id = get_client_id(namespace, identifier)

    log_entry = request_body.model_dump().get("logEntry")
    witness_signature = request_body.model_dump().get("witnessSignature")

    prev_log_entries = await askar.fetch("logEntries", client_id) or []
    prev_witness_file = await askar.fetch("witnessFile", client_id)

    webvh = DidWebVH(
        active_policy=await askar.fetch("policy", "active"),
        active_registry=(await askar.fetch("registry", "knownWitnesses")).get("registry"),
    )

    # Create DID
    if not prev_log_entries:
        try:
            log_entries, witness_file = await webvh.create_did(log_entry, witness_signature)
        except PolicyError as err:
            raise HTTPException(status_code=400, detail=f"Policy infraction: {err}")

        did_record, tags = sync_did_info(
            state=webvh.get_document_state(log_entries),
            logs=log_entries,
            did_resources=[],
            witness_file=witness_file,
            whois_presentation={},
        )

        await askar.store("logEntries", client_id, log_entries, tags)
        await askar.store("witnessFile", client_id, witness_file, tags)
        await askar.store("didRecord", client_id, did_record, tags)

        return JSONResponse(status_code=201, content=log_entries[-1])

    # Update DID
    try:
        log_entries, witness_file = await webvh.update_did(
            log_entry=log_entry,
            log_entries=prev_log_entries,
            witness_signature=witness_signature,
            prev_witness_file=prev_witness_file,
        )
    except PolicyError as err:
        raise HTTPException(status_code=400, detail=f"Policy infraction: {err}")

    state = webvh.get_document_state(log_entries)

    did_record, tags = sync_did_info(
        state=state,
        logs=log_entries,
        did_resources=[
            resource.value_json
            for resource in await askar.get_category_entries("resource", {"scid": state.scid})
        ],
        witness_file=witness_file,
        whois_presentation=(await askar.fetch("whois", client_id) or {}),
    )

    await askar.update("logEntries", client_id, log_entries, tags)
    await askar.update("witnessFile", client_id, witness_file, tags)
    await askar.update("didRecord", client_id, did_record, tags)

    # Deactivate DID
    if log_entries[-1].get("parameters").get("deactivated"):
        try:
            webvh.deactivate_did()
        except PolicyError as err:
            raise HTTPException(status_code=400, detail=f"Policy infraction: {err}")

    return JSONResponse(status_code=200, content=log_entries[-1])


@router.get("/{namespace}/{identifier}/did.json", include_in_schema=False)
async def read_did(namespace: str, identifier: str):
    """See https://identity.foundation/didwebvh/next/#publishing-a-parallel-didweb-did."""
    client_id = get_client_id(namespace, identifier)
    log_entries = await askar.fetch("logEntries", client_id)

    if not log_entries:
        raise HTTPException(status_code=404, detail="Not Found")

    document_state = webvh.get_document_state(log_entries)
    did_document = json.dumps(document_state.to_did_web())
    return Response(did_document, media_type="application/did+ld+json")


@router.get("/{namespace}/{identifier}/did.jsonl", include_in_schema=False)
async def read_did_log(namespace: str, identifier: str):
    """See https://identity.foundation/didwebvh/next/#the-did-log-file."""
    client_id = get_client_id(namespace, identifier)
    log_entries = await askar.fetch("logEntries", client_id)

    if not log_entries:
        raise HTTPException(status_code=404, detail="Not Found")

    log_entries = "\n".join([json.dumps(log_entry) for log_entry in log_entries]) + "\n"
    return Response(log_entries, media_type="text/jsonl")


@router.get("/{namespace}/{identifier}/did-witness.json", include_in_schema=False)
async def read_witness_file(namespace: str, identifier: str):
    """See https://identity.foundation/didwebvh/next/#the-witness-proofs-file."""
    client_id = get_client_id(namespace, identifier)
    witness_file = await askar.fetch("witnessFile", client_id)
    if not witness_file:
        raise HTTPException(status_code=404, detail="Not Found")

    return JSONResponse(status_code=200, content=witness_file)


@router.get("/{namespace}/{identifier}/whois.vp", include_in_schema=False)
async def read_whois(namespace: str, identifier: str):
    """See https://identity.foundation/didwebvh/v1.0/#whois-linkedvp-service."""

    client_id = get_client_id(namespace, identifier)
    whois_vp = await askar.fetch("whois", client_id)

    if not whois_vp:
        raise HTTPException(status_code=404, detail="Not Found")

    return Response(json.dumps(whois_vp), media_type="application/vp")


@router.post("/{namespace}/{identifier}/whois")
async def update_whois(namespace: str, identifier: str, request_body: WhoisUpdate):
    """See https://didwebvh.info/latest/whois/."""

    client_id = get_client_id(namespace, identifier)

    log_entries = await askar.fetch("logEntries", client_id)

    if not log_entries:
        raise HTTPException(status_code=404, detail="Not Found")

    doc_state = webvh.get_document_state(log_entries)

    whois_vp = request_body.model_dump().get("verifiablePresentation")

    whois_vp_copy = whois_vp.copy()
    proof = first_proof(whois_vp_copy.pop("proof"))

    if proof.get("verificationMethod").split("#")[0] != doc_state.document.get("id"):
        return JSONResponse(status_code=400, content={"Reason": "Invalid holder."})

    multikey = find_verification_method(doc_state.document, proof.get("verificationMethod"))

    if not multikey:
        return JSONResponse(status_code=400, content={"Reason": "Invalid verification method."})

    verifier.purpose = "authentication"
    if not verifier.verify_proof(whois_vp_copy, proof, multikey):
        return JSONResponse(status_code=400, content={"Reason": "Verification failed."})

    await askar.store_or_update("whois", client_id, whois_vp)

    # Update DID record
    did_record = await askar.fetch("didRecord", client_id)
    did_record["whois_presentation"] = whois_vp
    await askar.update("didRecord", client_id, did_record)

    return JSONResponse(status_code=200, content={"Message": "Whois VP updated."})
