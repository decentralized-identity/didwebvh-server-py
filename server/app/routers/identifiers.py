"""Identifier endpoints for DIDWeb and DIDWebVH."""

import json
import logging
from fastapi import APIRouter, HTTPException, Response, Depends
from fastapi.responses import JSONResponse


from app.models.web_schemas import NewLogEntry, WhoisUpdate
from app.plugins import PolicyError, DidWebVH, AskarVerifier
from did_webvh.core.state import InvalidDocumentState
from app.db.models import DidControllerRecord
from app.utilities import (
    first_proof,
    find_verification_method,
)
from app.dependencies import get_did_controller_dependency
from app.plugins.storage import StorageManager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Identifiers"])
resolver_router = APIRouter(tags=["Resolvers"])
storage = StorageManager()
verifier = AskarVerifier()
webvh = DidWebVH()


@router.post("/{namespace}/{alias}")
async def new_log_entry(
    namespace: str,
    alias: str,
    request_body: NewLogEntry,
):
    """Create a new log entry for a given namespace and alias."""

    log_entry = request_body.model_dump().get("logEntry")
    witness_signature = request_body.model_dump().get("witnessSignature")

    # Debug logging
    logger.info(f"=== New Log Entry Request: {namespace}/{alias} ===")
    logger.debug(f"Log Entry: {json.dumps(log_entry, indent=2)}")
    logger.debug(f"Witness Signature: {witness_signature is not None}")

    # Get policy and registry from database
    policy = storage.get_policy("active")
    registry = storage.get_registry("knownWitnesses")

    # Convert to format expected by DidWebVH
    policy_data = policy.to_dict() if policy else None
    registry_data = registry.registry_data if registry else {}

    webvh = DidWebVH(
        active_policy=policy_data,
        active_registry=registry_data,
    )

    # Get existing DID controller if it exists
    if not (did_controller := storage.get_did_controller_by_alias(namespace, alias)):
        try:
            log_entries, witness_file = await webvh.create_did(log_entry, witness_signature)
        except PolicyError as err:
            raise HTTPException(status_code=400, detail=f"Policy infraction: {err}")
        except InvalidDocumentState as err:
            raise HTTPException(status_code=400, detail=f"Invalid document state: {err}")

        # Create DID controller in database (extracts all data from logs)
        controller = storage.create_did_controller(log_entries, witness_file)
        logger.info(
            f"Created DID controller: {controller.scid} ({controller.namespace}/{controller.alias})"
        )

        return JSONResponse(status_code=201, content=log_entries[-1])

    # Update DID

    try:
        log_entries, witness_file = await webvh.update_did(
            log_entry=log_entry,
            log_entries=did_controller.logs,
            witness_signature=witness_signature,
            prev_witness_file=did_controller.witness_file,
        )

        # Update DID controller in database (re-extracts state from logs)
        storage.update_did_controller(did_controller.scid, log_entries, witness_file)

    except PolicyError as err:
        raise HTTPException(status_code=400, detail=f"Policy infraction: {err}")
    except InvalidDocumentState as err:
        raise HTTPException(status_code=400, detail=f"Invalid document state: {err}")

    # Deactivate DID
    if log_entries[-1].get("parameters").get("deactivated"):
        try:
            webvh.deactivate_did()
        except PolicyError as err:
            raise HTTPException(status_code=400, detail=f"Policy infraction: {err}")

    return JSONResponse(status_code=200, content=log_entries[-1])


@router.post("/{namespace}/{alias}/whois")
async def update_whois(
    request_body: WhoisUpdate,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """See https://didwebvh.info/latest/whois/."""

    doc_state = webvh.get_document_state(did_controller.logs)
    whois_vp = request_body.model_dump().get("verifiablePresentation")

    whois_vp_copy = whois_vp.copy()
    proof = first_proof(whois_vp_copy.pop("proof"))

    if proof.get("verificationMethod").split("#")[0] != doc_state.document.get("id"):
        return JSONResponse(status_code=400, content={"Reason": "Invalid holder."})

    multikey = find_verification_method(doc_state.document, proof.get("verificationMethod"))

    if not (
        multikey := find_verification_method(doc_state.document, proof.get("verificationMethod"))
    ):
        return JSONResponse(status_code=400, content={"Reason": "Invalid verification method."})

    verifier.purpose = "authentication"
    if not verifier.verify_proof(whois_vp_copy, proof, multikey):
        return JSONResponse(status_code=400, content={"Reason": "Verification failed."})

    # Update DID controller with new WHOIS presentation
    storage.update_did_controller(scid=did_controller.scid, whois_presentation=whois_vp)

    return JSONResponse(status_code=200, content={"Message": "Whois VP updated."})


@resolver_router.get("/{namespace}/{alias}/did.json")
async def read_did(did_controller: DidControllerRecord = Depends(get_did_controller_dependency)):
    """See https://identity.foundation/didwebvh/next/#publishing-a-parallel-didweb-did."""

    document_state = webvh.get_document_state(did_controller.logs)

    return Response(json.dumps(document_state.to_did_web()), media_type="application/did+ld+json")


@resolver_router.get("/{namespace}/{alias}/did.jsonl")
async def read_did_log(
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """See https://identity.foundation/didwebvh/next/#the-did-log-file."""
    log_entries = "\n".join([json.dumps(log_entry) for log_entry in did_controller.logs]) + "\n"
    return Response(log_entries, media_type="text/jsonl")


@resolver_router.get("/{namespace}/{alias}/did-witness.json")
async def read_witness_file(
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """See https://identity.foundation/didwebvh/next/#the-witness-proofs-file."""
    if not did_controller.witness_file:
        raise HTTPException(status_code=404, detail="Not Found")

    return JSONResponse(status_code=200, content=did_controller.witness_file)


@resolver_router.get("/{namespace}/{alias}/whois.vp")
async def read_whois(did_controller: DidControllerRecord = Depends(get_did_controller_dependency)):
    """See https://identity.foundation/didwebvh/v1.0/#whois-linkedvp-service."""
    if not did_controller.whois_presentation:
        raise HTTPException(status_code=404, detail="Not Found")

    return Response(json.dumps(did_controller.whois_presentation), media_type="application/vp")
