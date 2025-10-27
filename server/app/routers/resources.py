"""Ressource management endpoints."""

import copy
import logging

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from app.models.web_schemas import ResourceUpload
from app.db.models import DidControllerRecord
from app.utilities import first_proof
from app.routers.dependencies import get_did_controller_dependency
from app.plugins import AskarVerifier, DidWebVH
from app.plugins.storage import StorageManager

from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Attested Resources"])

webvh = DidWebVH()
storage = StorageManager()
verifier = AskarVerifier()


@router.post("/{namespace}/{identifier}/resources")
async def upload_attested_resource(
    request_body: ResourceUpload,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """Upload an attested resource."""
    logger.info(f"=== Uploading resource for {did_controller.namespace}/{did_controller.alias} ===")

    secured_resource = vars(request_body)["attestedResource"].model_dump()
    resource = copy.deepcopy(secured_resource)
    proofs = resource.pop("proof")
    proofs = proofs if isinstance(proofs, list) else [proofs]

    # Check if endorsement policy is set for attested resources
    if settings.WEBVH_ENDORSEMENT:
        try:
            assert len(proofs) == 2
            witness_proof = next(
                (proof for proof in proofs if proof["verificationMethod"].startswith("did:key:")),
                None,
            )
            registry = storage.get_registry("knownWitnesses")
            witness_registry = registry.registry_data if registry else {}
            witness_id = witness_proof.get("verificationMethod").split("#")[0]
            assert witness_registry.get(witness_id, None)
            assert verifier.verify_proof(resource, witness_proof, witness_id.split(":")[-1])
        except AssertionError as e:
            logger.error(f"Endorsement validation failed: {e}")
            raise HTTPException(status_code=400, detail="Invalid endorsement witness proof.")

    secured_resource["proof"] = next(
        (proof for proof in proofs if proof["verificationMethod"].startswith("did:webvh:")), None
    )

    author_id = secured_resource["proof"].get("verificationMethod").split("#")[0]
    if (
        len(author_id.split(":")) != 6
        or author_id.split(":")[4] != did_controller.namespace
        or author_id.split(":")[5] != did_controller.alias
    ):
        raise HTTPException(status_code=400, detail="Invalid author id value.")

    # Get the DID document for verification
    controller_document = did_controller.document

    try:
        verifier.verify_resource_proof(copy.deepcopy(secured_resource), controller_document)
    except HTTPException as e:
        logger.error(f"Resource proof validation failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid resource proof.")

    try:
        webvh.validate_resource(copy.deepcopy(secured_resource))
    except HTTPException as e:
        logger.error(f"Resource validation failed: {e.status_code} - {e.detail}")
        raise HTTPException(status_code=400, detail=f"Invalid resource: {e.detail}")

    storage.create_resource(did_controller.scid, secured_resource)

    return JSONResponse(status_code=201, content=secured_resource)


@router.put("/{namespace}/{identifier}/resources/{resource_id}")
async def update_attested_resource(
    resource_id: str,
    request_body: ResourceUpload,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """Update an attested resource."""
    logger.info(f"=== Updating resource for {did_controller.namespace}/{did_controller.alias} ===")

    secured_resource = vars(request_body)["attestedResource"].model_dump()
    secured_resource["proof"] = first_proof(secured_resource["proof"])

    # This will ensure the verification method is registered
    # on the server and that the proof is valid
    try:
        # Get the DID document for verification
        controller_document = did_controller.document
        verifier.verify_resource_proof(copy.deepcopy(secured_resource), controller_document)
    except HTTPException as e:
        logger.error(f"Resource proof validation failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid resource proof.")

    # This will ensure that the resource is properly assigned
    # to it's issuer and double check the digested path
    try:
        webvh.validate_resource(copy.deepcopy(secured_resource))
    except HTTPException as e:
        logger.error(f"Resource validation failed: {e.status_code} - {e.detail}")
        raise HTTPException(status_code=400, detail=f"Invalid resource: {e.detail}")

    if not (existing_resource := storage.get_resource(resource_id)):
        raise HTTPException(status_code=404, detail="Couldn't find resource.")

    webvh.compare_resource(
        copy.deepcopy(existing_resource.attested_resource), copy.deepcopy(secured_resource)
    )
    storage.update_resource(secured_resource)

    return JSONResponse(status_code=200, content=secured_resource)


@router.get("/{namespace}/{identifier}/resources/{resource_id}")
async def get_resource(
    resource_id: str, did_controller: DidControllerRecord = Depends(get_did_controller_dependency)
):
    """Fetch existing resource."""
    logger.info(f"=== Fetching resource for {did_controller.namespace}/{did_controller.alias} ===")

    if not (resource := storage.get_resource(resource_id)):
        raise HTTPException(status_code=404, detail="Couldn't find resource.")

    return JSONResponse(status_code=200, content=resource.attested_resource)
