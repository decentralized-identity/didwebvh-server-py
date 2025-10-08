"""Ressource management endpoints."""

import copy

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from app.models.web_schemas import ResourceUpload
from app.plugins import AskarVerifier, AskarStorage, DidWebVH
from app.utilities import first_proof, sync_resource, get_client_id, resource_details

from config import settings

router = APIRouter(tags=["Attested Resources"])

webvh = DidWebVH()
storage = AskarStorage()
verifier = AskarVerifier()


@router.post("/{namespace}/{identifier}/resources")
async def upload_attested_resource(namespace, identifier, request_body: ResourceUpload):
    """Upload an attested resource."""

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
            witness_registry = (await storage.fetch("registry", "knownWitnesses")).get("registry")
            witness_id = witness_proof.get("verificationMethod").split("#")[0]
            assert witness_registry.get(witness_id, None)
            assert verifier.verify_proof(resource, witness_proof, witness_id.split(":")[-1])
        except AssertionError:
            raise HTTPException(status_code=400, detail="Invalid endorsement witness proof.")

    secured_resource["proof"] = next(
        (proof for proof in proofs if proof["verificationMethod"].startswith("did:webvh:")), None
    )

    author_id = secured_resource["proof"].get("verificationMethod").split("#")[0]
    if (
        len(author_id.split(":")) != 6
        or author_id.split(":")[4] != namespace
        or author_id.split(":")[5] != identifier
    ):
        raise HTTPException(status_code=400, detail="Invalid author id value.")

    # This will ensure the verification method is registered on the server
    # and that the proof is valid
    await verifier.verify_resource_proof(copy.deepcopy(secured_resource))

    # This will ensure that the resource is properly assigned to it's issuer
    # and double check the digested path
    webvh.validate_resource(copy.deepcopy(secured_resource))

    resource_record, tags = sync_resource(secured_resource)
    store_id = webvh.resource_store_id(copy.deepcopy(secured_resource))

    await storage.store("resource", store_id, secured_resource, tags)
    await storage.store("resourceRecord", store_id, resource_record, tags)

    # Bind to owner
    client_id = get_client_id(namespace, identifier)
    did_record = await storage.fetch("didRecord", client_id)
    did_record["resources"].append(
        {
            "type": secured_resource.get("metadata").get("resourceType"),
            "digest": secured_resource.get("metadata").get("resourceId"),
            "details": resource_details(secured_resource),
        }
    )
    await storage.update("didRecord", client_id, did_record)

    return JSONResponse(status_code=201, content=secured_resource)


@router.put("/{namespace}/{identifier}/resources/{resource_id}")
async def update_attested_resource(
    namespace: str, identifier: str, resource_id: str, request_body: ResourceUpload
):
    """Update an attested resource."""
    secured_resource = vars(request_body)["attestedResource"].model_dump()
    secured_resource["proof"] = first_proof(secured_resource["proof"])

    # This will ensure the verification method is registered
    # on the server and that the proof is valid
    await verifier.verify_resource_proof(copy.deepcopy(secured_resource))

    # This will ensure that the resource is properly assigned
    # to it's issuer and double check the digested path
    webvh.validate_resource(copy.deepcopy(secured_resource))

    store_id = webvh.resource_store_id(copy.deepcopy(secured_resource))

    if not (resource := await storage.fetch("resource", store_id)):
        raise HTTPException(status_code=404, detail="Couldn't find resource.")

    webvh.compare_resource(copy.deepcopy(resource), copy.deepcopy(secured_resource))

    resource_record, tags = sync_resource(secured_resource)

    await storage.update("resource", store_id, secured_resource, tags)
    await storage.update("resourceRecord", store_id, resource_record, tags)
    return JSONResponse(status_code=200, content=secured_resource)


@router.get("/{namespace}/{identifier}/resources/{resource_id}")
async def get_resource(namespace: str, identifier: str, resource_id: str):
    """Fetch existing resource."""

    store_id = f"{namespace}:{identifier}:{resource_id}"

    if not (resource := await storage.fetch("resource", store_id)):
        raise HTTPException(status_code=404, detail="Couldn't find resource.")

    return JSONResponse(status_code=200, content=resource)
