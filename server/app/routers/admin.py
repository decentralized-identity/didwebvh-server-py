"""Admin endpoints."""

from fastapi import APIRouter, HTTPException, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from operator import itemgetter

from app.models.web_schemas import AddWitness
from app.plugins import AskarStorage, DidWebVH
from config import settings
from app.utilities import (
    timestamp,
    is_valid_multikey,
    beautify_date,
    did_to_https,
    resource_details,
    resource_id_to_url,
    sync_resource,
    sync_did_info
)

from app.models.storage import DidRecordTags, DidRecord, ResourceRecordTags, ResourceRecord

router = APIRouter(tags=["Admin"])
askar = AskarStorage()
webvh = DidWebVH()

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


def get_api_key(
    api_key_header: str = Security(api_key_header),
) -> str:
    """Retrieve and validate an API key from the query parameters or HTTP header.

    Args:
        api_key_header: The API key passed in the HTTP header.

    Returns:
        The validated API key.

    Raises:
        HTTPException: If the API key is invalid or missing.
    """
    if api_key_header == settings.API_KEY:
        return api_key_header

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


@router.get("/policy")
async def get_active_policy(api_key: str = Security(get_api_key)):
    """Get active policy."""
    active_policy = await askar.fetch("policy", "active")
    return JSONResponse(status_code=200, content=active_policy)


@router.get("/policy/known-witnesses")
async def get_known_witnesses(api_key: str = Security(get_api_key)):
    """Get known witnesses registry."""
    witness_registry = await askar.fetch("registry", "knownWitnesses")

    if not witness_registry:
        raise HTTPException(status_code=404, detail="Error, witness registry not found.")

    return JSONResponse(status_code=200, content=witness_registry)


@router.post("/policy/known-witnesses")
async def add_known_witness(request_body: AddWitness, api_key: str = Security(get_api_key)):
    """Add known witness."""
    request_body = request_body.model_dump()
    witness_registry = await askar.fetch("registry", "knownWitnesses")
    multikey = request_body["multikey"]

    if not is_valid_multikey(multikey, alg="ed25519"):
        raise HTTPException(status_code=400, detail="Invalid multikey, must be ed25519 type.")

    witness_did = f"did:key:{multikey}"

    if witness_registry["registry"].get(witness_did):
        raise HTTPException(status_code=409, detail="Witness already exists.")

    witness_registry["registry"][witness_did] = {"name": request_body["label"]}
    witness_registry["meta"]["updated"] = timestamp()

    await askar.update("registry", "knownWitnesses", witness_registry)

    return JSONResponse(status_code=200, content=witness_registry)


@router.delete("/policy/known-witnesses/{multikey}")
async def remove_known_witness(multikey: str, api_key: str = Security(get_api_key)):
    """Remove known witness."""
    witness_registry = await askar.fetch("registry", "knownWitnesses")

    if not is_valid_multikey(multikey, alg="ed25519"):
        raise HTTPException(status_code=400, detail="Invalid multikey, must be ed25519 type.")

    witness_did = f"did:key:{multikey}"

    if not witness_registry["registry"].get(witness_did):
        raise HTTPException(status_code=404, detail="Witness not found.")

    witness_registry["registry"].pop(witness_did)
    witness_registry["meta"]["updated"] = timestamp()

    await askar.update("registry", "knownWitnesses", witness_registry)

    return JSONResponse(status_code=200, content=witness_registry)


@router.post("/sync")
async def sync_storage(api_key: str = Security(get_api_key)):
    """Sync storage."""

    for entry in await askar.get_category_entries("resource"):
        resource_record, tags = sync_resource(entry.value_json)
        await askar.update("resource", entry.name, entry.value_json, tags=tags)
        await askar.store_or_update("resourceRecord", entry.name, resource_record, tags=tags)

    for entry in await askar.get_category_entries("logEntries"):
        logs = entry.value_json
        state = webvh.get_document_state(logs)
        did_record, tags = sync_did_info(
            state=state,
            logs=logs, 
            did_resources=[
                resource.value_json for resource in 
                await askar.get_category_entries("resource", {"scid": state.scid})
            ],
            witness_file=(await askar.fetch("witnessFile", entry.name) or []),
            whois_presentation=(await askar.fetch("whois", entry.name) or {})
        )
        await askar.update("logEntries", entry.name, entry.value_json, tags=tags)
        await askar.store_or_update("didRecord", entry.name, did_record, tags=tags)

    return JSONResponse(status_code=200, content={})
