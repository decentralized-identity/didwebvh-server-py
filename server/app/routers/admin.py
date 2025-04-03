"""Admin endpoints."""

from fastapi import APIRouter, HTTPException, Security, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from app.models.web_schemas import AddWitness
from app.plugins import AskarStorage
from config import settings
from app.utilities import timestamp

router = APIRouter(tags=["Admin"])
askar = AskarStorage()

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
    if api_key_header == settings.SECRET_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


@router.get("/admin/known-witnesses")
async def get_known_witnesses(api_key: str = Security(get_api_key)):
    """Get known witnesses registry."""
    witness_registry = await askar.fetch("registry", "knownWitnesses")

    if not witness_registry:
        raise HTTPException(status_code=500, detail="Error, witness registry not found.")

    return JSONResponse(status_code=200, content=witness_registry)


@router.post("/admin/known-witnesses")
async def add_known_witness(request_body: AddWitness, api_key: str = Security(get_api_key)):
    """Add known witness."""
    request_body = request_body.model_dump()
    witness_registry = await askar.fetch("registry", "knownWitnesses")
    multikey = request_body["multikey"]

    if not multikey.startswith("z6M") or len(multikey) != 48:
        raise HTTPException(status_code=400, detail="Invalid multikey, must be ed25519 type.")

    witness_did = f"did:key:{multikey}"

    if witness_registry["registry"].get(witness_did):
        raise HTTPException(status_code=404, detail="Witness already exists.")

    witness_registry["registry"][witness_did] = {"name": request_body["label"]}
    witness_registry["meta"]["updated"] = timestamp()

    await askar.update("registry", "knownWitnesses", witness_registry)

    return JSONResponse(status_code=200, content=witness_registry)


@router.delete("/admin/known-witnesses/{multikey}")
async def remove_known_witness(multikey: str, api_key: str = Security(get_api_key)):
    """Remove known witness."""
    witness_registry = await askar.fetch("registry", "knownWitnesses")

    if not multikey.startswith("z6M") or len(multikey) != 48:
        raise HTTPException(status_code=400, detail="Invalid multikey, must be ed25519 type.")

    witness_did = f"did:key:{multikey}"

    if not witness_registry["registry"].get(witness_did):
        raise HTTPException(status_code=404, detail="Witness not found.")

    witness_registry["registry"].pop(witness_did)
    witness_registry["meta"]["updated"] = timestamp()

    await askar.update("registry", "knownWitnesses", witness_registry)

    return JSONResponse(status_code=200, content=witness_registry)
