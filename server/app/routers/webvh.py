from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from config import settings
from app.models.did_log import LogParameters, InitialLogEntry
from app.models.web_schemas import UpdateLogEntry
from app.plugins import DidWebVH

router = APIRouter(tags=["WebVH"])

@router.post("/{namespace}/{identifier}")
async def create_did(namespace: str, identifier: str):
    """
    https://identity.foundation/didwebvh/next/#create-register
    """
    did_string = r'did:webvh:{SCID}'+settings.DOMAIN
    update_key = ''
    initial_did_doc = DidWebVH().create_initial_did_doc(did_string)
    parameters = LogParameters(
        updateKeys=[update_key]
    )
    pass

@router.get("/{namespace}/{identifier}/did.json")
async def read_did(namespace: str, identifier: str):
    """
    https://identity.foundation/didwebvh/next/#read-resolve
    """
    pass

@router.get("/{namespace}/{identifier}/did.jsonl")
async def read_did_log(namespace: str, identifier: str):
    """
    https://identity.foundation/didwebvh/next/#read-resolve
    """
    pass

@router.put("/{namespace}/{identifier}")
async def update_did(namespace: str, identifier: str, request_body: UpdateLogEntry):
    """
    https://identity.foundation/didwebvh/next/#update-rotate
    """
    pass

@router.delete("/{namespace}/{identifier}")
async def deactivate_did(namespace: str, identifier: str):
    """
    https://identity.foundation/didwebvh/next/#deactivate-revoke
    """
    pass