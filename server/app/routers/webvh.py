from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from config import settings
from app.models.did_log import LogParameters
from app.plugins import DidWebVH

router = APIRouter(tags=["WebVH"])

@router.post("")
async def create_did():
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

@router.get("")
async def read_did():
    """
    https://identity.foundation/didwebvh/next/#read-resolve
    """
    pass

@router.put("")
async def update_did():
    """
    https://identity.foundation/didwebvh/next/#update-rotate
    """
    pass

@router.delete("")
async def deactivate_did():
    """
    https://identity.foundation/didwebvh/next/#deactivate-revoke
    """
    pass