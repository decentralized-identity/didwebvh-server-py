"""Invitation endpoints for witness service lookup."""

import logging
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse
from app.plugins.storage import StorageManager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Invitations"])
storage = StorageManager()


@router.get("")
async def get_invitation_by_oobid(_oobid: str = Query(..., description="Witness key (multikey) for invitation lookup")):
    """Retrieve a witness invitation by _oobid (witness key).
    
    The _oobid parameter is the multikey portion of the witness DID (did:key:...).
    This endpoint looks up the stored invitation for the witness and returns it as JSON.
    """
    # Find witness by multikey (the _oobid is the witness key)
    registry = storage.get_registry("knownWitnesses")
    if registry:
        for witness_id, entry in registry.registry_data.items():
            witness_key = witness_id.split(":")[-1]
            if witness_key == _oobid:
                invitation = storage.get_witness_invitation(witness_id)
                if invitation and invitation.invitation_payload:
                    return JSONResponse(status_code=200, content=invitation.invitation_payload)
    
    raise HTTPException(status_code=404, detail="Invitation not found")

