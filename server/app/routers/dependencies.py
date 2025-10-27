"""Shared dependencies for all routers."""

from fastapi import HTTPException
from app.db.models import DidControllerRecord
from app.plugins.storage import StorageManager

storage = StorageManager()


# Dependency to get DID controller from path parameters
async def get_did_controller_dependency(namespace: str, identifier: str) -> DidControllerRecord:
    """Get DID controller from database, raise 404 if not found."""
    did_controller = storage.get_did_controller_by_alias(namespace, identifier)
    if not did_controller:
        raise HTTPException(status_code=404, detail="Not Found")
    return did_controller
