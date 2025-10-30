"""This module contains dependencies used by the FastAPI application."""

from fastapi import HTTPException

from app.plugins import AskarStorage
from app.db.models import DidControllerRecord
from app.plugins.storage import StorageManager

storage = StorageManager()


async def identifier_available(did: str):
    """Check if a DID identifier is available."""
    if await AskarStorage().fetch("didDocument", did):
        raise HTTPException(status_code=409, detail="Identifier unavailable.")


async def did_document_exists(did: str):
    """Check if a DID document exists."""
    if not await AskarStorage().fetch("didDocument", did):
        raise HTTPException(status_code=404, detail="Resource not found.")


async def get_did_controller_dependency(namespace: str, identifier: str) -> DidControllerRecord:
    """Get DID controller from database, raise 404 if not found."""
    did_controller = storage.get_did_controller_by_alias(namespace, identifier)
    if not did_controller:
        raise HTTPException(status_code=404, detail="Not Found")
    return did_controller
