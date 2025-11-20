"""Common FastAPI dependencies."""

from fastapi import HTTPException

from app.db.models import DidControllerRecord
from app.plugins.storage import StorageManager

storage = StorageManager()


async def get_did_controller_dependency(namespace: str, alias: str) -> DidControllerRecord:
    """Get DID controller from database, raise 404 if not found."""
    did_controller = storage.get_did_controller_by_alias(namespace, alias)
    if not did_controller:
        raise HTTPException(status_code=404, detail="Not Found")
    return did_controller
