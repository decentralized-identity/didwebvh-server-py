"""This module contains dependencies used by the FastAPI application."""

from fastapi import HTTPException

from app.plugins import AskarStorage


async def identifier_available(did: str):
    """Check if a DID identifier is available."""
    if await AskarStorage().fetch("didDocument", did):
        raise HTTPException(status_code=409, detail="Identifier unavailable.")


async def did_document_exists(did: str):
    """Check if a DID document exists."""
    if not await AskarStorage().fetch("didDocument", did):
        raise HTTPException(status_code=404, detail="Resource not found.")
