"""Tails endpoints for AnonCreds revocation."""

import hashlib
import logging
import base58
import re


from fastapi import APIRouter, HTTPException, Response, Request, Depends
from fastapi.responses import StreamingResponse

from app.utilities import multipart_reader
from app.plugins.storage import StorageManager

router = APIRouter()
storage = StorageManager()
logger = logging.getLogger(__name__)

RESPONSE_CHUNK_SIZE = 64 * 1024  # 64 KB
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


async def safe_request_body(request: Request) -> bytes:
    """Dependency for limiting upload size."""
    total_size = 0
    body_chunks = []

    async for chunk in request.stream():
        total_size += len(chunk)
        if total_size > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=413, detail="Request Entity Too Large")

        body_chunks.append(chunk)

    return b"".join(body_chunks)


@router.get("/hash/{tails_hash}")
async def get_tails_file(tails_hash: str):
    """Get tails file."""

    # Fetch file from database
    tails_file = storage.get_tails_file(tails_hash)
    if not tails_file:
        raise HTTPException(status_code=404, detail="Not Found")

    # Load memoryview from hex content
    view = memoryview(bytes.fromhex(tails_file.file_content_hex))

    # Stream bytes in response
    async def byte_stream():
        for i in range(0, len(view), RESPONSE_CHUNK_SIZE):
            yield bytes(view[i : i + RESPONSE_CHUNK_SIZE])

    return StreamingResponse(byte_stream(), media_type="application/octet-stream")


@router.put("/hash/{tails_hash}")
async def upload_tails_file(
    request: Request,
    tails_hash: str,
    request_body: bytes = Depends(safe_request_body),
):
    """Upload tails file and store it by hash."""

    content_type = request.headers.get("Content-Type", "")

    # Validate content type
    if "multipart/form-data" not in content_type:
        logger.warning("Expecting multipart/form-data content-type.")
        raise HTTPException(status_code=400, detail="Expecting multipart/form-data content-type.")

    # Find multipart boundary (strip whitespace, quotes, semicolon so split matches body)
    match = re.search(r"boundary=(.+)", content_type)
    if not match:
        logger.warning("Invalid multipart boundary.")
        raise HTTPException(status_code=400, detail="Invalid multipart boundary.")
    boundary = match.group(1).strip().strip('"').strip("'").rstrip(";").encode()

    # Process request body to get tails file
    if not (file_content := multipart_reader(request_body, boundary)):
        logger.warning("No file content found.")
        raise HTTPException(status_code=400, detail="No file content found.")

    # Validate starting bytes
    if file_content[:2] != b"\x00\x02":
        logger.warning('Tails file must start with "00 02".')
        raise HTTPException(status_code=400, detail='Tails file must start with "00 02".')

    # Validate file size
    if (len(file_content) - 2) % 128 != 0:
        logger.warning("Tails file is not the correct size.")
        raise HTTPException(status_code=400, detail="Tails file is not the correct size.")

    # Validate file hash
    if tails_hash != base58.b58encode(hashlib.sha256(file_content).digest()).decode("utf-8"):
        logger.warning("tailsHash does not match hash of file.")
        raise HTTPException(status_code=400, detail="tailsHash does not match hash of file.")

    # Store file in database
    storage.create_tails_file(
        tails_hash=tails_hash, file_content_hex=file_content.hex(), file_size=len(file_content)
    )

    return Response(content=tails_hash, media_type="text/plain", status_code=201)
