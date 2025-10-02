"""Tails endpoints for AnonCreds revocation."""

import hashlib
import logging
import base58
import re


from fastapi import APIRouter, HTTPException, Response, Request
from fastapi.responses import StreamingResponse

from app.plugins import AskarStorage

from app.utilities import multipart_reader

router = APIRouter()
askar = AskarStorage()
logger = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024  # 64 KB per chunk
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB max


@router.get("/hash/{tails_hash}")
async def get_file_by_hash(tails_hash: str):
    """Get tails file."""
    if not (tails_file := await askar.fetch("tailsFile", tails_hash)):
        raise HTTPException(status_code=404, detail="Not Found")

    view = memoryview(bytes.fromhex(tails_file))

    async def byte_stream():
        for i in range(0, len(view), CHUNK_SIZE):
            yield bytes(view[i : i + CHUNK_SIZE])

    return StreamingResponse(byte_stream(), media_type="application/octet-stream")


@router.put("/hash/{tails_hash}")
async def put_file_by_hash(request: Request, tails_hash: str):
    """Upload tails file and store it by hash."""
    content_type = request.headers.get("Content-Type", "")

    if "multipart/form-data" not in content_type:
        logger.warning("Expecting multipart/form-data content-type.")
        raise HTTPException(status_code=400, detail="Expecting multipart/form-data content-type.")

    if not (boundary := re.search(r"boundary=(.+)", content_type).group(1).encode()):
        raise HTTPException(status_code=400, detail="Invalid multipart boundary")

    if not (file_content := multipart_reader(await request.body(), boundary)):
        raise HTTPException(status_code=400, detail="No file content found")

    if file_content[:2] != b"\x00\x02":
        logger.warning('Tails file must start with "00 02".')
        raise HTTPException(status_code=400, detail='Tails file must start with "00 02".')

    if len(file_content) > MAX_FILE_SIZE:
        logger.warning("Tails file too large.")
        raise HTTPException(status_code=400, detail="Tails file too large.")

    if (len(file_content) - 2) % 128 != 0:
        logger.warning("Tails file is not the correct size.")
        raise HTTPException(status_code=400, detail="Tails file is not the correct size.")

    if tails_hash != base58.b58encode(hashlib.sha256(file_content).digest()).decode("utf-8"):
        logger.warning("tailsHash does not match hash of file.")
        raise HTTPException(status_code=400, detail="tailsHash does not match hash of file.")

    await askar.store("tailsFile", tails_hash, file_content.hex())

    return Response(content=tails_hash, media_type="text/plain", status_code=201)
