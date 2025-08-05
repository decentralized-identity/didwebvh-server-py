"""Main entry point for the server."""

import asyncio
import os
import uvicorn

from app.plugins import AskarStorage

if __name__ == "__main__":
    asyncio.run(AskarStorage().provision())
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=os.getenv("APP_PORT", 8000),
        workers=os.getenv("APP_WORKERS", 4),
    )
