"""Main entry point for the server."""

import asyncio
import os
import uvicorn

from dotenv import load_dotenv

from app.plugins import AskarStorage

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))

APP_PORT = int(os.getenv("APP_PORT", "8000"))
APP_WORKERS = int(os.getenv("APP_WORKERS", "4"))

if __name__ == "__main__":
    asyncio.run(AskarStorage().provision())
    uvicorn.run("app:app", host="0.0.0.0", port=APP_PORT, workers=APP_WORKERS, reload=True)
