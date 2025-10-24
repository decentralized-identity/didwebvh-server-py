"""Main entry point for the server."""

import asyncio
import os
import uuid
import threading
import uvicorn

from dotenv import load_dotenv

from app.plugins.storage import StorageManager
from app.tasks import TaskManager  # set_policies, sync_explorer_records

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))

APP_PORT = int(os.getenv("APP_PORT", "8000"))
APP_WORKERS = int(os.getenv("APP_WORKERS", "4"))


class StartupBackgroundTasks(threading.Thread):
    """Server startup background tasks."""

    def run(self):
        """Run tasks."""

        # Provision SQLAlchemy database
        asyncio.run(StorageManager().provision())

        # Set initial policies
        asyncio.run(TaskManager(str(uuid.uuid4())).set_policies())


if __name__ == "__main__":
    # Run startup tasks synchronously to ensure database is ready before accepting requests
    print("Provisioning database...")
    asyncio.run(StorageManager().provision())

    print("Setting initial policies and witness registry...")
    asyncio.run(TaskManager(str(uuid.uuid4())).set_policies())

    print("Starting server...")
    uvicorn.run("app:app", host="0.0.0.0", port=APP_PORT, workers=APP_WORKERS, reload=False)
