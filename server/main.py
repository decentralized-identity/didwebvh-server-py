"""Main entry point for the server."""

import asyncio
import os
import uuid
import threading
import uvicorn

from dotenv import load_dotenv

from app.plugins import AskarStorage
from app.tasks import sync_explorer_records

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))

APP_PORT = int(os.getenv("APP_PORT", "8000"))
APP_WORKERS = int(os.getenv("APP_WORKERS", "4"))


class StartupBackgroundTasks(threading.Thread):
    """Server startup background tasks."""

    def run(self):
        """Run tasks."""
        asyncio.run(AskarStorage().provision())

        task_id = str(uuid.uuid4())
        asyncio.run(sync_explorer_records(task_id))


if __name__ == "__main__":
    StartupBackgroundTasks().start()
    uvicorn.run("app:app", host="0.0.0.0", port=APP_PORT, workers=APP_WORKERS, reload=True)
