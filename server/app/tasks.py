"""Background Tasks."""

import logging
import json

from enum import Enum

from config import settings

from app.models.task import TaskInstance
from app.plugins import AskarStorage, DidWebVH
from app.plugins.storage import StorageManager
from app.utilities import timestamp

logger = logging.getLogger(__name__)

askar = AskarStorage()
storage = StorageManager()
webvh = DidWebVH()


class TaskType(str, Enum):
    """Types of tasks."""

    SetPolicy = "set_policy"
    SyncRecords = "sync_records"


class TaskStatus(str, Enum):
    """Statuses of tasks."""

    started = "started"
    finished = "finished"
    abandonned = "abandonned"


class TaskManager:
    """TaskManager."""

    def __init__(self, task_id: str = None):
        """Initialize TaskManager."""
        self.task_id = task_id
        self.task = None

    def task_tags(self):
        """Return current task tags."""
        return {"status": self.task.status, "task_type": self.task.type}

    async def start_task(self, task_type):
        """Start new task."""
        logger.info(f"Task {task_type} started: {self.task_id}")
        self.task = TaskInstance(
            id=self.task_id,
            type=task_type,
            created=timestamp(),
            updated=timestamp(),
            status=TaskStatus.started,
            progress={},
        )
        # Store task in database
        storage.create_task(
            task_id=self.task_id,
            task_type=task_type.value,
            status=TaskStatus.started.value,
            progress={},
            message=None,
        )

    async def update_task_progress(self, progress):
        """Update task progress."""
        logger.debug(f"Task {self.task_id} updated: {json.dumps(progress)}")
        self.task.progress.update(progress)
        self.task.updated = timestamp()
        # Update task in database
        storage.update_task(self.task_id, progress=self.task.progress)

    async def finish_task(self):
        """Finish existing task."""
        logger.info(f"Task {self.task_id} finished.")
        self.task.status = TaskStatus.finished
        self.task.updated = timestamp()
        # Update task in database
        storage.update_task(self.task_id, status=TaskStatus.finished.value)

    async def abandon_task(self, message=None):
        """Abandon existing task."""
        logger.error(f"Task {self.task_id} abandonned: {message}")
        self.task.status = TaskStatus.abandonned
        self.task.message = message
        self.task.updated = timestamp()
        # Update task in database
        storage.update_task(self.task_id, status=TaskStatus.abandonned.value, message=message)

    async def set_policies(self, force=False):
        """Provision DB with policies."""

        await self.start_task(TaskType.SetPolicy)

        try:
            # Check/create policy in database
            if not (policy := storage.get_policy("active")):
                logger.info("Creating server policies.")
                policy_data = {
                    "version": settings.WEBVH_VERSION,
                    "witness": settings.WEBVH_WITNESS,
                    "watcher": settings.WEBVH_WATCHER,
                    "portability": settings.WEBVH_PORTABILITY,
                    "prerotation": settings.WEBVH_PREROTATION,
                    "endorsement": settings.WEBVH_ENDORSEMENT,
                    "witness_registry_url": settings.KNOWN_WITNESS_REGISTRY,
                }
                policy = storage.create_or_update_policy("active", policy_data)
            else:
                logger.info("Skipping server policies.")

            await self.update_task_progress({"policy": f"Policy {policy.version} active"})

            # Check/create witness registry in database
            if not (registry := storage.get_registry("knownWitnesses")):
                logger.info("Creating known witness registry.")
                registry_data = {}
                if settings.KNOWN_WITNESS_KEY:
                    witness_did = f"did:key:{settings.KNOWN_WITNESS_KEY}"
                    registry_data[witness_did] = {"name": "Default Server Witness"}

                meta = {"created": timestamp(), "updated": timestamp()}
                registry = storage.create_or_update_registry(
                    registry_id="knownWitnesses",
                    registry_type="witnesses",
                    registry_data=registry_data,
                    meta=meta,
                )
            else:
                logger.info("Skipping known witness registry.")

            await self.update_task_progress(
                {"knownWitnessRegistry": f"{len(registry.registry_data)} witnesses registered"}
            )

            await self.finish_task()

        except Exception as e:
            await self.abandon_task(str(e))
