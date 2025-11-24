"""Background Tasks."""

import logging
import json

from enum import Enum

from config import settings

from app.models.task import TaskInstance
from app.plugins import DidWebVH
from app.plugins.invitations import (
    build_short_invitation_url,
    decode_invitation_from_url,
)
from app.plugins.storage import StorageManager
from app.utilities import timestamp

logger = logging.getLogger(__name__)

storage = StorageManager()
webvh = DidWebVH()


class TaskType(str, Enum):
    """Types of tasks."""

    SetPolicy = "set_policy"
    RegisterWitness = "register_witness"
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
        """Apply policy from environment variables."""

        await self.start_task(TaskType.SetPolicy)

        try:
            # Always update policy from environment variables
            logger.info("Applying policy from environment variables...")
            policy_data = {
                "version": settings.WEBVH_VERSION,
                "witness": settings.WEBVH_WITNESS,
                "watcher": settings.WEBVH_WATCHER,
                "portability": settings.WEBVH_PORTABILITY,
                "prerotation": settings.WEBVH_PREROTATION,
                "endorsement": settings.WEBVH_ENDORSEMENT,
                "witness_registry_url": None,
            }
            policy = storage.create_or_update_policy("active", policy_data)
            logger.info(f"Policy {policy_data['version']} applied successfully")

            await self.update_task_progress({"policy": f"Policy {policy.version} active"})

            # Check/create witness registry in database
            if not (registry := storage.get_registry("knownWitnesses")):
                logger.info("Creating empty known witness registry.")
                meta = {"created": timestamp(), "updated": timestamp()}
                registry = storage.create_or_update_registry(
                    registry_id="knownWitnesses",
                    registry_type="witnesses",
                    registry_data={},
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

    async def register_initial_witness(self):
        """Register initial witness from environment variables."""
        await self.start_task(TaskType.RegisterWitness)

        try:
            if not settings.WEBVH_WITNESS_ID or not settings.WEBVH_WITNESS_INVITATION:
                logger.info("No initial witness configured, skipping registration.")
                await self.finish_task()
                return

            logger.info("Registering initial witness from environment variables...")

            # Decode invitation to get label
            invitation_payload = decode_invitation_from_url(settings.WEBVH_WITNESS_INVITATION)

            # Validate invitation goal_code and goal
            goal_code = invitation_payload.get("goal_code")
            goal = invitation_payload.get("goal")

            if goal_code != "witness-service":
                raise ValueError(
                    f"Invalid invitation goal_code. Expected 'witness-service', got '{goal_code}'"
                )

            if goal != settings.WEBVH_WITNESS_ID:
                raise ValueError(
                    f"Invitation goal does not match witness ID. "
                    f"Expected '{settings.WEBVH_WITNESS_ID}', got '{goal}'"
                )

            invitation_label = invitation_payload.get("label") or "Default Server Witness"

            await self.update_task_progress({"step": "Validated invitation"})

            # Build short service endpoint
            short_service_endpoint = build_short_invitation_url(
                settings.WEBVH_WITNESS_ID, invitation_payload
            )

            await self.update_task_progress({"step": "Built service endpoint"})

            # Get or create registry
            registry = storage.get_registry("knownWitnesses")
            if registry:
                registry_data = registry.registry_data
                meta = {"updated": timestamp()}
            else:
                registry_data = {}
                meta = {"created": timestamp(), "updated": timestamp()}

            # Update or add witness entry
            registry_data[settings.WEBVH_WITNESS_ID] = {
                "name": invitation_label,
                "serviceEndpoint": short_service_endpoint,
            }

            # Update registry in database
            storage.create_or_update_registry(
                registry_id="knownWitnesses",
                registry_type="witnesses",
                registry_data=registry_data,
                meta=meta,
            )

            await self.update_task_progress({"step": "Updated witness registry"})

            # Store invitation
            storage.create_or_update_witness_invitation(
                witness_did=settings.WEBVH_WITNESS_ID,
                invitation_url=settings.WEBVH_WITNESS_INVITATION,
                invitation_payload=invitation_payload,
                invitation_id=invitation_payload.get("@id"),
                label=invitation_label,
            )

            await self.update_task_progress(
                {"witness": f"Witness {settings.WEBVH_WITNESS_ID} registered successfully"}
            )

            logger.info(f"Initial witness {settings.WEBVH_WITNESS_ID} registered successfully")
            await self.finish_task()

        except Exception as e:
            logger.warning(f"Failed to register initial witness: {e}")
            await self.abandon_task(str(e))
