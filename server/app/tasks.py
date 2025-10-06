"""Background Tasks."""

import logging
import json

from enum import Enum

from config import settings

from app.models.policy import ActivePolicy
from app.models.task import TaskInstance
from app.plugins import AskarStorage, DidWebVH
from app.utilities import (
    timestamp,
    sync_resource,
    sync_did_info,
)

logger = logging.getLogger(__name__)

askar = AskarStorage()
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
        await askar.store("task", self.task_id, self.task.model_dump(), self.task_tags())

    async def update_task_progress(self, progress):
        """Update task progress."""
        logger.debug(f"Task {self.task_id} updated: {json.dumps(progress)}")
        self.task.progress.update(progress)
        self.task.updated = timestamp()
        await askar.update("task", self.task_id, self.task.model_dump(), self.task_tags())

    async def finish_task(self):
        """Finish existing task."""
        logger.info(f"Task {self.task_id} finished.")
        self.task.status = TaskStatus.finished
        self.task.updated = timestamp()
        await askar.update("task", self.task_id, self.task.model_dump(), self.task_tags())

    async def abandon_task(self, message=None):
        """Abandon existing task."""
        logger.error(f"Task {self.task_id} abandonned: {message}")
        self.task.status = TaskStatus.abandonned
        self.task.message = message
        self.task.updated = timestamp()
        await askar.update("task", self.task_id, self.task.model_dump(), self.task_tags())

    async def set_policies(self, force=False):
        """Provision DB with policies."""

        await self.start_task(TaskType.SetPolicy)

        try:
            if not (policy := await askar.fetch("policy", "active")):
                logger.info("Creating server policies.")
                policy = ActivePolicy(
                    version=settings.WEBVH_VERSION,
                    witness=settings.WEBVH_WITNESS,
                    watcher=settings.WEBVH_WATCHER,
                    portability=settings.WEBVH_PORTABILITY,
                    prerotation=settings.WEBVH_PREROTATION,
                    endorsement=settings.WEBVH_ENDORSEMENT,
                    witness_registry_url=settings.KNOWN_WITNESS_REGISTRY,
                ).model_dump()
                await askar.store("policy", "active", policy)
            else:
                logger.info("Skipping server policies.")

            await self.update_task_progress({"policy": json.dumps(policy)})

            if not (witness_registry := await askar.fetch("registry", "knownWitnesses")):
                logger.info("Creating known witness registry.")
                witness_registry = {
                    "meta": {"created": timestamp(), "updated": timestamp()},
                    "registry": {},
                }
                if settings.KNOWN_WITNESS_KEY:
                    witness_did = f"did:key:{settings.KNOWN_WITNESS_KEY}"
                    witness_registry["registry"][witness_did] = {"name": "Default Server Witness"}
                await askar.store("registry", "knownWitnesses", witness_registry)
            else:
                logger.info("Skipping known witness registry.")

            await self.update_task_progress({"knownWitnessRegistry": json.dumps(witness_registry)})

            await self.finish_task()

        except Exception as e:
            await self.abandon_task(str(e))

    async def sync_explorer_records(self, force=False):
        """Sync explorer records."""

        await self.start_task(TaskType.SyncRecords)

        try:
            entries = await askar.get_category_entries("resource")
            for idx, entry in enumerate(entries):
                await self.update_task_progress({"resourceRecords": f"{idx + 1}/{len(entries)}"})

                if not force and await askar.fetch("resourceRecord", entry.name):
                    continue

                resource_record, tags = sync_resource(entry.value_json)
                await askar.update("resource", entry.name, entry.value_json, tags)
                await askar.store_or_update("resourceRecord", entry.name, resource_record, tags)

            entries = await askar.get_category_entries("logEntries")
            for idx, entry in enumerate(entries):
                await self.update_task_progress({"didRecords": f"{idx + 1}/{len(entries)}"})

                if not force and await askar.fetch("didRecord", entry.name):
                    continue

                logs = entry.value_json
                state = webvh.get_document_state(logs)
                did_record, tags = sync_did_info(
                    state=state,
                    logs=logs,
                    did_resources=[
                        resource.value_json
                        for resource in await askar.get_category_entries(
                            "resource", {"scid": state.scid}
                        )
                    ],
                    witness_file=(await askar.fetch("witnessFile", entry.name) or []),
                    whois_presentation=(await askar.fetch("whois", entry.name) or {}),
                )
                await askar.update("logEntries", entry.name, entry.value_json, tags=tags)
                await askar.store_or_update("didRecord", entry.name, did_record, tags=tags)

            await self.finish_task()

        except Exception as e:
            await self.abandon_task(str(e))
