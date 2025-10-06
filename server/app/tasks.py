"""Background Tasks."""

import logging

from enum import Enum

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

    SyncRecords = "sync_records"


async def sync_explorer_records(task_id, force=False):
    """Sync explorer records."""
    logger.info(f"Starting sync task ID: {task_id}")
    task = {
        "id": task_id,
        "type": TaskType.SyncRecords,
        "created": timestamp(),
        "updated": timestamp(),
        "status": "started",
        "progress": {
            "didRecords": "none",
            "resourceRecords": "none",
        },
    }
    await askar.store("task", task_id, task)
    try:
        for idx, entry in enumerate((entries := await askar.get_category_entries("resource"))):
            task["progress"]["resourceRecords"] = f"{idx + 1}/{len(entries)}"
            task["updated"] = timestamp()
            await askar.update("task", task_id, task)
            if not force and await askar.fetch("resourceRecord", entry.name):
                continue

            resource_record, tags = sync_resource(entry.value_json)
            await askar.update("resource", entry.name, entry.value_json, tags=tags)
            await askar.store_or_update("resourceRecord", entry.name, resource_record, tags=tags)

        for idx, entry in enumerate((entries := await askar.get_category_entries("logEntries"))):
            task["progress"]["didRecords"] = f"{idx + 1}/{len(entries)}"
            task["updated"] = timestamp()
            await askar.update("task", task_id, task)
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

        task["status"] = "finished"
        task["updated"] = timestamp()
        await askar.update("task", task_id, task)
        logger.info(f"Task {task_id} finished.")

    except Exception as e:
        logger.warning(f"Task {task_id} abandonned.")
        logger.warning(str(e))
        task["status"] = "abandonned"
        task["message"] = str(e)
        task["updated"] = timestamp()
        await askar.update("task", task_id, task)
