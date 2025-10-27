"""Admin endpoints."""

import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, HTTPException, Security, status
from fastapi.params import Query
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader


from app.models.web_schemas import AddWitness
from app.tasks import TaskManager, TaskStatus, TaskType
from config import settings
from app.utilities import timestamp, is_valid_multikey
from app.plugins import DidWebVH
from app.plugins.storage import StorageManager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Admin"])
storage = StorageManager()
webvh = DidWebVH()

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


def get_api_key(
    api_key_header: str = Security(api_key_header),
) -> str:
    """Retrieve and validate an API key from the query parameters or HTTP header.

    Args:
        api_key_header: The API key passed in the HTTP header.

    Returns:
        The validated API key.

    Raises:
        HTTPException: If the API key is invalid or missing.
    """
    if api_key_header == settings.API_KEY:
        return api_key_header

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


@router.get("/policy")
async def get_active_policy(api_key: str = Security(get_api_key)):
    """Get active policy."""

    if not (policy := storage.get_policy("active")):
        raise HTTPException(status_code=404, detail="Active policy not found.")

    return JSONResponse(status_code=200, content=policy.to_dict())


@router.get("/policy/known-witnesses")
async def get_known_witnesses(api_key: str = Security(get_api_key)):
    """Get known witnesses registry."""
    if not (registry := storage.get_registry("knownWitnesses")):
        raise HTTPException(status_code=404, detail="Error, witness registry not found.")

    return JSONResponse(status_code=200, content=registry.to_dict())


@router.post("/policy/known-witnesses")
async def add_known_witness(request_body: AddWitness, api_key: str = Security(get_api_key)):
    """Add known witness."""
    request_body = request_body.model_dump()
    multikey = request_body["multikey"]

    if not is_valid_multikey(multikey, alg="ed25519"):
        raise HTTPException(status_code=400, detail="Invalid multikey, must be ed25519 type.")

    witness_did = f"did:key:{multikey}"

    # Get existing registry or create new one
    registry = storage.get_registry("knownWitnesses")

    if registry:
        registry_data = registry.registry_data
        if registry_data.get(witness_did):
            raise HTTPException(status_code=409, detail="Witness already exists.")

        # Add new witness
        registry_data[witness_did] = {"name": request_body["label"]}
        meta = {"updated": timestamp()}
    else:
        # Create new registry with this witness
        registry_data = {witness_did: {"name": request_body["label"]}}
        meta = {"created": timestamp(), "updated": timestamp()}

    # Update registry in database
    updated_registry = storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=registry_data,
        meta=meta,
    )

    return JSONResponse(status_code=200, content=updated_registry.to_dict())


@router.delete("/policy/known-witnesses/{multikey}")
async def remove_known_witness(multikey: str, api_key: str = Security(get_api_key)):
    """Remove known witness."""
    if not is_valid_multikey(multikey, alg="ed25519"):
        raise HTTPException(status_code=400, detail="Invalid multikey, must be ed25519 type.")

    witness_did = f"did:key:{multikey}"

    # Get existing registry
    registry = storage.get_registry("knownWitnesses")

    if not registry:
        raise HTTPException(status_code=404, detail="Witness registry not found.")

    registry_data = registry.registry_data

    if not registry_data.get(witness_did):
        raise HTTPException(status_code=404, detail="Witness not found.")

    # Remove witness
    registry_data.pop(witness_did)
    meta = {"updated": timestamp()}

    # Update registry in database
    updated_registry = storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=registry_data,
        meta=meta,
    )

    return JSONResponse(status_code=200, content=updated_registry.to_dict())


@router.post("/tasks")
async def sync_storage(
    tasks: BackgroundTasks,
    task_type: TaskType = Query(...),
    force: bool = False,
    api_key: str = Security(get_api_key),
):
    """Start an administrative task."""
    task_id = str(uuid.uuid4())
    logger.debug(f"Task type: {task_type}, SetPolicy: {TaskType.SetPolicy}, SyncRecords: {TaskType.SyncRecords}")
    if task_type == TaskType.SetPolicy:
        tasks.add_task(TaskManager(task_id).set_policies, force)
    elif task_type == TaskType.SyncRecords:
        tasks.add_task(TaskManager(task_id).sync_explorer_records, force)
    else:
        raise HTTPException(status_code=400, detail="Unknown task type.")
    return JSONResponse(status_code=201, content={"task_id": task_id})


@router.get("/tasks")
async def fetch_tasks(
    task_type: TaskType = Query(None),
    status: TaskStatus = Query(None),
    api_key: str = Security(get_api_key),
):
    """Check the status of an administrative task."""
    filters = {}
    if task_type:
        filters["task_type"] = task_type.value
    if status:
        filters["status"] = status.value

    tasks = storage.get_tasks(filters if filters else None)
    tasks_data = [task.to_dict() for task in tasks]

    return JSONResponse(status_code=200, content={"tasks": tasks_data})


@router.get("/tasks/{task_id}")
async def check_task_status(task_id: str, api_key: str = Security(get_api_key)):
    """Check the status of an administrative task."""
    if not (task := storage.get_task(task_id)):
        raise HTTPException(status_code=404, detail="Task not found.")
    return JSONResponse(status_code=200, content=task.to_dict())
