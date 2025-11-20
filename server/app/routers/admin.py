"""Admin endpoints."""

import logging
import uuid

from fastapi import (
    APIRouter,
    BackgroundTasks,
    HTTPException,
    Security,
    status,
)
from fastapi.params import Query
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader


from app.models.web_schemas import AddWitness
from app.tasks import TaskManager, TaskStatus, TaskType
from config import settings
from app.utilities import timestamp, validate_witness_id, process_invitation, create_witness_entry
from app.plugins import DidWebVH
from app.plugins.storage import StorageManager

logger = logging.getLogger(__name__)


router = APIRouter(tags=["Admin"])
storage = StorageManager()
webvh = DidWebVH()

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

# Constants
WITNESS_REGISTRY_ID = "knownWitnesses"
WITNESS_REGISTRY_TYPE = "witnesses"


def get_admin_api_key(
    api_key_header: str = Security(api_key_header),
) -> str:
    """Retrieve and validate an admin API key from the query parameters or HTTP header.

    Args:
        api_key_header: The API key passed in the HTTP header.

    Returns:
        The validated API key.

    Raises:
        HTTPException: If the API key is invalid or missing.
    """
    if api_key_header == settings.WEBVH_ADMIN_API_KEY:
        return api_key_header

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


def _get_or_create_registry():
    """Get existing witness registry or return empty dict and metadata."""
    registry = storage.get_registry(WITNESS_REGISTRY_ID)
    if registry:
        return registry.registry_data, {"updated": timestamp()}
    return {}, {"created": timestamp(), "updated": timestamp()}


def _update_registry(registry_data: dict, meta: dict):
    """Update witness registry in database."""
    return storage.create_or_update_registry(
        registry_id=WITNESS_REGISTRY_ID,
        registry_type=WITNESS_REGISTRY_TYPE,
        registry_data=registry_data,
        meta=meta,
    )


@router.get("/parameters")
async def get_parameters(api_key: str = Security(get_admin_api_key)):
    """Get the parameters generated from the active server policy."""
    policy = storage.get_policy("active")
    if not policy:
        raise HTTPException(status_code=404, detail="Active policy not found.")

    # Load policy and registry into webvh instance
    webvh.active_policy = policy.policy_data or policy.to_dict()
    registry = storage.get_registry(WITNESS_REGISTRY_ID)
    webvh.known_witness_registry = registry.registry_data if registry else {}

    return JSONResponse(status_code=200, content=webvh.parameters())


@router.post("/witnesses")
async def add_known_witness(request_body: AddWitness, api_key: str = Security(get_admin_api_key)):
    """Add or update known witness."""
    body = request_body.model_dump()
    witness_did = body["id"]
    validate_witness_id(witness_did)

    invitation_url = body.get("invitationUrl")
    if not invitation_url:
        raise HTTPException(status_code=400, detail="Invitation URL is required.")

    # Process invitation (validates and extracts data)
    try:
        invitation_payload, invitation_label, short_service_endpoint = process_invitation(
            invitation_url, witness_did, body.get("label")
        )
    except (ValueError, HTTPException) as e:
        # decode_invitation_from_url raises ValueError,
        # validate_invitation_goal raises HTTPException
        if isinstance(e, ValueError):
            raise HTTPException(status_code=400, detail=str(e))
        raise

    # Get or create registry and update witness entry
    registry_data, meta = _get_or_create_registry()
    registry_data[witness_did] = create_witness_entry(
        invitation_label, short_service_endpoint, invitation_url
    )

    # Update registry and store invitation
    updated_registry = _update_registry(registry_data, meta)
    storage.create_or_update_witness_invitation(
        witness_did=witness_did,
        invitation_url=invitation_url,
        invitation_payload=invitation_payload,
        invitation_id=invitation_payload.get("@id"),
        label=invitation_label,
    )

    return JSONResponse(status_code=200, content=updated_registry.to_dict())


@router.delete("/witnesses/{multikey}")
async def remove_known_witness(multikey: str, api_key: str = Security(get_admin_api_key)):
    """Remove known witness."""
    witness_id = f"did:key:{multikey}"
    validate_witness_id(witness_id)

    # Get existing registry
    registry = storage.get_registry(WITNESS_REGISTRY_ID)
    if not registry:
        raise HTTPException(status_code=404, detail="Witness registry not found.")

    registry_data = registry.registry_data
    if witness_id not in registry_data:
        raise HTTPException(status_code=404, detail="Witness not found.")

    # Remove witness and update registry
    registry_data.pop(witness_id)
    updated_registry = _update_registry(registry_data, {"updated": timestamp()})
    storage.delete_witness_invitation(witness_id)

    return JSONResponse(status_code=200, content=updated_registry.to_dict())


@router.post("/tasks")
async def sync_storage(
    tasks: BackgroundTasks,
    task_type: TaskType = Query(...),
    force: bool = False,
    api_key: str = Security(get_admin_api_key),
):
    """Start an administrative task."""
    task_id = str(uuid.uuid4())
    task_manager = TaskManager(task_id)

    if task_type == TaskType.SetPolicy:
        tasks.add_task(task_manager.set_policies, force)
    elif task_type == TaskType.RegisterWitness:
        tasks.add_task(task_manager.register_initial_witness)
    elif task_type == TaskType.SyncRecords:
        # SyncRecords task not yet implemented
        raise HTTPException(status_code=400, detail="SyncRecords task not implemented.")
    else:
        raise HTTPException(status_code=400, detail="Unknown task type.")

    return JSONResponse(status_code=201, content={"task_id": task_id})


@router.get("/tasks")
async def fetch_tasks(
    task_type: TaskType = Query(None),
    status: TaskStatus = Query(None),
    api_key: str = Security(get_admin_api_key),
):
    """List administrative tasks with optional filtering."""
    filters = {k: v.value for k, v in {"task_type": task_type, "status": status}.items() if v}
    tasks_list = storage.get_tasks(filters if filters else None)
    return JSONResponse(status_code=200, content={"tasks": [task.to_dict() for task in tasks_list]})


@router.get("/tasks/{task_id}")
async def check_task_status(task_id: str, api_key: str = Security(get_admin_api_key)):
    """Check the status of an administrative task."""
    if not (task := storage.get_task(task_id)):
        raise HTTPException(status_code=404, detail="Task not found.")
    return JSONResponse(status_code=200, content=task.to_dict())
