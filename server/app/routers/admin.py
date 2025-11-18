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
from app.plugins.invitations import (
    build_short_invitation_url,
    decode_invitation_from_url as parse_invitation_url,
)
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
    if api_key_header == settings.WEBVH_ADMIN_API_KEY:
        return api_key_header

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


def decode_invitation_from_url(invitation_url: str):
    """Compatibility wrapper around shared invitation decoder."""
    return parse_invitation_url(invitation_url)


@router.get("/parameters")
async def get_parameters(api_key: str = Security(get_api_key)):
    """Get the parameters generated from the active server policy."""
    policy = storage.get_policy("active")
    if not policy:
        raise HTTPException(status_code=404, detail="Active policy not found.")

    # Load policy data into webvh instance
    policy_data = policy.policy_data if policy.policy_data else policy.to_dict()
    webvh.active_policy = policy_data

    # Load witness registry
    registry = storage.get_registry("knownWitnesses")
    if registry:
        webvh.load_known_witness_registry(registry.registry_data)
    else:
        webvh.known_witness_registry = {}

    # Generate and return parameters
    parameters = webvh.parameters()
    return JSONResponse(status_code=200, content=parameters)


def _validate_witness_id(witness_did: str) -> str:
    """Validate witness DID and return multikey."""
    if not witness_did.startswith("did:key:"):
        raise HTTPException(status_code=400, detail="Witness id must be a did:key identifier.")
    multikey = witness_did.split("did:key:")[-1]
    if not is_valid_multikey(multikey, alg="ed25519"):
        raise HTTPException(status_code=400, detail="Invalid witness id, must be ed25519 multikey.")
    return multikey


def _validate_invitation_goal(invitation_payload: dict, witness_did: str) -> None:
    """Validate that invitation goal_code and goal match witness requirements."""
    goal_code = invitation_payload.get("goal_code")
    goal = invitation_payload.get("goal")
    
    if goal_code != "witness-service":
        raise HTTPException(
            status_code=400,
            detail=f"Invalid invitation goal_code. Expected 'witness-service', got '{goal_code}'"
        )
    
    if goal != witness_did:
        raise HTTPException(
            status_code=400,
            detail=f"Invitation goal does not match witness ID. Expected '{witness_did}', got '{goal}'"
        )


def _process_invitation(
    invitation_url: str, witness_did: str, provided_label: str | None
) -> tuple[dict, str, str]:
    """Process invitation URL and return payload, label, and short endpoint.
    
    Label priority: provided_label > invitation label > fallback
    """
    invitation_payload = decode_invitation_from_url(invitation_url)
    _validate_invitation_goal(invitation_payload, witness_did)
    
    # Use provided label if available, otherwise use invitation label, otherwise fallback
    invitation_label = (
        provided_label 
        or invitation_payload.get("label") 
        or "Witness Service"
    )
    
    short_service_endpoint = build_short_invitation_url(witness_did, invitation_payload)
    return invitation_payload, invitation_label, short_service_endpoint


def _create_witness_entry(
    invitation_label: str, short_service_endpoint: str | None, invitation_url: str
) -> dict:
    """Create witness registry entry."""
    entry = {"name": invitation_label}
    if short_service_endpoint:
        entry["serviceEndpoint"] = short_service_endpoint
    elif invitation_url:
        entry["serviceEndpoint"] = invitation_url
    return entry


@router.post("/witnesses")
async def add_known_witness(request_body: AddWitness, api_key: str = Security(get_api_key)):
    """Add known witness."""
    request_body = request_body.model_dump()
    witness_did = request_body["id"]
    _validate_witness_id(witness_did)

    invitation_url = request_body.get("invitationUrl")
    if not invitation_url:
        raise HTTPException(status_code=400, detail="Invitation URL is required.")

    invitation_payload, invitation_label, short_service_endpoint = _process_invitation(
        invitation_url, witness_did, request_body["label"]
    )

    # Get existing registry or create new one
    registry = storage.get_registry("knownWitnesses")
    if registry:
        registry_data = registry.registry_data
        meta = {"updated": timestamp()}
    else:
        registry_data = {}
        meta = {"created": timestamp(), "updated": timestamp()}

    # Update or add witness entry (update if exists, as per user requirement)
    entry = _create_witness_entry(invitation_label, short_service_endpoint, invitation_url)
    registry_data[witness_did] = entry

    # Update registry in database
    updated_registry = storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=registry_data,
        meta=meta,
    )

    if invitation_payload:
        storage.create_or_update_witness_invitation(
            witness_did=witness_did,
            invitation_url=invitation_url,
            invitation_payload=invitation_payload,
            invitation_id=invitation_payload.get("@id"),
            label=invitation_label,
        )

    return JSONResponse(status_code=200, content=updated_registry.to_dict())


@router.delete("/witnesses/{multikey}")
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

    storage.delete_witness_invitation(witness_did)

    return JSONResponse(status_code=200, content=updated_registry.to_dict())


@router.post("/tasks", include_in_schema=False)
async def sync_storage(
    tasks: BackgroundTasks,
    task_type: TaskType = Query(...),
    force: bool = False,
    api_key: str = Security(get_api_key),
):
    """Start an administrative task."""
    task_id = str(uuid.uuid4())
    logger.debug(
        f"Task type: {task_type}, SetPolicy: {TaskType.SetPolicy}, "
        f"SyncRecords: {TaskType.SyncRecords}"
    )
    if task_type == TaskType.SetPolicy:
        tasks.add_task(TaskManager(task_id).set_policies, force)
    elif task_type == TaskType.SyncRecords:
        tasks.add_task(TaskManager(task_id).sync_explorer_records, force)
    else:
        raise HTTPException(status_code=400, detail="Unknown task type.")
    return JSONResponse(status_code=201, content={"task_id": task_id})


@router.get("/tasks", include_in_schema=False)
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


@router.get("/tasks/{task_id}", include_in_schema=False)
async def check_task_status(task_id: str, api_key: str = Security(get_api_key)):
    """Check the status of an administrative task."""
    if not (task := storage.get_task(task_id)):
        raise HTTPException(status_code=404, detail="Task not found.")
    return JSONResponse(status_code=200, content=task.to_dict())
