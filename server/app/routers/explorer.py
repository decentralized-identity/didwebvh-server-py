"""Explorer routes for DIDs and resources UI."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.plugins.storage import StorageManager
from app.utilities import create_pagination
from app.models.explorer import (
    ExplorerDidRecord,
    ExplorerResourceRecord,
    ExplorerCredentialRecord,
    ExplorerWitnessRecord,
    ExplorerWitnessRegistryMeta,
)

from config import templates, settings

router = APIRouter(tags=["Explorer"])
storage = StorageManager()


@router.get("/")
async def explorer_index(request: Request):
    """Landing page for the explorer UI."""
    CONTEXT = {"branding": settings.BRANDING}
    return templates.TemplateResponse(request=request, name="pages/index.jinja", context=CONTEXT)


@router.get("/dids")
async def explorer_did_table(  # noqa: C901
    request: Request,
    namespace: str = None,
    status: str = None,
    identifier: str = None,
    scid: str = None,
    domain: str = None,
    has_resources: str = None,
    page: int = 1,
    limit: int = 50,
):
    """DID table."""
    # Build filters for StorageManager query

    filters = {
        "scid": scid,
        "namespace": namespace,
        "alias": identifier,  # Note: identifier maps to alias column
        "domain": domain,
        "deactivated": False if status == "active" else (True if status == "deactivated" else None),
    }
    # Remove None values
    filters = {k: v for k, v in filters.items() if v is not None}

    # Calculate offset
    offset = (page - 1) * limit

    # Get total count for pagination
    total = storage.count_did_controllers(filters)
    total_pages = (total + limit - 1) // limit  # Ceiling division

    # Get paginated results from DidControllerRecord
    did_controllers = storage.get_did_controllers(filters, limit=limit, offset=offset)

    # Format results for explorer UI using factory method
    results = [ExplorerDidRecord.from_controller(controller) for controller in did_controllers]

    CONTEXT = {
        "results": [r.model_dump() for r in results],
        "pagination": create_pagination(page, limit, total, total_pages),
    }

    if request.headers.get("Accept") == "application/json":
        return JSONResponse(status_code=200, content=CONTEXT)

    CONTEXT["branding"] = settings.BRANDING
    return templates.TemplateResponse(request=request, name="pages/dids.jinja", context=CONTEXT)


@router.get("/resources")
async def explorer_resource_table(
    request: Request,
    scid: str = None,
    resource_id: str = None,
    resource_type: str = None,
    page: int = 1,
    limit: int = 50,
):
    """Resource table with pagination."""
    # Build filters for StorageManager query
    filters = {
        "scid": scid,
        "resource_id": resource_id,
        "resource_type": resource_type,
    }
    # Remove None values
    filters = {k: v for k, v in filters.items() if v is not None}

    # Calculate offset
    offset = (page - 1) * limit

    # Get total count for pagination
    total = storage.count_resources(filters)
    total_pages = (total + limit - 1) // limit  # Ceiling division

    # Get paginated results from AttestedResourceRecord
    resource_records = storage.get_resources(filters, limit=limit, offset=offset)

    # Format results for explorer UI using factory method
    formatted_results = [
        ExplorerResourceRecord.from_resource_record(resource).model_dump()
        for resource in resource_records
    ]

    CONTEXT = {
        "results": formatted_results,
        "pagination": create_pagination(page, limit, total, total_pages),
    }

    if request.headers.get("Accept") == "application/json":
        return JSONResponse(status_code=200, content=CONTEXT)

    CONTEXT["branding"] = settings.BRANDING
    return templates.TemplateResponse(
        request=request, name="pages/resources.jinja", context=CONTEXT
    )


@router.get("/credentials")
async def explorer_credential_table(
    request: Request,
    credential_id: str = None,
    scid: str = None,
    issuer_did: str = None,
    subject_id: str = None,
    credential_type: str = None,
    namespace: str = None,
    alias: str = None,
    revoked: str = None,
    page: int = 1,
    limit: int = 50,
):
    """Credential table with pagination."""
    # Build filters for StorageManager query

    # Helper: resolve namespace/alias to scid
    def resolve_scid():
        if namespace and alias:
            controller = storage.get_did_controller_by_alias(namespace, alias)
            return controller.scid if controller else "NOTFOUND"
        return scid

    # Helper: parse revoked string to boolean
    def parse_revoked():
        if revoked and revoked.lower() in ["true", "false"]:
            return revoked.lower() == "true"
        return None

    filters = {
        "credential_id": credential_id,
        "scid": resolve_scid(),
        "issuer_did": issuer_did,
        "subject_id": subject_id,
        "revoked": parse_revoked(),
    }
    # Remove None values
    filters = {k: v for k, v in filters.items() if v is not None}

    # Calculate offset
    offset = (page - 1) * limit

    # Get total count for pagination
    total = storage.count_credentials(filters)
    total_pages = (total + limit - 1) // limit  # Ceiling division

    # Get paginated results from VerifiableCredentialRecord
    credential_records = storage.get_credentials(filters, limit=limit, offset=offset)

    # Format results for explorer UI using factory method
    formatted_results = [
        ExplorerCredentialRecord.from_credential_record(c) for c in credential_records
    ]

    # Apply credential_type filter (post-query since it's stored as JSON)
    if credential_type:
        formatted_results = [
            r
            for r in formatted_results
            if credential_type.lower() in [t.lower() for t in r.all_types]
        ]
        # Recalculate total and pages after filtering
        total = len(formatted_results)
        total_pages = (total + limit - 1) // limit if limit else 1

    CONTEXT = {
        "results": [r.model_dump() for r in formatted_results],
        "pagination": create_pagination(page, limit, total, total_pages),
    }

    if request.headers.get("Accept") == "application/json":
        return JSONResponse(status_code=200, content=CONTEXT)

    CONTEXT["branding"] = settings.BRANDING
    return templates.TemplateResponse(
        request=request, name="pages/credentials.jinja", context=CONTEXT
    )


@router.get("/witnesses")
@router.get("/witnesses/")
async def explorer_witness_registry(request: Request):
    """View the known witness registry."""
    registry = storage.get_registry("knownWitnesses")
    witness_records: list[ExplorerWitnessRecord] = []

    if registry and registry.registry_data:
        for witness_id, entry in registry.registry_data.items():
            entry_data = entry or {}
            witness_records.append(
                ExplorerWitnessRecord.from_registry_entry(witness_id, entry_data)
            )

    # Sort alphabetically by name then short id for consistent display
    witness_records.sort(key=lambda w: (w.name or w.short_id).lower())

    meta = ExplorerWitnessRegistryMeta.from_meta(registry.meta if registry else None)

    context = {
        "results": [record.model_dump() for record in witness_records],
        "total": len(witness_records),
        "meta": meta.model_dump(),
    }

    if request.headers.get("Accept") == "application/json":
        return JSONResponse(status_code=200, content=context)

    context["branding"] = settings.BRANDING
    return templates.TemplateResponse(
        request=request,
        name="pages/witnesses.jinja",
        context=context,
    )
