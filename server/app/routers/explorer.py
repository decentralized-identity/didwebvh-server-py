"""Explorer routes for DIDs and resources UI."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.db.models import AttestedResourceRecord
from app.utilities import beautify_date, resource_details, resource_id_to_url
from app.plugins import DidWebVH
from app.plugins.storage import StorageManager
from app.avatar_generator import generate_avatar

from config import templates, settings
from sqlalchemy import func

router = APIRouter(tags=["Explorer"])
storage = StorageManager()
webvh = DidWebVH()


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
    filters = {}
    if scid:
        filters["scid"] = scid
    if namespace:
        filters["namespace"] = namespace
    if identifier:
        filters["alias"] = identifier  # Note: identifier maps to alias column
    if domain:
        filters["domain"] = domain
    if status == "active":
        filters["deactivated"] = False
    elif status == "deactivated":
        filters["deactivated"] = True

    # Calculate offset
    offset = (page - 1) * limit

    # Get total count for pagination
    total = storage.count_did_controllers(filters)
    total_pages = (total + limit - 1) // limit  # Ceiling division

    # Get paginated results from DidControllerRecord
    did_controllers = storage.get_did_controllers(filters, limit=limit, offset=offset)

    # Format results for explorer UI (compute fields on-the-fly)
    results = []
    for controller in did_controllers:
        # Get resources for this DID
        did_resources = storage.get_resources(filters={"scid": controller.scid})
        formatted_resources = [
            {
                "type": r.resource_type,
                "digest": r.resource_id,
                "details": {},  # Can be enhanced with resource_details() later
            }
            for r in did_resources
        ]

        # Generate links
        links = {
            "resolver": f"{settings.UNIRESOLVER_URL}/#{controller.did}",
            "log_file": f"https://{controller.domain}/{controller.namespace}/{controller.alias}/did.jsonl",
            "witness_file": f"https://{controller.domain}/{controller.namespace}/{controller.alias}/did-witness.json",
            "resource_query": f"https://{settings.DOMAIN}/explorer/resources?scid={controller.scid}",
            "whois_presentation": f"https://{controller.domain}/{controller.namespace}/{controller.alias}/whois.vp",
        }

        results.append(
            {
                # Basic info
                "did": controller.did,
                "scid": controller.scid,
                "domain": controller.domain,
                "namespace": controller.namespace,
                "identifier": controller.alias,
                "created": beautify_date(controller.logs[0].get("versionTime"))
                if controller.logs
                else "",
                "updated": beautify_date(controller.logs[-1].get("versionTime"))
                if controller.logs
                else "",
                "deactivated": str(controller.deactivated),
                # Computed explorer fields
                "active": not controller.deactivated,
                "avatar": generate_avatar(controller.scid),  # Generate avatar from SCID
                "witnesses": controller.parameters.get("witness", {}).get("witnesses", [])
                if controller.parameters
                else [],
                "watchers": controller.parameters.get("watchers", [])
                if controller.parameters
                else [],
                "resources": formatted_resources,
                "links": links,
                "parameters": controller.parameters,
                "version_id": controller.logs[-1].get("versionId") if controller.logs else "",
                "version_time": controller.logs[-1].get("versionTime") if controller.logs else "",
                # Raw data (for detail views)
                "logs": controller.logs,
                "witness_file": controller.witness_file,
                "whois_presentation": controller.whois_presentation,
                "document": controller.document,
                "document_state": controller.document,  # Template expects document_state for VM and services
            }
        )

    # Apply has_resources filter (post-fetch since it's not a tag)
    if has_resources == "yes":
        results = [r for r in results if r.get("resources") and len(r.get("resources", [])) > 0]
    elif has_resources == "no":
        results = [r for r in results if not r.get("resources") or len(r.get("resources", [])) == 0]

    CONTEXT = {
        "results": results,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1 if page > 1 else None,
            "next_page": page + 1 if page < total_pages else None,
        },
    }

    if request.headers.get("Accept") == "application/json":
        return JSONResponse(status_code=200, content=CONTEXT)
    CONTEXT["branding"] = settings.BRANDING
    return templates.TemplateResponse(request=request, name="pages/did_list.jinja", context=CONTEXT)


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
    # Build filters (route-level)
    filters = {}
    if scid:
        filters["scid"] = scid
    if resource_id:
        filters["resource_id"] = resource_id
    if resource_type:
        filters["resource_type"] = resource_type

    # Calculate offset
    offset = (page - 1) * limit

    # Temporary Postgres compatibility fallback:
    # Select only columns that are guaranteed to exist to avoid selecting
    # a missing 'did' column in older deployments.
    with storage.get_session() as session:
        # Base selectable columns (exclude AttestedResourceRecord.did)
        base_query = session.query(
            AttestedResourceRecord.resource_id,
            AttestedResourceRecord.scid,
            AttestedResourceRecord.resource_type,
            AttestedResourceRecord.resource_name,
            AttestedResourceRecord.attested_resource,
            AttestedResourceRecord.media_type,
        )

        count_query = session.query(func.count()).select_from(AttestedResourceRecord)

        # Apply filters consistently
        if "scid" in filters:
            base_query = base_query.filter(AttestedResourceRecord.scid == filters["scid"])
            count_query = count_query.filter(AttestedResourceRecord.scid == filters["scid"])
        if "resource_id" in filters:
            base_query = base_query.filter(
                AttestedResourceRecord.resource_id == filters["resource_id"]
            )
            count_query = count_query.filter(
                AttestedResourceRecord.resource_id == filters["resource_id"]
            )
        if "resource_type" in filters:
            base_query = base_query.filter(
                AttestedResourceRecord.resource_type == filters["resource_type"]
            )
            count_query = count_query.filter(
                AttestedResourceRecord.resource_type == filters["resource_type"]
            )

        total = count_query.scalar() or 0
        total_pages = (total + limit - 1) // limit if limit else 1

        rows = base_query.offset(offset).limit(limit).all()

    # Format results for explorer UI (compute missing 'did' from attested_resource.id)
    formatted_results = []
    for row in rows:
        attested_res = row.attested_resource or {}
        res_id_full = attested_res.get("id", "")
        # Derive DID from resource id if present: did:webvh:.../resources/<digest>
        did_from_id = res_id_full.split("/resources/")[0] if "/resources/" in res_id_full else ""
        did_parts = did_from_id.split(":") if did_from_id else []
        domain = did_parts[3] if len(did_parts) >= 4 else ""
        namespace = did_parts[4] if len(did_parts) >= 5 else ""
        alias = did_parts[5] if len(did_parts) >= 6 else ""

        formatted_results.append(
            {
                # Basic info
                "did": did_from_id,
                "scid": row.scid,
                "resource_id": row.resource_id,
                "resource_type": row.resource_type,
                "resource_name": row.resource_name,
                # Computed fields
                "attested_resource": attested_res,
                "details": resource_details(attested_res),
                "url": resource_id_to_url(res_id_full) if res_id_full else "",
                "author": {
                    "scid": row.scid,
                    "domain": domain,
                    "namespace": namespace,
                    "alias": alias,
                    "avatar": generate_avatar(row.scid),  # Generate avatar from SCID
                },
            }
        )

    CONTEXT = {
        "results": formatted_results,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1 if page > 1 else None,
            "next_page": page + 1 if page < total_pages else None,
        },
    }

    if request.headers.get("Accept") == "application/json":
        return JSONResponse(status_code=200, content=CONTEXT)

    CONTEXT["branding"] = settings.BRANDING
    return templates.TemplateResponse(
        request=request, name="pages/resource_list.jinja", context=CONTEXT
    )
