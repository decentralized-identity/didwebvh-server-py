"""Explorer routes for DIDs and resources UI."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.plugins import AskarStorage, DidWebVH

from config import templates, settings

router = APIRouter(tags=["Explorer"])
askar = AskarStorage()
webvh = DidWebVH()


@router.get("/")
async def explorer_index(request: Request):
    """Landing page for the explorer UI."""
    CONTEXT = {"branding": settings.BRANDING}
    return templates.TemplateResponse(request=request, name="pages/index.jinja", context=CONTEXT)


@router.get("/dids")
async def explorer_did_table(
    request: Request,
    namespace: str = None,
    status: str = None,
    identifier: str = None,
    scid: str = None,
):
    """DID table."""
    tags = {
        "scid": scid or None,
        "namespace": namespace or None,
        "identifier": identifier or None,
    }
    if status == "active":
        tags["deactivated"] = "False"
    elif status == "deactivated":
        tags["deactivated"] = "True"
    # elif status == "all":
    #     tags["deactivated"] = None

    tags = {k: v for k, v in tags.items() if v is not None}
    CONTEXT = {
        "results": [
            entry.value_json for entry in await askar.get_category_entries("didRecord", tags)
        ]
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
):
    """Resource table."""
    tags = {
        k: v for k, v in 
        {
            "scid": scid, 
            "resource_type": resource_type, 
            "resource_id": resource_id
        }.items() 
        if v is not None
    }
    CONTEXT = {
        "results": [
            entry.value_json for entry in await askar.get_category_entries("resourceRecord", tags)
        ]
    }

    if request.headers.get("Accept") == "application/json":
        return JSONResponse(status_code=200, content=CONTEXT)

    CONTEXT["branding"] = settings.BRANDING
    return templates.TemplateResponse(
        request=request, name="pages/resource_list.jinja", context=CONTEXT
    )
