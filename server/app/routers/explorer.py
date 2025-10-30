"""Explorer routes for DIDs and resources UI."""

import json
import base64
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.db.models import AttestedResourceRecord, VerifiableCredentialRecord
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
        
        # Get credentials for this DID
        did_credentials = storage.get_credentials(filters={"scid": controller.scid})
        formatted_credentials = [
            {
                "id": c.credential_id,
                "type": c.credential_type,
                "subject_id": c.subject_id,
                "issued": beautify_date(c.created) if c.created else "",
                "valid_from": beautify_date(c.valid_from) if c.valid_from else "",
                "valid_until": beautify_date(c.valid_until) if c.valid_until else "",
                "revoked": c.revoked,
                "verified": c.verified,
            }
            for c in did_credentials
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
                "credentials": formatted_credentials,
                "links": links,
                "parameters": controller.parameters,
                "version_id": controller.logs[-1].get("versionId") if controller.logs else "",
                "version_time": controller.logs[-1].get("versionTime") if controller.logs else "",
                # Raw data (for detail views)
                "logs": controller.logs,
                "witness_file": controller.witness_file,
                "whois_presentation": controller.whois_presentation,
                "document": controller.document,
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
    filters = {}
    if credential_id:
        filters["credential_id"] = credential_id
    
    # Handle namespace/alias -> scid lookup
    if namespace and alias:
        # Look up the DID controller by namespace and alias to get SCID
        did_controller = storage.get_did_controller_by_alias(namespace, alias)
        if did_controller:
            filters["scid"] = did_controller.scid
        else:
            # If no matching controller found, use impossible SCID to return no results
            filters["scid"] = "NOTFOUND"
    elif scid:
        filters["scid"] = scid
    
    if issuer_did:
        filters["issuer_did"] = issuer_did
    if subject_id:
        filters["subject_id"] = subject_id
    if revoked and revoked.lower() in ['true', 'false']:
        filters["revoked"] = revoked.lower() == 'true'
    
    # Calculate offset
    offset = (page - 1) * limit
    
    # Get total count for pagination
    total = storage.count_credentials(filters)
    total_pages = (total + limit - 1) // limit  # Ceiling division
    
    # Get paginated results from VerifiableCredentialRecord
    credential_records = storage.get_credentials(filters, limit=limit, offset=offset)
    
    # Format results for explorer UI (compute on-the-fly)
    formatted_results = []
    for c in credential_records:
        vc = c.verifiable_credential
        
        # Check if this is an EnvelopedVerifiableCredential
        cred_types = vc.get("type", [])
        if isinstance(cred_types, str):
            cred_types = [cred_types]
        
        # If it's an envelope, decode the JWT to get the actual credential type
        if "EnvelopedVerifiableCredential" in cred_types:
            try:
                # Extract JWT from data URL
                # Note: We only support VC-JOSE format (application/vc+jwt)
                # Validation is performed at storage time
                data_url = vc.get("id", "")
                if data_url.startswith("data:"):
                    jwt_token = data_url.split(",", 1)[1]
                    parts = jwt_token.split(".")
                    
                    if len(parts) == 3:
                        # Decode JWT payload (the actual credential)
                        # Add proper padding for base64
                        payload = parts[1]
                        payload += '=' * (4 - len(payload) % 4)
                        decoded_vc = json.loads(base64.urlsafe_b64decode(payload))
                        
                        # Extract types from decoded credential
                        decoded_types = decoded_vc.get("type", [])
                        if isinstance(decoded_types, str):
                            decoded_types = [decoded_types]
                        cred_types = decoded_types
                        
                        # Also extract subject from decoded credential for display
                        subject = decoded_vc.get("credentialSubject", {})
                        if isinstance(subject, list):
                            subject = subject[0] if subject else {}
                    else:
                        # Fallback if decoding fails
                        subject = vc.get("credentialSubject", {})
                        if isinstance(subject, list):
                            subject = subject[0] if subject else {}
                else:
                    # Fallback if no data URL
                    subject = vc.get("credentialSubject", {})
                    if isinstance(subject, list):
                        subject = subject[0] if subject else {}
            except Exception as e:
                # Fallback if decoding fails
                subject = vc.get("credentialSubject", {})
                if isinstance(subject, list):
                    subject = subject[0] if subject else {}
        else:
            # Regular credential, extract subject normally
            subject = vc.get("credentialSubject", {})
            if isinstance(subject, list):
                subject = subject[0] if subject else {}
        
        # Filter out "VerifiableCredential" to show only specific types
        specific_types = [t for t in cred_types if t != "VerifiableCredential"]
        
        # Format credential type for display (add spaces before capital letters)
        raw_type = specific_types[0] if specific_types else "VerifiableCredential"
        # Add space before capital letters and trim
        formatted_type = ''.join([' ' + c if c.isupper() else c for c in raw_type]).strip()
        
        # Get DID controller to extract namespace and alias
        did_controller = storage.get_did_controller_by_scid(c.scid)
        namespace_val = did_controller.namespace if did_controller else ""
        alias_val = did_controller.alias if did_controller else ""
        
        # Extract DID method from issuer_did (did:web:, did:key:, etc.)
        did_method = "unknown"
        if c.issuer_did and c.issuer_did.startswith("did:"):
            parts = c.issuer_did.split(":")
            if len(parts) >= 2:
                did_method = parts[1]
        
        # Extract subject name and type for display
        subject_name = subject.get("name") if isinstance(subject, dict) else None
        subject_type = None
        if isinstance(subject, dict):
            subject_types = subject.get("type", [])
            if isinstance(subject_types, list):
                # Get first non-generic type
                subject_type = next((t for t in subject_types if t != "VerifiableCredential"), subject_types[0] if subject_types else None)
            else:
                subject_type = subject_types
        
        formatted_results.append({
            # Basic info
            "credential_id": c.credential_id,
            "issuer_did": c.issuer_did,
            "subject_id": c.subject_id or "N/A",
            "subject_name": subject_name,
            "subject_type": subject_type,
            "scid": c.scid,
            "namespace": namespace_val,
            "alias": alias_val,
            "avatar": generate_avatar(c.scid),
            "did_method": did_method,
            
            # Credential details
            "credential_type": formatted_type,
            "all_types": cred_types,
            "revoked": c.revoked,
            "status": "Revoked" if c.revoked else "Active",
            
            # Validity
            "valid_from": beautify_date(c.valid_from) if c.valid_from else "N/A",
            "valid_until": beautify_date(c.valid_until) if c.valid_until else "N/A",
            
            # Verification
            "verified": c.verified,
            "verification_method": c.verification_method,
            "verification_error": c.verification_error,
            
            # Full credential
            "verifiable_credential": vc,
            
            # Timestamps
            "created": beautify_date(c.created),
            "updated": beautify_date(c.updated),
        })
    
    # Apply credential_type filter (post-query since it's stored as JSON)
    if credential_type:
        formatted_results = [
            r for r in formatted_results 
            if credential_type.lower() in [t.lower() for t in r["all_types"]]
        ]
        # Recalculate total and pages after filtering
        total = len(formatted_results)
        total_pages = (total + limit - 1) // limit if limit else 1
    
    CONTEXT = {
        "results": formatted_results,
        "query_params": {
            "scid": scid,
            "issuer_did": issuer_did,
            "subject_id": subject_id,
            "credential_type": credential_type,
            "namespace": namespace,
            "alias": alias,
            "revoked": revoked,
        },
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1 if page > 1 else None,
            "next_page": page + 1 if page < total_pages else None,
        }
    }

    if request.headers.get("Accept") == "application/json":
        return JSONResponse(status_code=200, content=CONTEXT)

    CONTEXT["branding"] = settings.BRANDING
    return templates.TemplateResponse(
        request=request, name="pages/credential_list.jinja", context=CONTEXT
    )
