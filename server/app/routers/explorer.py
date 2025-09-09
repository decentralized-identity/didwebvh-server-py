"""Explorer routes for DIDs and resources UI."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from operator import itemgetter

from app.plugins import AskarStorage, DidWebVH
from app.utilities import beautify_date, resource_id_to_url, resource_details, get_client_id

from config import templates, settings

router = APIRouter(tags=["Explorer"])
askar = AskarStorage()
webvh = DidWebVH()

@router.get("/")
async def explorer_index(request: Request):
    """Landing page for the explorer UI."""
    CONTEXT = {
        'branding': settings.BRANDING
    }
    return templates.TemplateResponse(
        request=request, name="pages/index.jinja", context=CONTEXT
    )

@router.get("/dids")
async def explorer_did_table(
    request: Request,
    namespace: str = None,
    status: str = None,
    identifier: str = None,
    scid: str = None,
):
    """DID table."""
    tag_filters = {
        'scid': scid or None,
        'namespace': namespace or None,
        'identifier': identifier or None,
    }
    if status == 'active':
        tag_filters['deactivated'] = 'False'
    elif status == 'deactivated':
        tag_filters['deactivated'] = 'True'
    elif status == 'all':
        tag_filters['deactivated'] = None
        
    tag_filters = {k: v for k, v in tag_filters.items() if v is not None}
    entries = await askar.get_category_entries('logEntries', tag_filters)
    CONTEXT = {
        'results': []
    }
    for entry in entries:
        logs = entry.value_json
        state = webvh.get_document_state(logs)
        initial_log = logs[0]
        did = initial_log.get('state').get('id')
        scid, domain, namespace, identifier = itemgetter(2, 3, 4, 5)(did.split(":"))
        did_info = {
            'id': did,
            'avatar': f'{settings.AVATAR_URL}?seed={scid}',
            'resolver': f'{settings.UNIRESOLVER_URL}/#{did}',
            'scid': scid,
            'domain': domain,
            'namespace': namespace,
            'identifier': identifier,
            'created': beautify_date(logs[0].get('versionTime')),
            'updated': beautify_date(logs[-1].get('versionTime')),
            'deactivated': str(state.deactivated)
        }
        await askar.update('logEntries', entry.name, entry.value_json, tags=did_info)
        did_info['logs'] = logs
        did_info['resources'] = []
        resources = await askar.get_category_entries('resource', {'scid': scid})
        for resource in resources:
            attested_resource = resource.value_json
            did_info['resources'].append({
                'digest': attested_resource.get('metadata').get('resourceId'),
                'type': attested_resource.get('metadata').get('resourceType'),
                'details': resource_details(attested_resource)
            })
        did_info['active'] = False if state.deactivated else True
        client_id = get_client_id(namespace, identifier)
        did_info['witnesses'] = state.witness.get('witnesses')
        whois_vp = await askar.fetch("whois", client_id)
        did_info['whois'] = whois_vp
        CONTEXT['results'].append(did_info)
        
    if request.headers.get("Accept") == 'application/json':
        return JSONResponse(status_code=200, content=CONTEXT)
    CONTEXT['branding'] = settings.BRANDING
    return templates.TemplateResponse(
        request=request, name="pages/did_list.jinja", context=CONTEXT
    )

@router.get("/resources")
async def explorer_resource_table(
    request: Request,
    scid: str = None,
    resource_id: str = None,
    resource_type: str = None,
):
    """Resource table."""
    tag_filters = {
        'scid': scid,
        'resource_type': resource_type,
        'resource_id': resource_id
    }
    tag_filters = {k: v for k, v in tag_filters.items() if v is not None}
    entries = await askar.get_category_entries('resource', tag_filters)
    CONTEXT = {
        'results': []
    }
    for entry in entries:
        attested_resource = entry.value_json
        author_id = attested_resource.get('id').split('/')[0]
        author_scid = author_id.split(':')[2]
        digest = attested_resource.get('id').split('/')[-1]
        author = {
            'avatar': f'{settings.AVATAR_URL}?seed={author_scid}',
            'scid': author_scid,
            'domain': 'sandbox.bcvh.vonx.io',
            'namespace': 'test',
            'identifier': 'df598728-bbeb-4f45-bd24-dc8f8154a472',
        }
        resource = {
            'avatar': f'{settings.AVATAR_URL}?seed={digest}',
            'url': resource_id_to_url(attested_resource.get('id')),
            'digest': digest,
            'name': attested_resource.get('metadata').get('resourceName'),
            'type': attested_resource.get('metadata').get('resourceType'),
            'version': attested_resource.get('metadata').get('resourceVersion'),
            'author': author,
            'details': {}
        }
        name = 'null'
        if resource.get('type') == 'anonCredsSchema':
            resource['details'] = {
                'name': attested_resource.get('content').get('name'),
                'version': attested_resource.get('content').get('version')
            }
            name = attested_resource.get('content').get('name')
        elif resource.get('type') == 'anonCredsCredDef':
            resource['details'] = {
                'tag': attested_resource.get('content').get('tag')
            }
            name = attested_resource.get('content').get('tag')
        elif resource.get('type') == 'anonCredsRevRegDef':
            resource['details'] = {
                'tag': '',
                'size': ''
            }
            name = attested_resource.get('content').get('tag')
        elif resource.get('type') == 'anonCredsStatusList':
            resource['details'] = {}
            name = attested_resource.get('content').get('tag')
        tags = {
            'scid': author_scid,
            'author': author_scid,
            'type': attested_resource.get('metadata').get('resourceType'),
            'digest': digest,
            'name': name
        }
        await askar.update('resource', entry.name, entry.value_json, tags=tags)
        CONTEXT['results'].append(resource)
        
    if request.headers.get("Accept") == 'application/json':
        return JSONResponse(status_code=200, content=CONTEXT)
    CONTEXT['branding'] = settings.BRANDING
    return templates.TemplateResponse(
        request=request, name="pages/resource_list.jinja", context=CONTEXT
    )