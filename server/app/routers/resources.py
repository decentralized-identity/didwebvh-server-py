from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from typing import Union
from app.models.web_schemas import ResourceUpload, ResourceTemplate
from app.models.resource import AttestedResource
from app.models.anoncreds import SecuredSchema, SecuredCredDef
from app.plugins import AskarVerifier, AskarStorage
import copy

# router = APIRouter(tags=["LinkedResources"])
router = APIRouter()

SUPPORTED_RESSOURCE_TYPES = [
    'AnonCredsSchema',
    'AnonCredsCredDef',
]

def verify_resource(resource):
    verifier = AskarVerifier()
    proof = resource.pop('proof')
    verifier.verify_proof(resource, proof)

@router.post("/resources", tags=["LinkedResources"])
async def upload_linked_resource(request_body: Union[ResourceTemplate, ResourceUpload]):
    options = vars(request_body)['options']
    if isinstance(request_body, ResourceTemplate):
        resource_content = vars(request_body).get('resourceContent')
        issuer = 'did:webvh:'
        resource_id = 'z123'
        resource_type = options.resourceType
        resource = AttestedResource(
            id=f'{issuer}/resources/{resource_id}.json',
            resourceInfo={
                'resourceCollectionId': resource_id,
                'resourceId': resource_id,
                'resourceType': resource_type
            },
            resourceContent=resource_content
        ).model_dump()
        if resource_type == 'AnonCredsSchema':
            pass
        elif resource_type == 'AnonCredsCredDef':
            pass
        elif resource_type == 'AnonCredsRevRegDef':
            pass
        return JSONResponse(status_code=200, content=resource)
    elif isinstance(request_body, ResourceUpload):
        secured_resource = vars(request_body).get('securedResource')
        verify_resource(copy.deepcopy(secured_resource))
        
        storage = AskarStorage()
        tags = {
            'type': options.get('resourceType')
        }
        resource_id = options.get('resourceId')
        resource_type = options.get('resourceType')
        await storage.store(f'resource:{resource_type}', resource_id, secured_resource)

# @router.post("/resources/anoncreds/schemas", tags=["AnonCreds"])
# async def upload_anoncreds_schema(request_body: SecuredSchema):
#     resource = vars(request_body)
#     verify_resource(copy.deepcopy(resource))
    
#     storage = AskarStorage()
#     tags = {
#         'type': 'AnonCredsSchema',
#         'issuer': resource['issuerId'],
#         'schemaName': ''
#     }
#     await storage.store('resource:anoncreds:schema', '', resource)

# @router.post("/resources/anoncreds/definitions", tags=["AnonCreds"])
# async def upload_anoncreds_definition(request_body: SecuredCredDef):
#     resource = vars(request_body)
#     verify_resource(copy.deepcopy(resource))
    
#     storage = AskarStorage()
#     await storage.store('resource:anoncreds:creDef', '', resource)
