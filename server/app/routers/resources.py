from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from typing import Union
from app.models.web_schemas import ResourceUpload, ResourceTemplate
from app.models.resource import AttestedResource
from app.models.anoncreds import SecuredSchema, SecuredCredDef
from app.plugins import AskarVerifier, AskarStorage
import copy
import json

# router = APIRouter(tags=["LinkedResources"])
router = APIRouter()

SUPPORTED_RESSOURCE_TYPES = [
    'AnonCredsSchema',
    'AnonCredsCredDef',
]

async def verify_resource(resource):
    # verifier = AskarVerifier()
    proof = resource.pop('proof')
    # verifier.verify_proof(resource, proof)
    try:
        # client_id = resource.get('resourceMetadata').get('resourceCollectionId').replace('/', ':')
        # log_entry = await AskarStorage().fetch("logEntries", client_id)
        # assert log_entry
        assert proof['verificationMethod'].split('#')[0]
        assert proof['type'] == 'DataIntegrityProof'
        assert proof['cryptosuite'] == 'eddsa-jcs-2022'
        assert proof['proofPurpose'] == 'assertionMethod'
    except:
        raise HTTPException(status_code=400, detail="Couldn't verify resource.")
        

@router.post("/resources", tags=["LinkedResources"])
async def upload_linked_resource(request_body: ResourceUpload):
    options = vars(request_body)['options'].model_dump()
    secured_resource = vars(request_body)['securedResource'].model_dump()
    await verify_resource(copy.deepcopy(secured_resource))

    storage = AskarStorage()
    await storage.store(
        'resource',
        options.get('resourceId'),
        secured_resource,
        secured_resource.get('resourceMetadata')
    )
    return JSONResponse(status_code=201, content={})

@router.get("/{namespace}/{identifier}/resources/{resource_id}.json", tags=["Resources"])
async def get_resource(namespace: str, identifier: str, resource_id: str):
    
    storage = AskarStorage()
    # resource_id = f'{namespace}/{identifier}/{resource_id}'
    resource = await storage.fetch('resource', resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Couldn't find resource.")
    return JSONResponse(status_code=200, content=resource)

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
