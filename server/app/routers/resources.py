from fastapi import APIRouter, HTTPException
from app.models.web_schemas import ResourceUpload
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

@router.post("/resources/anoncreds/schemas", tags=["AnonCreds"])
async def upload_anoncreds_schema(request_body: SecuredSchema):
    resource = vars(request_body)
    verify_resource(copy.deepcopy(resource))
    
    storage = AskarStorage()
    tags = {
        'type': 'AnonCredsSchema',
        'issuer': resource['issuerId'],
        'schemaName': ''
    }
    await storage.store('resource:anoncreds:schema', '', resource)

@router.post("/resources/anoncreds/definitions", tags=["AnonCreds"])
async def upload_anoncreds_definition(request_body: SecuredCredDef):
    resource = vars(request_body)
    verify_resource(copy.deepcopy(resource))
    
    storage = AskarStorage()
    await storage.store('resource:anoncreds:creDef', '', resource)

@router.post("/resources", tags=["LinkedResources"])
async def upload_linked_resource(request_body: ResourceUpload):
    resource = vars(request_body)
    verify_resource(copy.deepcopy(resource))
    
    storage = AskarStorage()
    tags = {
        'type': 'AnonCredsSchema',
        'issuer': resource['issuerId'],
        'schemaName': ''
    }
    await storage.store('resource:anoncreds:schema', '', resource)
