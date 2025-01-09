from typing import Dict, Any
from pydantic import BaseModel, Field
from .did_document import SecuredDidDocument
from .did_log import InitialLogEntry


class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class RegisterDID(BaseModel):
    didDocument: SecuredDidDocument = Field()


class RegisterInitialLogEntry(BaseModel):
    logEntry: InitialLogEntry = Field()


class ResourceUploadDocument(BaseModel):
    proof: dict = Field()

class ResourceUploadOptions(BaseModel):
    type: str = Field()
    resourceId: str = Field()
    resourcePath: str = Field()

class ResourceUpload(BaseModel):
    securedResource: ResourceUploadDocument = Field()
    options: ResourceUploadOptions = Field()
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "securedResource": {
                        'issuerId': 'did:webvh:...:example.com',
                        'name': 'Person',
                        'version': '1.0',
                        'attributes': ['firstName', 'lastName'],
                        'proof': {
                            'type': 'DataIntegrityProof',
                            'cryptosuite': 'DataIntegrityProof',
                            'proofValue': '...'
                        }
                    },
                    "options": {
                        'resourceId': '35d2c712-2245-414f-9657-13a8c7965e2b',
                        'resourceType': 'AnonCredsSchema',
                        'resourcePath': '/anoncreds/schemas/Person/1.0',
                    },
                }
            ]
        }
    }
