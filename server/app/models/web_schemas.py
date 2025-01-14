from typing import Dict, Any, List
from pydantic import BaseModel, Field
from .did_document import SecuredDidDocument
from .did_log import InitialLogEntry, LogEntry, WitnessSignature
from .di_proof import DataIntegrityProof
from config import settings


class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class RegisterDID(BaseModel):
    didDocument: SecuredDidDocument = Field()


class RegisterInitialLogEntry(BaseModel):
    logEntry: InitialLogEntry = Field()


class ResourceUploadDocument(BaseModel):
    proof: dict = Field()

class ResourceOptions(BaseModel):
    resourceId: str = Field()
    resourceType: str = Field()

class ResourceTemplate(BaseModel):
    resourceContent: dict = Field()
    options: ResourceOptions = Field()
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "resourceContent": {
                        "issuerId": "did:webvh:",
                        "name": "Example",
                        "version": "1.0",
                        "attributes": ["firstName", "lastName"]    
                    },
                    "options": {
                        'resourceCollectionId': r'{SCID}' + f':{settings.DOMAIN}:example:identifier',
                        'resourceId': 'z123',
                        'resourceName': 'Example',
                        'resourceType': 'AnonCredsSchema'
                    },
                }
            ]
        }
    }

class ResourceUpload(BaseModel):
    securedResource: ResourceUploadDocument = Field()
    options: ResourceOptions = Field()
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "securedResource": {},
                    "options": {
                        'resourceType': 'AnonCredsSchema'
                    },
                }
            ]
        }
    }
class UpdateLogEntry(BaseModel):
    logEntry: LogEntry = Field()
    witnessProof: List[DataIntegrityProof] = Field(None)

    # model_config = {
    #     "json_schema_extra": {
    #         "examples": [
    #             {
    #                 "logEntry": {},
    #                 "witnessProof": [
    #                     DataIntegrityProof(
    #                         proofValue='',
    #                         verificationMethod=''
    #                     ).model_dump()
    #                 ]
    #             }
    #         ]
    #     }
    # }


# class DeactivateLogEntry(BaseModel):
#     logEntry: LogEntry = Field()
#     witnessProof: WitnessSignature = Field()
