from typing import Dict, Any, List
from pydantic import BaseModel, Field
from .did_document import SecuredDidDocument
from .did_log import InitialLogEntry, LogEntry, WitnessSignature
from .di_proof import DataIntegrityProof


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
    resourceDigest: str = Field()

class ResourceUpload(BaseModel):
    securedResource: ResourceUploadDocument = Field()
    options: ResourceUploadOptions = Field()
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "securedResource": {},
                    "options": {
                        'resourceId': '35d2c712-2245-414f-9657-13a8c7965e2b',
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
