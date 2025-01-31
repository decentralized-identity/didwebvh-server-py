from typing import Dict, Any, List
from pydantic import BaseModel, Field
from .did_document import SecuredDidDocument
from .resource import AttestedResource
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
    

class ResourceOptions(BaseModel):
    resourceId: str = Field(None)
    resourceName: str = Field(None)
    resourceType: str = Field(None)
    resourceCollectionId: str = Field(None)

class ResourceUpload(BaseModel):
    attestedResource: AttestedResource = Field()
    options: ResourceOptions = Field()
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "attestedResource": {},
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
