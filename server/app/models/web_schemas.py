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

class UpdateLogEntry(BaseModel):
    logEntry: LogEntry = Field()
    witnessProof: List[DataIntegrityProof] = Field(None)

class DeactivateLogEntry(BaseModel):
    logEntry: LogEntry = Field()
    witnessProof: WitnessSignature = Field()

class ResourceUploadDocument(BaseModel):
    proof: dict = Field()

class ResourceUploadOptions(BaseModel):
    type: str = Field()
    resourceId: str = Field()
    resourcePath: str = Field()

class ResourceUpload(BaseModel):
    securedResource: ResourceUploadDocument = Field()
    options: ResourceUploadOptions = Field()
