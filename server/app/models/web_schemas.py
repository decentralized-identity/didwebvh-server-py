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
    signedDocument: ResourceUploadDocument = Field()
    options: ResourceUploadOptions = Field()
