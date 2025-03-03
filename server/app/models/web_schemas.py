"""Pydantic models for the web schemas."""

from typing import Any, Dict, List

from pydantic import BaseModel, Field
from .did_document import SecuredDidDocument
from .resource import AttestedResource
from .did_log import InitialLogEntry, LogEntry, WitnessSignature
from .di_proof import DataIntegrityProof
from config import settings


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class RegisterDID(BaseModel):
    """RegisterDID model."""

    didDocument: SecuredDidDocument = Field()


class RegisterInitialLogEntry(BaseModel):
    """RegisterInitialLogEntry model."""

    logEntry: InitialLogEntry = Field()
    

class UpdateLogEntry(BaseModel):
    """UpdateLogEntry model."""

    logEntry: LogEntry = Field()
    witnessProof: List[DataIntegrityProof] = Field(None)

class DeactivateLogEntry(BaseModel):
    """DeactivateLogEntry model."""
    logEntry: LogEntry = Field()
    witnessProof: WitnessSignature = Field()

class ResourceUploadDocument(BaseModel):
    """ResourceUploadDocument model."""
    context: List[str] = Field(alias="@context")
    type: List[str] = Field()
    id: str = Field()
    resourceContent: dict = Field()
    resourceMetadata: dict = Field()
    relatedResource: List[dict] = Field(None)
    proof: dict = Field()

class ResourceOptions(BaseModel):
    """ResourceOptions model."""
    resourceId: str = Field(None)
    resourceName: str = Field(None)
    resourceType: str = Field(None)
    resourceCollectionId: str = Field(None)

class ResourceTemplate(BaseModel):
    """ResourceTemplate model."""
    resourceContent: dict = Field()
    options: ResourceOptions = Field()

class ResourceUpload(BaseModel):
    """ResourceUpload model."""
    attestedResource: AttestedResource = Field()
    options: ResourceOptions = Field()
