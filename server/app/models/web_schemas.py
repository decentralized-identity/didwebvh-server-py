"""Pydantic models for the web schemas."""

from typing import Any, Dict, List

from pydantic import BaseModel, Field

from .di_proof import DataIntegrityProof
from .did_document import SecuredDidDocument
from .did_log import InitialLogEntry, LogEntry


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
