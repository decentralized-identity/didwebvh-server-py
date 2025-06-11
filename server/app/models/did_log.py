"""DID Log models."""

from typing import Any, Dict, List, Union

from pydantic import BaseModel, Field

from config import settings

from .di_proof import DataIntegrityProof
from .did_document import DidDocument


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class WitnessSignature(BaseModel):
    """WitnessSignature model."""

    versionId: str = Field()
    proof: List[DataIntegrityProof] = Field()


class LogEntry(BaseModel):
    """LogEntry model."""

    class Parameters(BaseModel):
        """LogParameters model."""

        class WitnessParam(BaseModel):
            """WitnessParam model."""

            class Witness(BaseModel):
                """Witness model."""

                id: str = Field()

            threshold: int = Field()
            witnesses: List[Witness] = Field()

        method: str = Field(None, example=f"did:webvh:{settings.WEBVH_VERSION}")
        scid: str = Field(None)
        portable: bool = Field(None)
        updateKeys: List[str] = Field(None)
        nextKeyHashes: List[str] = Field(None)
        witness: WitnessParam = Field(None)
        watchers: List[str] = Field(None)
        deactivated: bool = Field(None)
        ttl: bool = Field(None)

    versionId: str = Field()
    versionTime: str = Field()
    parameters: Parameters = Field()
    state: DidDocument = Field()
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field(None)
