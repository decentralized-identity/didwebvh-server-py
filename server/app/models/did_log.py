"""DID Log models."""

from typing import List, Union
from pydantic import Field
from .di_proof import DataIntegrityProof
from .did_document import DidDocument
from .base import CustomBaseModel


class WitnessSignature(CustomBaseModel):
    """WitnessSignature model."""

    versionId: str = Field()
    proof: List[DataIntegrityProof] = Field()


class LogEntry(CustomBaseModel):
    """LogEntry model."""

    class Parameters(CustomBaseModel):
        """LogParameters model."""

        class WitnessParam(CustomBaseModel):
            """WitnessParam model."""

            class Witness(CustomBaseModel):
                """Witness model."""

                id: str = Field()

            threshold: int = Field()
            witnesses: List[Witness] = Field()

        method: str = Field(None)
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
