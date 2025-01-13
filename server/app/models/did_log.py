from typing import Union, List, Dict, Any
from pydantic import BaseModel, Field
from .did_document import DidDocument
from .di_proof import DataIntegrityProof
from config import settings


class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class Witness(BaseModel):
    id: str = Field(None)
    weight: int = Field(None)


class WitnessParam(BaseModel):
    threshold: int = Field(None)
    selfWeight: int = Field(None)
    witnesses: List[Witness] = Field(None)


class WitnessSignature(BaseModel):
    versionId: str = Field(None)
    proof: List[DataIntegrityProof] = Field()


class InitialLogParameters(BaseModel):
    method: str = Field(f"did:webvh:{settings.WEBVH_VERSION}")
    scid: str = Field()
    updateKeys: List[str] = Field()
    prerotation: bool = Field(default=False)
    portable: bool = Field(default=False)
    deactivated: bool = Field(False)
    nextKeyHashes: List[str] = Field(None)


class LogParameters(BaseModel):
    prerotation: bool = Field(None)
    portable: bool = Field(None)
    updateKeys: List[str] = Field(None)
    nextKeyHashes: List[str] = Field(None)
    witness: WitnessParam = Field(None)
    deactivated: bool = Field(None)
    ttl: bool = Field(None)
    method: str = Field(None)
    scid: str = Field(None)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "method": "",
                    "scid": "",
                    "prerotation": True,
                    "portable": False,
                    "updateKeys": [],
                    "nextKeyHashes": [],
                }
            ]
        }
    }


class InitialLogEntry(BaseModel):
    versionId: str = Field()
    versionTime: str = Field()
    parameters: LogParameters = Field()
    state: dict = Field()
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field(None)


class LogEntry(BaseModel):
    versionId: str = Field()
    versionTime: str = Field()
    parameters: LogParameters = Field()
    state: DidDocument = Field()
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field(None)
