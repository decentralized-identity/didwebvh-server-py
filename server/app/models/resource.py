from typing import Dict, Any, List, Union
from pydantic import BaseModel, Field, field_validator
from di_proof import DataIntegrityProof

class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)

class RelatedResource(BaseModel):
    id: str = Field()
    type: str = Field()
    digestMultibase: str = Field()

class AttestedResource(BaseModel):
    context: List[str] = Field(alias='@context')
    type: List[str] = Field(default=['AttestedResource'])
    id: str = Field()
    resourceInfo: dict = Field()
    resourceContent: dict = Field()
    relatedResource: Union[RelatedResource, List[RelatedResource]] = Field()
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field()
