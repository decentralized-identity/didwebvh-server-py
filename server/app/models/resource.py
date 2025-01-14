from typing import Dict, Any, List, Union
from pydantic import BaseModel, Field, field_validator
from app.models.di_proof import DataIntegrityProof
from config import settings

class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)

class RelatedResource(BaseModel):
    id: str = Field()
    type: str = Field()
    digestMultibase: str = Field()

class AttestedResource(BaseModel):
    context: List[str] = Field(
        alias='@context',
        default=[
            f'https://{settings.DOMAIN}/attested-resource/v1',
            'https://w3id.org/security/data-integrity/v2'
        ]
    )
    type: List[str] = Field(default=['AttestedResource'])
    id: str = Field()
    resourceInfo: dict = Field()
    resourceContent: dict = Field()
    relatedResource: Union[RelatedResource, List[RelatedResource]] = Field(None)
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field(None)
