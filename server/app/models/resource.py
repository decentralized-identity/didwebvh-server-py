"""Models for attested resource handling and routes."""

from typing import List, Union
from pydantic import Field
from app.models.di_proof import DataIntegrityProof
from config import settings
from .base import CustomBaseModel


class ResourceMetadata(CustomBaseModel):
    """ResourceMetadata Field."""

    resourceId: str = Field(None)
    resourceType: str = Field(None)
    resourceName: str = Field(None)
    resourceCollectionId: str = Field(None)


class RelatedLink(CustomBaseModel):
    """RelatedLink Field."""

    id: str = Field()
    type: str = Field()
    timestamp: int = Field(None)
    digestMultibase: str = Field(None)


class AttestedResource(CustomBaseModel):
    """AttestedResource Object."""

    context: List[str] = Field(
        alias="@context",
        default=[
            settings.ATTESTED_RESOURCE_CTX,
            "https://w3id.org/security/data-integrity/v2",
        ],
    )
    type: List[str] = Field(default=["AttestedResource"])
    id: str = Field()
    content: dict = Field()
    metadata: ResourceMetadata = Field(None)
    links: List[RelatedLink] = Field(None)
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field(None)
