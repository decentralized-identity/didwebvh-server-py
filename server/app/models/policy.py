"""WebVH Server Policy."""

from typing import Dict, Union
from pydantic import Field
from .base import CustomBaseModel


class ActivePolicy(CustomBaseModel):
    """Model for server policies."""

    version: str = Field(None)
    witness: bool = Field(True)
    watcher: Union[str, None] = Field(None)
    portability: bool = Field(True)
    prerotation: bool = Field(True)
    endorsement: bool = Field(True)
    validity: int = Field(0)
    witness_registry_url: Union[str, None] = Field(None)


class KnownWitnessRegistry(CustomBaseModel):
    """Model for witness registry."""

    class RegistryMetadata(CustomBaseModel):
        """Model for witness registry metadata."""

        created: str = Field()
        updates: str = Field()

    class RegistryEntry(CustomBaseModel):
        """Model for witness registry entry."""

        url: str = Field(None)
        name: str = Field(None)
        location: str = Field(None)
        serviceEndpoint: str = Field(None)

    meta: RegistryMetadata = Field()
    registry: Dict[str, RegistryEntry] = Field()
