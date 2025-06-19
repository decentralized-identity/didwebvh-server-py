"""WebVH Server Policy."""

from typing import Any, Dict, Union
from pydantic import BaseModel, Field


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class ActivePolicy(BaseModel):
    """Model for server policies."""

    version: str = Field(None)
    witness: bool = Field(True)
    watcher: Union[str, None] = Field(None)
    portability: bool = Field(True)
    prerotation: bool = Field(True)
    endorsement: bool = Field(True)
    validity: int = Field(0)
    witness_registry_url: Union[str, None] = Field(None)


class KnownWitnessRegistry(BaseModel):
    """Model for witness registry."""

    class RegistryMetadata(BaseModel):
        """Model for witness registry metadata."""

        created: str = Field()
        updates: str = Field()

    class RegistryEntry(BaseModel):
        """Model for witness registry entry."""

        url: str = Field(None)
        name: str = Field(None)
        location: str = Field(None)

    meta: RegistryMetadata = Field()
    registry: Dict[str, RegistryEntry] = Field()
