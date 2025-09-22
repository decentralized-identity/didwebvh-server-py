"""DB Storage Tags models."""

from pydantic import Field

from .base import CustomBaseModel

class LogEntryTags(CustomBaseModel):
    """Tags for log entry model."""

    did: str = Field()
    scid: str = Field()
    domain: str = Field()
    namespace: str = Field()
    identifier: str = Field()
    created: str = Field()
    updated: str = Field()
    deactivated: str = Field()

class AttestedResourceTags(CustomBaseModel):
    """Tags for attested resource model."""
    
    did: str = Field()
    scid: str = Field()
    resource_id: str = Field()
    resource_type: str = Field()