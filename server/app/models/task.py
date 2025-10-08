"""DB Storage Tags models."""

from pydantic import Field

from .base import CustomBaseModel


class TaskInstance(CustomBaseModel):
    """Tags for log entry model."""

    id: str = Field()
    type: str = Field()
    created: str = Field()
    updated: str = Field()
    status: str = Field()
    message: str = Field(None)
    progress: dict = Field()
