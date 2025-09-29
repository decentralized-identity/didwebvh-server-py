"""DB Storage Tags models."""

from pydantic import Field
from typing import List

from .base import CustomBaseModel


class DidRecordTags(CustomBaseModel):
    """Tags for log entry model."""

    did: str = Field()
    scid: str = Field()
    domain: str = Field()
    namespace: str = Field()
    identifier: str = Field()
    created: str = Field()
    updated: str = Field()
    deactivated: str = Field()


class DidRecord(DidRecordTags):
    """Did Record model."""

    logs: List[dict] = Field()
    witness_file: List[dict] = Field()
    whois_presentation: dict = Field()

    avatar: str = Field()
    active: bool = Field()
    witnesses: List[dict] = Field()
    watchers: List[str] = Field()

    class ResourceDetails(CustomBaseModel):
        """Resource details."""

        type: str = Field()
        digest: str = Field()
        details: dict = Field()

    resources: List[ResourceDetails] = Field()

    class DidLinks(CustomBaseModel):
        """Did related links."""

        resolver: str = Field()
        log_file: str = Field()
        witness_file: str = Field()
        resource_query: str = Field()
        whois_presentation: str = Field()

    links: DidLinks = Field()


class ResourceRecordTags(CustomBaseModel):
    """Tags for attested resource model."""

    did: str = Field()
    scid: str = Field()
    resource_id: str = Field()
    resource_type: str = Field()


class ResourceRecord(ResourceRecordTags):
    """Resource Record model."""

    attested_resource: dict = Field()
    details: dict = Field()
    url: str = Field()

    class ResourceAuthor(CustomBaseModel):
        """Resource author details."""

        avatar: str = Field()
        scid: str = Field()
        domain: str = Field()
        namespace: str = Field()
        alias: str = Field()

    author: ResourceAuthor = Field()
