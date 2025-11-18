"""Pydantic models for the web schemas."""

from typing import List, Union

from pydantic import Field
from .did_document import SecuredDidDocument
from .resource import AttestedResource
from .did_log import LogEntry, WitnessSignature
from .di_proof import DataIntegrityProof
from .presentation import (
    VerifiablePresentation,
    VerifiableCredential,
    EnvelopedVerifiableCredential,
)
from .base import CustomBaseModel


class AddWitness(CustomBaseModel):
    """AddWitness model."""

    id: str = Field(
        json_schema_extra={"example": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}
    )
    label: str = Field(None, json_schema_extra={"example": "Example Witness Service"})
    invitationUrl: str = Field(
        None,
        json_schema_extra={
            "example": "https://witness.example.com/oob-invite?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICJpbnYtZXhhbXBsZS0xMjMiLCAibGFiZWwiOiAiRXhhbXBsZSBXaXRuZXNzIFNlcnZpY2UiLCAiZ29hbF9jb2RlIjogIndpdG5lc3Mtc2VydmljZSIsICJzZXJ2aWNlcyI6IFt7ImlkIjogIiNpbmxpbmUiLCAidHlwZSI6ICJkaWQtY29tbXVuaWNhdGlvbiIsICJzZXJ2aWNlRW5kcG9pbnQiOiAiaHR0cHM6Ly93aXRuZXNzLmV4YW1wbGUuY29tL2FnZW50IiwgInJlY2lwaWVudEtleXMiOiBbImRpZDprZXk6ejZNa2hhWGdCWkR2b3REa0w1MjU3ZmFpenRpR2lDMlF0S0xHcGJubkVHdGEyZG9LI3JlY2lwaWVudCJdfV19"
        },
    )


class RegisterDID(CustomBaseModel):
    """RegisterDID model."""

    didDocument: SecuredDidDocument = Field()


class NewLogEntry(CustomBaseModel):
    """NewLogEntry model."""

    logEntry: LogEntry = Field()
    witnessSignature: Union[WitnessSignature, None] = Field(None)


class UpdateLogEntry(CustomBaseModel):
    """UpdateLogEntry model."""

    logEntry: LogEntry = Field()

    class WitnessProof(CustomBaseModel):
        """WitnessProof model."""

        versionId: str = Field()
        proof: List[DataIntegrityProof] = Field()

    witnessProof: WitnessProof = Field(None)


class DeactivateLogEntry(CustomBaseModel):
    """DeactivateLogEntry model."""

    logEntry: LogEntry = Field()
    witnessProof: WitnessSignature = Field()


class ResourceUploadDocument(CustomBaseModel):
    """ResourceUploadDocument model."""

    context: List[str] = Field(alias="@context")
    type: List[str] = Field()
    id: str = Field()
    resourceContent: dict = Field()
    resourceMetadata: dict = Field()
    relatedResource: List[dict] = Field(None)
    proof: dict = Field()


class ResourceOptions(CustomBaseModel):
    """ResourceOptions model."""

    resourceId: str = Field(None)
    resourceName: str = Field(None)
    resourceType: str = Field(None)
    resourceCollectionId: str = Field(None)


class ResourceTemplate(CustomBaseModel):
    """ResourceTemplate model."""

    resourceContent: dict = Field()
    options: ResourceOptions = Field()


class ResourceUpload(CustomBaseModel):
    """ResourceUpload model."""

    attestedResource: AttestedResource = Field()
    options: ResourceOptions = Field(None)


class WhoisUpdate(CustomBaseModel):
    """WhoisUpdate model."""

    verifiablePresentation: VerifiablePresentation = Field()


class CredentialOptions(CustomBaseModel):
    """CredentialOptions model."""

    credentialId: str = Field(None)


class CredentialUpload(CustomBaseModel):
    """CredentialUpload model."""

    verifiableCredential: Union[VerifiableCredential, EnvelopedVerifiableCredential] = Field()
    options: CredentialOptions = Field(None)


class OobService(CustomBaseModel):
    """Service entry inside a DIDComm OOB invitation."""

    id: str = Field()
    type: str = Field()
    serviceEndpoint: str = Field()
    recipientKeys: List[str] = Field(default_factory=list)
    routingKeys: List[str] = Field(default=None)


class OobInvitation(CustomBaseModel):
    """DIDComm Out-of-Band invitation with optional Data Integrity proof."""

    type: str = Field(alias="@type")
    id: str = Field(alias="@id")
    label: str = Field(default=None)
    goal_code: str = Field(default=None)
    goal: str = Field(default=None)
    services: List[OobService] = Field()
    proof: Union[List[DataIntegrityProof], DataIntegrityProof, None] = Field(default=None)
