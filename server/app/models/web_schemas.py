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

    id: str = Field()
    label: str = Field()
    invitationUrl: str = Field(None)


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
