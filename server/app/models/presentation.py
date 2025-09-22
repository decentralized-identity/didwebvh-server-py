"""This module defines the Presentation model used for whois.vp."""

from typing import Any, Dict, List, Union
from pydantic import Field
from .di_proof import DataIntegrityProof
from .base import CustomBaseModel


class VerifiableCredential(CustomBaseModel):
    """VerifiableCredential model."""

    context: List[str] = Field(alias="@context")
    id: str = Field(None)
    type: Union[List[str], str] = Field()

    issuer: Union[Dict[str, str], str] = Field()

    validFrom: str = Field(None)
    validUntil: str = Field(None)

    credentialSubject: Union[List[dict], dict] = Field()

    credentialStatus: Union[List[dict], dict] = Field(None)
    credentialSchema: Union[List[dict], dict] = Field(None)

    renderMethod: Union[List[dict], dict] = Field(None)
    refreshMethod: Union[List[dict], dict] = Field(None)

    termsOfUse: Union[List[dict], dict] = Field(None)

    proof: Union[List[DataIntegrityProof], DataIntegrityProof] = Field()


class EnvelopedVerifiableCredential(CustomBaseModel):
    """VerifiableCredential model."""

    context: List[str] = Field(alias="@context")
    id: str = Field()
    type: Union[List[str], str] = Field()


class VerifiablePresentation(CustomBaseModel):
    """VerifiablePresentation model."""

    context: List[str] = Field(alias="@context")
    id: str = Field(None)
    type: Union[List[str], str] = Field()

    holder: Union[Dict[str, str], str] = Field(None)

    verifiableCredential: List[Union[VerifiableCredential, EnvelopedVerifiableCredential]] = Field(
        None
    )

    proof: Union[List[DataIntegrityProof], DataIntegrityProof] = Field()
