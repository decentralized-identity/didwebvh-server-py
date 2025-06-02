"""This module defines the Presentation model used for whois.vp."""

from typing import Any, Dict, List, Union

from pydantic import BaseModel, Field, field_validator
from .di_proof import DataIntegrityProof


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class VerifiableCredential(BaseModel):
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


class EnvelopedVerifiableCredential(BaseModel):
    """VerifiableCredential model."""

    context: List[str] = Field(alias="@context")
    id: str = Field()
    type: Union[List[str], str] = Field()


class VerifiablePresentation(BaseModel):
    """VerifiablePresentation model."""

    context: List[str] = Field(alias="@context")
    id: str = Field(None)
    type: Union[List[str], str] = Field()

    holder: Union[Dict[str, str], str] = Field(None)

    verifiableCredential: List[Union[VerifiableCredential, EnvelopedVerifiableCredential]] = Field(
        None
    )

    proof: Union[List[DataIntegrityProof], DataIntegrityProof] = Field()
