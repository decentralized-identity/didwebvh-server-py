from typing import Union, List, Dict, Any
from pydantic import BaseModel, Field, field_validator
from .di_proof import DataIntegrityProof
from multiformats import multibase
from config import settings
import re
import validators


DID_WEB_REGEX = re.compile("did:web:((?:[a-zA-Z0-9._%-]*:)*[a-zA-Z0-9._%-]+)")

DID_WEB_ID_REGEX = re.compile(
    "did:web:((?:[a-zA-Z0-9._%-]*:)*[a-zA-Z0-9._%-]+)#([a-z0-9._%-]+)"
)


class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)



class JsonWebKey(BaseModel):
    kty: str = Field("OKP")
    crv: str = Field("Ed25519")
    x: str = Field()

class VerificationMethod(BaseModel):
    id: str = Field()
    type: Union[str, List[str]] = Field()
    controller: str = Field()
    publicKeyJwk: JsonWebKey = Field(None)
    publicKeyMultibase: str = Field(None)

    @field_validator("id")
    @classmethod
    def verification_method_id_validator(cls, value):
        assert value.startswith("did:")
        return value

    @field_validator("type")
    @classmethod
    def verification_method_type_validator(cls, value):
        assert value in [
            "Multikey",
            "JsonWebKey",
        ], "Expected type Multikey or JsonWebKey"
        return value

    @field_validator("controller")
    @classmethod
    def verification_method_controller_validator(cls, value):
        assert value.startswith("did:")
        return value

class Service(BaseModel):
    id: str = Field()
    type: Union[str, List[str]] = Field()
    serviceEndpoint: str = Field()

    @field_validator("id")
    @classmethod
    def service_id_validator(cls, value):
        assert value.startswith("did:")
        return value

    @field_validator("serviceEndpoint")
    @classmethod
    def service_endpoint_validator(cls, value):
        assert validators.url(value), f"Invalid service endpoint {value}."
        return value


class DidDocument(BaseModel):
    context: Union[str, List[str]] = Field(
        ["https://www.w3.org/ns/did/v1"],
        alias="@context",
    )
    id: str = Field()
    name: str = Field(None)
    description: str = Field(None)
    controller: str = Field(None)
    alsoKnownAs: List[str] = Field(None)
    verificationMethod: List[VerificationMethod] = Field(None)
    authentication: List[Union[str, VerificationMethod]] = Field(None)
    assertionMethod: List[Union[str, VerificationMethod]] = Field(None)
    keyAgreement: List[Union[str, VerificationMethod]] = Field(None)
    capabilityInvocation: List[Union[str, VerificationMethod]] = Field(None)
    capabilityDelegation: List[Union[str, VerificationMethod]] = Field(None)
    service: List[Service] = Field(None)
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field(None)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "@context": ["https://www.w3.org/ns/did/v1"],
                    "id": "",
                }
            ]
        }
    }

    @field_validator("context")
    @classmethod
    def context_validator(cls, value):
        assert value[0] == "https://www.w3.org/ns/did/v1", "Invalid context."
        return value

    @field_validator("id")
    @classmethod
    def id_validator(cls, value):
        assert value.startswith("did:")
        return value


class SecuredDidDocument(DidDocument):
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field()
