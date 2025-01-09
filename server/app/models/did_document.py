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


class VerificationMethod(BaseModel):
    id: str = Field()
    type: Union[str, List[str]] = Field()
    controller: str = Field()

    @field_validator("id")
    @classmethod
    def verification_method_id_validator(cls, value):
        assert value.startswith(f"did:web:{settings.DOMAIN}")
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
        assert DID_WEB_REGEX.match(value), "Expected controller to be a DID."
        assert value.startswith(f"did:web:{settings.DOMAIN}")
        return value


class JsonWebKey(BaseModel):
    kty: str = Field("OKP")
    crv: str = Field("Ed25519")
    x: str = Field()


class VerificationMethodJwk(VerificationMethod):
    publicKeyJwk: JsonWebKey = Field()

    @field_validator("publicKeyJwk")
    @classmethod
    def verification_method_public_key_validator(cls, value):
        # TODO decode b64
        return value


class VerificationMethodMultikey(VerificationMethod):
    publicKeyMultibase: str = Field()

    @field_validator("publicKeyMultibase")
    @classmethod
    def verification_method_public_key_validator(cls, value):
        try:
            multibase.decode(value)
        except:
            assert False, f"Unable to decode public key multibase value {value}"
        return value


class Service(BaseModel):
    id: str = Field()
    type: Union[str, List[str]] = Field()
    serviceEndpoint: str = Field()

    @field_validator("id")
    @classmethod
    def service_id_validator(cls, value):
        assert value.startswith(f"did:web:{settings.DOMAIN}")
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
    verificationMethod: List[
        Union[VerificationMethodMultikey, VerificationMethodJwk]
    ] = Field(None)
    authentication: List[Union[str, VerificationMethod]] = Field(None)
    assertionMethod: List[Union[str, VerificationMethod]] = Field(None)
    keyAgreement: List[Union[str, VerificationMethod]] = Field(None)
    capabilityInvocation: List[Union[str, VerificationMethod]] = Field(None)
    capabilityDelegation: List[Union[str, VerificationMethod]] = Field(None)
    service: List[Service] = Field(None)
    
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
        assert DID_WEB_REGEX.match(value), "Expected id to be a DID."
        return value


class SecuredDidDocument(DidDocument):
    proof: Union[DataIntegrityProof, List[DataIntegrityProof]] = Field()
