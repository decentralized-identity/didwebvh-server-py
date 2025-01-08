from typing import Dict, Any
from pydantic import BaseModel, Field, field_validator


class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class DataIntegrityProof(BaseModel):
    type: str = Field("DataIntegrityProof")
    cryptosuite: str = Field("eddsa-jcs-2022")
    proofValue: str = Field()
    proofPurpose: str = Field("assertionMethod")
    verificationMethod: str = Field()
    domain: str = Field(None)
    challenge: str = Field(None)
    created: str = Field(None)
    expires: str = Field(None)
    
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "proofPurpose": "assertionMethod",
                    # "proofValue": "",
                    # "verificationMethod": "",
                }
            ]
        }
    }

    @field_validator("type")
    @classmethod
    def validate_type(cls, value):
        assert value == "DataIntegrityProof"
        return value

    @field_validator("cryptosuite")
    @classmethod
    def validate_cryptosuite(cls, value):
        assert value in ["eddsa-jcs-2022"]
        return value

    @field_validator("proofPurpose")
    @classmethod
    def validate_proof_purpose(cls, value):
        assert value in ["assertionMethod", "authentication"]
        return value

    @field_validator("expires")
    @classmethod
    def validate_expires(cls, value):
        return value
