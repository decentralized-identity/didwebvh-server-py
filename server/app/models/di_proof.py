"""This module defines the DataIntegrityProof model used for data integrity proofs."""

from typing import Any, Dict

from pydantic import BaseModel, Field, field_validator


class BaseModel(BaseModel):
    """Base model for all models in the application."""

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Dump the model to a dictionary."""
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)


class DataIntegrityProof(BaseModel):
    """DataIntegrityProof model."""

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
        """Validate the type field."""
        assert value == "DataIntegrityProof"
        return value

    @field_validator("cryptosuite")
    @classmethod
    def validate_cryptosuite(cls, value):
        """Validate the cryptosuite field."""
        assert value in ["eddsa-jcs-2022"]
        return value

    @field_validator("proofPurpose")
    @classmethod
    def validate_proof_purpose(cls, value):
        """Validate the proofPurpose field."""
        assert value in ["assertionMethod", "authentication"]
        return value

    @field_validator("expires")
    @classmethod
    def validate_expires(cls, value):
        """Validate the expires field."""
        return value
