from typing import Dict, Any, List
from pydantic import BaseModel, Field, field_validator


class BaseModel(BaseModel):
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        return super().model_dump(by_alias=True, exclude_none=True, **kwargs)
    
class Schema(BaseModel):
    issuerId: str = Field()
    name: str = Field()
    version: str = Field()
    attrNames: List[str] = Field()
    
class SecuredSchema(Schema):
    proof: dict = Field()
    
class RevRegDefAccumKey(BaseModel):
    z: str = Field()
    
class RevRegDefPubKey(BaseModel):
    accumKey: RevRegDefAccumKey = Field()
    
class RevRegDefValue(BaseModel):
    publicKeys: RevRegDefPubKey = Field()
    maxCredNum: int = Field()
    tailsLocation: str = Field()
    tailsHash: str = Field()
    
class RevRegDef(BaseModel):
    issuerId: str = Field()
    revocDefType: str = Field("CL_ACCUM")
    credDefId: str = Field()
    tag: str = Field()
    value: RevRegDefValue = Field()

class CredDefRValue(BaseModel):
    link_secret: str = Field()

class CredDefPrimaryValue(BaseModel):
    n: str = Field()
    r: CredDefRValue = Field()
    rctxt: str = Field()
    s: str = Field()
    z: str = Field()
    
class CredDefValue(BaseModel):
    primary: CredDefPrimaryValue = Field()
    
class CredDef(BaseModel):
    issuerId: str = Field()
    schemaId: str = Field()
    type: str = Field("CL")
    tag: str = Field()
    value: CredDefValue = Field()
    
class SecuredCredDef(CredDef):
    proof: dict = Field()