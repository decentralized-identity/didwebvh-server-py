from aries_askar import Store, Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from multiformats import multibase
from hashlib import sha256
import jcs
from config import settings
from tests.fixtures import TEST_WITNESS_SEED, TEST_SIGNING_SEED, TEST_UPDATE_SEED
from tests.utils import key_to_multikey, transform, digest_multibase
from app.models.resource import AttestedResource, ResourceMetadata

DID_NAMESPACE = "test"
DID_IDENTIFIER = "01"

PROOF_OPTIONS = {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
}


class WitnessAgent:
    def __init__(self):
        self.key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_WITNESS_SEED)
        self.multikey = key_to_multikey(self.key)
        self.did_key = f"did:key:{self.multikey}"


class ControllerAgent:
    def __init__(self):
        self.update_key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_UPDATE_SEED)
        self.update_multikey = key_to_multikey(self.update_key)
        self.signing_key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_SIGNING_SEED)
        self.signing_multikey = key_to_multikey(self.update_key)
        self.signing_key_id = "key-0"
        self.did_key = f"did:key:{self.update_multikey}"
        self.did_web = f"did:web:{settings.DOMAIN}:{DID_NAMESPACE}:{DID_IDENTIFIER}"
        self.issuer_id = None

    def sign_log(self, document):
        options = PROOF_OPTIONS | {"verificationMethod": f"{self.did_key}#{self.update_multikey}"}
        proof = options | {
            "proofValue": multibase.encode(
                self.update_key.sign_message(transform(document, options)), "base58btc"
            )
        }
        return document | {"proof": proof}

    def sign(self, document):
        options = PROOF_OPTIONS | {"verificationMethod": f"{self.issuer_id}#{self.signing_key_id}"}
        proof = options | {
            "proofValue": multibase.encode(
                self.signing_key.sign_message(transform(document, options)), "base58btc"
            )
        }
        return document | {"proof": proof}

    def attest_resource(self, content, resource_type):
        resource_digest = digest_multibase(content)
        resource_id = f"{self.issuer_id}/resources/{resource_digest}"

        return self.sign(
            AttestedResource(
                id=resource_id,
                content=content,
                metadata=ResourceMetadata(resourceId=resource_digest, resourceType=resource_type),
            ).model_dump()
        ), resource_id
