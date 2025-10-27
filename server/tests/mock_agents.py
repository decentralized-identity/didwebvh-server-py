from aries_askar import Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from multiformats import multibase
from hashlib import sha256
import canonicaljson
from tests.fixtures import TEST_WITNESS_SEED, TEST_SIGNING_SEED, TEST_UPDATE_SEED, TEST_DID
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
        self.id = f"did:key:{self.multikey}"
        self.key_id = f"{self.id}#{self.multikey}"
        self.proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
            "verificationMethod": self.key_id,
        }
        self.proof_digest = sha256(canonicaljson.encode_canonical_json(self.proof_options)).digest()

    def sign(self, document):
        document.pop("proof", None)
        document_digest = sha256(canonicaljson.encode_canonical_json(document)).digest()
        hash_data = self.proof_digest + document_digest
        proof_value = multibase.encode(self.key.sign_message(hash_data), "base58btc")
        document["proof"] = [self.proof_options | {"proofValue": proof_value}]
        return document

    def create_log_entry_proof(self, log_entry):
        witness_proof = self.sign({"versionId": log_entry.get("versionId")})
        return witness_proof


class ControllerAgent:
    def __init__(self):
        self.issuer_id = TEST_DID
        self.update_key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_UPDATE_SEED)
        self.update_multikey = key_to_multikey(self.update_key)
        self.signing_key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_SIGNING_SEED)
        self.signing_multikey = key_to_multikey(self.signing_key)  # Fixed: was using update_key
        self.signing_key_id = f"{self.issuer_id}#{self.signing_multikey}"
        self.verification_method = None

    def sign_log(self, document):
        options = PROOF_OPTIONS | {
            "verificationMethod": f"did:key:{self.update_multikey}#{self.update_multikey}"
        }
        proof = options | {
            "proofValue": multibase.encode(
                self.update_key.sign_message(transform(document, options)), "base58btc"
            )
        }
        return document | {"proof": proof}

    def sign(self, document):
        options = PROOF_OPTIONS | {"verificationMethod": self.signing_key_id}
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
