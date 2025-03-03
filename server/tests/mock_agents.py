from aries_askar import Store, Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from multiformats import multibase
from hashlib import sha256
import jcs
from config import settings
from tests.fixtures import (
    TEST_WITNESS_SEED,
    TEST_UPDATE_SEED
)

DID_NAMESPACE = "test"
DID_IDENTIFIER = "01"

PROOF_OPTIONS = {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
}

def key_to_multikey(key):
    return multibase.encode(
        bytes.fromhex(
            f"ed01{key.get_public_bytes().hex()}"
        ),
        "base58btc",
    )
    
def sign(document, options, key):
    proof_bytes = key.key.sign_message((
        sha256(jcs.canonicalize(options)).digest()
        + sha256(jcs.canonicalize(document)).digest()
    ))
    document['proof'] = options | {'proofValue': multibase.encode(proof_bytes, "base58btc")}

class WitnessAgent:
    def __init__(self):
        self.key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_WITNESS_SEED)
        self.multikey = key_to_multikey(self.key)
        self.did_key = f'did:key:{self.multikey}'


class ControllerAgent:
    def __init__(self):
        self.key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_UPDATE_SEED)
        self.multikey = key_to_multikey(self.key)
        self.did_key = f'did:key:{self.multikey}'
        self.did_web = f'did:web:{settings.DOMAIN}:{DID_NAMESPACE}:{DID_IDENTIFIER}'