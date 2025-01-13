from hashlib import sha256
import canonicaljson
from multiformats import multibase
from aries_askar import Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from tests.fixtures import TEST_SEED, TEST_PROOF_OPTIONS


def sign(document, options=TEST_PROOF_OPTIONS):
    key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_SEED)
    pub_key_multi = multibase.encode(
        bytes.fromhex(f"ed01{key.get_public_bytes().hex()}"),
        "base58btc",
    )
    options["verificationMethod"] = f"did:key:{pub_key_multi}#{pub_key_multi}"

    hash_data = (
        sha256(canonicaljson.encode_canonical_json(options)).digest()
        + sha256(canonicaljson.encode_canonical_json(document)).digest()
    )

    proof = options.copy()
    proof["proofValue"] = multibase.encode(key.sign_message(hash_data), "base58btc")

    return document | {"proof": proof}
