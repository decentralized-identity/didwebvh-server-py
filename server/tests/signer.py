from hashlib import sha256

import canonicaljson
from aries_askar import Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from tests.fixtures import TEST_REGISTRATION_SEED, TEST_PROOF_OPTIONS
from multiformats import multibase


def sign(document, options=TEST_PROOF_OPTIONS, verification_method=None):
    document.pop('proof', None)
    key = Key(LocalKeyHandle()).from_seed(KeyAlg.ED25519, TEST_REGISTRATION_SEED)
    if not verification_method:
        pub_key_multi = multibase.encode(
            bytes.fromhex(f"ed01{key.get_public_bytes().hex()}"),
            "base58btc",
        )
        verification_method = f"did:key:{pub_key_multi}#{pub_key_multi}"
    options["verificationMethod"] = verification_method
    hash_data = (
        sha256(canonicaljson.encode_canonical_json(options)).digest()
        + sha256(canonicaljson.encode_canonical_json(document)).digest()
    )

    proof = options.copy()
    proof["proofValue"] = multibase.encode(key.sign_message(hash_data), "base58btc")

    return document | {"proof": [proof]}


def verify(document, proof):
    multikey = proof["verificationMethod"].split("#")[-1]
    key = Key(LocalKeyHandle()).from_public_bytes(
        alg="ed25519", public=bytes(bytearray(multibase.decode(multikey))[2:])
    )
    signature = multibase.decode(proof.pop("proofValue"))
    hash_data = (
        sha256(canonicaljson.encode_canonical_json(proof)).digest()
        + sha256(canonicaljson.encode_canonical_json(document)).digest()
    )
    return key.verify_signature(message=hash_data, signature=signature)
