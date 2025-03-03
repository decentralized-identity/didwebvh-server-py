import jcs
from multiformats import multibase, multihash
from app.models.resource import AttestedResource, ResourceMetadata
from hashlib import sha256


def digest_multibase(content):
    return multibase.encode(multihash.digest(jcs.canonicalize(content), "sha2-256"), "base58btc")


def key_to_multikey(key):
    return multibase.encode(
        bytes.fromhex(f"ed01{key.get_public_bytes().hex()}"),
        "base58btc",
    )


def transform(document, options):
    return sha256(jcs.canonicalize(options)).digest() + sha256(jcs.canonicalize(document)).digest()


def create_attested_resource(content, resource_type, issuer_id):
    resource_digest = digest_multibase(content)
    resource_id = f"{issuer_id}/resources/{resource_digest}"

    attested_schema = AttestedResource(
        id=resource_id,
        content=content,
        metadata=ResourceMetadata(resourceId=resource_digest, resourceType=resource_type),
    ).model_dump()
