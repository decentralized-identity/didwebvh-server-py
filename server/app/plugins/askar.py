"""Askar plugin for verifying cryptographic proofs."""

import json
import logging
from datetime import datetime, timezone
from hashlib import sha256

import base64
import canonicaljson
from aries_askar import Key
from aries_askar.bindings import LocalKeyHandle
from fastapi import HTTPException
from multiformats import multibase

logger = logging.getLogger(__name__)


class AskarVerifier:
    """Askar verifier plugin."""

    def __init__(self):
        """Initialize the Askar verifier plugin."""
        self.type = "DataIntegrityProof"
        self.cryptosuite = "eddsa-jcs-2022"
        self.purpose = "assertionMethod"

    def validate_proof(self, proof):
        """Validate the proof."""
        try:
            if proof.get("expires"):
                assert datetime.fromisoformat(proof["expires"]) > datetime.now(timezone.utc), (
                    "Proof expired."
                )
            assert proof["type"] == self.type, f"Expected {self.type} proof type."
            assert proof["cryptosuite"] == self.cryptosuite, (
                f"Expected {self.cryptosuite} proof cryptosuite."
            )
            assert proof["proofPurpose"] == self.purpose, f"Expected {self.purpose} proof purpose."
        except AssertionError as msg:
            raise HTTPException(status_code=400, detail=str(msg))

    def verify_resource_proof(self, resource, controller_document):
        """Verify the proof."""
        proof = resource.pop("proof")
        if (
            proof.get("type") != self.type
            or proof.get("cryptosuite") != self.cryptosuite
            or proof.get("proofPurpose") != self.purpose
        ):
            raise HTTPException(status_code=400, detail="Invalid proof options")

        multikey = next(
            (
                vm["publicKeyMultibase"]
                for vm in controller_document["verificationMethod"]
                if vm["id"] == proof.get("verificationMethod")
            ),
            None,
        )
        key = Key(LocalKeyHandle()).from_public_bytes(
            alg="ed25519", public=bytes(bytearray(multibase.decode(multikey))[2:])
        )
        signature = multibase.decode(proof.pop("proofValue"))
        hash_data = (
            sha256(canonicaljson.encode_canonical_json(proof)).digest()
            + sha256(canonicaljson.encode_canonical_json(resource)).digest()
        )
        if not key.verify_signature(message=hash_data, signature=signature):
            raise HTTPException(status_code=400, detail="Signature was forged or corrupt.")

    def verify_proof(self, document, proof, multikey=None):
        """Verify the proof."""
        self.validate_proof(proof)

        multikey = multikey or proof["verificationMethod"].split("#")[-1]

        key = Key(LocalKeyHandle()).from_public_bytes(
            alg="ed25519", public=bytes(bytearray(multibase.decode(multikey))[2:])
        )

        proof_options = proof.copy()
        signature = multibase.decode(proof_options.pop("proofValue"))

        hash_data = (
            sha256(canonicaljson.encode_canonical_json(proof_options)).digest()
            + sha256(canonicaljson.encode_canonical_json(document)).digest()
        )
        try:
            if not key.verify_signature(message=hash_data, signature=signature):
                raise HTTPException(status_code=400, detail="Signature was forged or corrupt.")
            return True
        except Exception:
            raise HTTPException(status_code=400, detail="Error verifying proof.")

    def verify_jwt_signature(self, jwt_token: str, did_document: dict, expected_issuer: str):
        """Verify JWT signature for EnvelopedVerifiableCredential.

        Args:
            jwt_token: The JWT token (without data: prefix)
            did_document: The issuer's DID document
            expected_issuer: Expected issuer DID (for validation)

        Returns:
            dict: The decoded JWT payload

        Raises:
            HTTPException: If verification fails
        """

        try:
            parts = jwt_token.split(".")

            if len(parts) != 3:
                raise HTTPException(
                    status_code=400, detail="Invalid JWT format - must have 3 parts"
                )

            header_b64, payload_b64, signature_b64 = parts

            # Add padding for base64 decoding
            header_b64_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
            payload_b64_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            signature_b64_padded = signature_b64 + "=" * (4 - len(signature_b64) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_b64_padded))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64_padded))
            signature_bytes = base64.urlsafe_b64decode(signature_b64_padded)

            # Get verification method from JWT header (kid)
            verification_method_id = header.get("kid")
            if not verification_method_id:
                raise HTTPException(status_code=400, detail="JWT header missing 'kid' field")

            # Extract issuer DID from payload
            issuer = payload.get("issuer", {})
            issuer_did = issuer.get("id") if isinstance(issuer, dict) else issuer

            if not issuer_did:
                raise HTTPException(status_code=400, detail="Credential payload missing issuer")

            # Verify the issuer DID matches expected
            if not issuer_did.startswith("did:webvh:") or issuer_did != expected_issuer:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"Credential issuer ({issuer_did}) must match expected ({expected_issuer})"
                    ),
                )

            # Get the public key from the DID document
            verification_method = next(
                (
                    vm
                    for vm in did_document.get("verificationMethod", [])
                    if vm["id"] == verification_method_id
                ),
                None,
            )

            if not verification_method:
                raise HTTPException(
                    status_code=400,
                    detail=f"Verification method '{verification_method_id}' not found",
                )

            # Extract public key (multikey format)
            multikey = verification_method.get("publicKeyMultibase")
            if not multikey:
                raise HTTPException(
                    status_code=400, detail="Verification method missing publicKeyMultibase"
                )

            # Create Askar key from public key
            public_key_bytes = bytes(bytearray(multibase.decode(multikey))[2:])
            key = Key(LocalKeyHandle()).from_public_bytes(alg="ed25519", public=public_key_bytes)

            # Verify JWT signature (EdDSA signs the header.payload)
            message = f"{header_b64}.{payload_b64}".encode()

            if not key.verify_signature(message=message, signature=signature_bytes):
                raise HTTPException(status_code=400, detail="JWT signature verification failed")

            return payload

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"JWT verification failed: {str(e)}")
