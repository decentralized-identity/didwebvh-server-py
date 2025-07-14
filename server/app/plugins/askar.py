"""Askar plugin for storing and verifying data."""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256

import canonicaljson
from aries_askar import Key, Store
from aries_askar.bindings import LocalKeyHandle
from fastapi import HTTPException
from multiformats import multibase
from app.utilities import timestamp
from app.models.policy import (
    ActivePolicy,
)  # , KnownWitnessRegistry, RegistryMetadata, RegistryEntry

from config import settings


class AskarStorage:
    """Askar storage plugin."""

    def __init__(self):
        """Initialize the Askar storage plugin."""
        self.db = settings.ASKAR_DB

    async def provision(self, recreate=False):
        """Provision the Askar storage."""
        await Store.provision(self.db, "none", recreate=recreate)
        if not await self.fetch("registry", "knownWitnesses"):
            witness_registry = {
                "meta": {"created": timestamp(), "updated": timestamp()},
                "registry": {},
            }
            if settings.KNOWN_WITNESS_KEY:
                witness_did = f"did:key:{settings.KNOWN_WITNESS_KEY}"
                witness_registry["registry"][witness_did] = {"name": "Default Server Witness"}
            await self.store("registry", "knownWitnesses", witness_registry)

        if not await self.fetch("policy", "active"):
            policy = ActivePolicy(
                version=settings.WEBVH_VERSION,
                witness=settings.WEBVH_WITNESS,
                watcher=settings.WEBVH_WATCHER,
                portability=settings.WEBVH_PORTABILITY,
                prerotation=settings.WEBVH_PREROTATION,
                endorsement=settings.WEBVH_ENDORSEMENT,
                witness_registry_url=settings.KNOWN_WITNESS_REGISTRY,
            ).model_dump()
            await self.store("policy", "active", policy)

    async def open(self):
        """Open the Askar storage."""
        return await Store.open(self.db, "none")

    async def fetch(self, category, data_key):
        """Fetch data from the store."""
        store = await self.open()
        try:
            async with store.session() as session:
                data = await session.fetch(category, data_key)
            return json.loads(data.value)
        except Exception:
            logging.debug(f"Error fetching data {category}: {data_key}", exc_info=True)
            return None

    async def store(self, category, data_key, data, tags=None):
        """Store data in the store."""
        store = await self.open()
        try:
            async with store.session() as session:
                await session.insert(category, data_key, json.dumps(data), tags=tags)
        except Exception:
            logging.debug(f"Error storing data {category}: {data_key}", exc_info=True)
            raise HTTPException(status_code=404, detail="Couldn't store record.")

    async def update(self, category, data_key, data, tags=None):
        """Update data in the store."""
        store = await self.open()
        try:
            async with store.session() as session:
                await session.replace(category, data_key, json.dumps(data), tags=tags)
        except Exception:
            logging.debug(f"Error updating data {category}: {data_key}", exc_info=True)
            raise HTTPException(status_code=404, detail="Couldn't update record.")

    async def append(self, category, data_key, data, tags=None):
        """Append data in the store."""
        store = await self.open()
        try:
            async with store.session() as session:
                data_array = await session.fetch(category, data_key)
                data_array = json.loads(data_array.value)
                data_array = data_array.append(data)
                await session.replace(category, data_key, json.dumps(data), tags=tags)
        except Exception:
            logging.debug(f"Error fetching data {category}: {data_key}", exc_info=True)
            raise HTTPException(status_code=404, detail="Couldn't update record.")

    async def store_or_update(self, category, data_key, data):
        """Store or update data in the store."""
        (
            await self.update(category, data_key, data)
            if await self.fetch(category, data_key)
            else await self.store(category, data_key, data)
        )


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

    async def verify_resource_proof(self, resource):
        """Verify the proof."""
        proof = resource.pop("proof")
        if (
            proof.get("type") != self.type
            or proof.get("cryptosuite") != self.cryptosuite
            or proof.get("proofPurpose") != self.purpose
        ):
            raise HTTPException(status_code=400, detail="Invalid proof options")

        did = proof.get("verificationMethod").split("#")[0]
        namespace = did.split(":")[4]
        identifier = did.split(":")[5]
        profile_id = f"{namespace}:{identifier}"
        issuer_log = await AskarStorage().fetch("logEntries", profile_id)

        if not issuer_log:
            raise HTTPException(status_code=400, detail="Unknown controller")

        did_document = issuer_log[-1].get("state")
        multikey = next(
            (
                vm["publicKeyMultibase"]
                for vm in did_document["verificationMethod"]
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
