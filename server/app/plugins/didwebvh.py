"""DID Web Verifiable History (DID WebVH) plugin."""

from fastapi import HTTPException
from config import settings
import requests
from multiformats import multibase, multihash

from app.utilities import digest_multibase

# AskarStorage removed - using SQLAlchemy for all storage
import canonicaljson
from did_webvh.core.state import DocumentState, verify_state_proofs
from did_webvh.core.witness import verify_witness_proofs


class PolicyError(Exception):
    """Policy error."""

    pass


class DidWebVH:
    """DID Web Verifiable History (DID WebVH) plugin."""

    def __init__(self, active_policy=None, active_registry=None):
        """Initialize the DID WebVH plugin."""
        self.prefix = "did:webvh:"
        self.scid_placeholder = settings.SCID_PLACEHOLDER
        self.method_version = f"{self.prefix}{settings.WEBVH_VERSION}"
        self.did_string_base = f"{self.prefix}{settings.SCID_PLACEHOLDER}:{settings.DOMAIN}"
        self.active_policy = active_policy or {}
        self.known_witness_key = settings.WEBVH_WITNESS_ID
        self.known_witness_registry = active_registry or {}

        # Reserved namespaces from settings (single source of truth)
        self.reserved_namespaces = settings.RESERVED_NAMESPACES

    def placeholder_id(self, namespace, identifier):
        """Return placeholder id."""
        return f"did:webvh:{settings.SCID_PLACEHOLDER}:{settings.DOMAIN}:{namespace}:{identifier}"

    def get_document_state(self, log_entries, doc_state=None):
        """Return the latest document state."""
        for log_entry in log_entries:
            doc_state = DocumentState.load_history_line(log_entry, doc_state)
        return doc_state

    def verify_state_proofs(self, state, prev_state=None):
        """Return the latest document state."""
        verify_state_proofs(state, prev_state)

    def _generate_hash(self, scid_input):
        # https://identity.foundation/trustdidweb/#generate-scid
        jcs = canonicaljson.encode_canonical_json(scid_input)
        multihashed = multihash.digest(jcs, "sha2-256")
        encoded = multibase.encode(multihashed, "base58btc")[1:]
        return encoded

    def _find_witness_proof(self, proof_set, witness_id):
        return [
            proof
            for proof in proof_set
            if proof.get("verificationMethod").split("#")[0] == witness_id
        ]

    def verify_resource(self, secured_resource):
        """Verify resource."""
        proof = secured_resource.pop("proof")
        proof = proof if isinstance(proof, dict) else [proof]
        if (
            not proof.get("verificationMethod")
            or not proof.get("proofValue")
            or proof.get("type") != "DataIntegrityProof"
            or proof.get("cryptosuite") == "eddsa-jcs-2022"
            or proof.get("proofPurpose") == "assertionMethod"
        ):
            raise HTTPException(status_code=400, detail="Invalid proof options.")

    def validate_resource(self, resource):
        """Validate resource."""
        proof = resource.pop("proof")
        verification_method = proof.get("verificationMethod")
        did = verification_method.split("#")[0]

        provided_id = resource.get("id")

        content = resource.get("content")
        content_digest = digest_multibase(content)

        metadata = resource.get("metadata")

        if settings.DOMAIN != did.split(":")[3]:
            raise HTTPException(status_code=400, detail="Invalid resource id.")

        if did != provided_id.split("/")[0]:
            raise HTTPException(status_code=400, detail="Invalid resource id.")

        if content_digest != provided_id.split("/")[-1].split(".")[0]:
            raise HTTPException(status_code=400, detail="Invalid resource id.")

        if not metadata.get("resourceId") or content_digest != metadata.get("resourceId"):
            raise HTTPException(status_code=400, detail="Invalid resource id.")

        if not metadata.get("resourceType"):
            raise HTTPException(status_code=400, detail="Missing resource type.")

    def compare_resource(self, old_resource, new_resource):
        """Compare resource."""
        if old_resource.get("id") != new_resource.get("id"):
            raise HTTPException(status_code=400, detail="Invalid resource id.")
        if digest_multibase(old_resource.get("content")) != digest_multibase(
            new_resource.get("content")
        ):
            raise HTTPException(status_code=400, detail="Invalid resource content.")
        if digest_multibase(old_resource.get("metadata").get("resourceType")) != digest_multibase(
            new_resource.get("metadata").get("resourceType")
        ):
            raise HTTPException(status_code=400, detail="Invalid resource type.")
        if digest_multibase(
            old_resource.get("proof").get("verificationMethod").split("#")[0]
        ) != digest_multibase(new_resource.get("proof").get("verificationMethod").split("#")[0]):
            raise HTTPException(status_code=400, detail="Invalid verification method.")

    def resource_store_id(self, resource):
        """Generate resource id for storage."""
        resource_id = resource.get("id")
        did = resource_id.split("/")[0]
        namespace = did.split(":")[4]
        identifier = did.split(":")[5]
        content_digest = resource_id.split("/")[-1]
        return f"{namespace}:{identifier}:{content_digest}"

    def namespace_available(self, namespace):
        """Check if requested namespace is available."""
        return False if namespace in self.reserved_namespaces else True

    def load_known_witness_registry(self, registry):
        """Load known witness registry."""

        self.known_witness_registry = registry

        if self.known_witness_key:
            # WEBVH_WITNESS_ID is now a full did:key, not just the multikey
            witness_id = self.known_witness_key
            if not witness_id.startswith("did:key:"):
                raise ValueError(
                    f"WEBVH_WITNESS_ID must be a full did:key identifier, got: {witness_id}"
                )
            if witness_id not in self.known_witness_registry:
                self.known_witness_registry[witness_id] = {"name": "Default Server Witness"}

    def cache_known_witness_registry(self):
        """Cache known witness registry."""
        if self.active_policy.get("witness_registry_url"):
            response = requests.get(self.active_policy.get("witness_registry_url"))
            remote_registry = response.json().get("registry", {}) if response.ok else {}
            if remote_registry:
                self.known_witness_registry |= remote_registry

        invalid_entries = [
            witness_id
            for witness_id in list(self.known_witness_registry.keys())
            if not witness_id.startswith("did:key:")
        ]
        for witness_id in invalid_entries:
            self.known_witness_registry.pop(witness_id, None)

        return self.known_witness_registry

    def validate_known_witness(self, document_state, witness_signature):
        """Validate known witness."""
        # Check if witness is configured in parameters
        witness_config = document_state.params.get("witness")
        if not witness_config:
            raise PolicyError("No witness configured in parameters")

        witnesses = witness_config.get("witnesses", [])
        if not witnesses:
            raise PolicyError("No witnesses in configuration")

        witness_id = witnesses[0].get("id")
        if not witness_id:
            raise PolicyError("No witness ID found")

        if not self.known_witness_registry.get(witness_id, None):
            self.cache_known_witness_registry()
            if not self.known_witness_registry.get(witness_id, None):
                raise PolicyError(f"Unknown witness: {witness_id}")

        witness_proof = self._find_witness_proof(witness_signature.get("proof"), witness_id)

        if not witness_proof:
            raise PolicyError("No witness proof")

    async def check_witness(self, document_state, witness_signature=None):
        """Apply witness checks."""
        witness_file = []
        if document_state.witness_rule:
            if not isinstance(witness_signature, dict):
                raise PolicyError("Missing witness signature.")

            if witness_signature.get("versionId") != document_state.version_id:
                raise PolicyError("Witness versionId mismatch.")

            if not (await verify_witness_proofs([witness_signature]))[0]:
                raise PolicyError("Witness check failed.")

            witness_file.append(witness_signature)
        return witness_file

    async def create_did(self, log_entry, witness_signature=None):
        """Apply policies to DID creation."""

        document_state = self.get_document_state([log_entry])
        self.verify_state_proofs(document_state)

        if self.active_policy.get("witness"):
            self.validate_known_witness(document_state, witness_signature)

        log_entries = [document_state.history_line()]
        witness_file = await self.check_witness(document_state, witness_signature)

        return log_entries, witness_file

    async def update_did(
        self, log_entry, log_entries, witness_signature=None, prev_witness_file=None
    ):
        """Apply policies to DID updates."""
        prev_document_state = self.get_document_state(log_entries)
        if prev_document_state.params.get("deactivated"):
            raise PolicyError("DID is deactivated")

        document_state = self.get_document_state([log_entry], prev_document_state)
        self.verify_state_proofs(document_state, prev_document_state)

        if prev_document_state.next_key_hashes:
            document_state._check_key_rotation()

        if self.active_policy.get("witness"):
            self.validate_known_witness(document_state, witness_signature)

        if document_state.deactivated:
            self.deactivate_did()

        log_entries.append(document_state.history_line())
        witness_file = await self.check_witness(document_state, witness_signature)

        if prev_witness_file:
            witness_file += prev_witness_file

        return log_entries, witness_file

    def deactivate_did(self):
        """Apply policies to DID deactivation."""
        return

    def proof_options(self):
        """Create new proof options."""
        return {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
        }

    def parameters(self):
        """Create policy driven parameters."""

        server_parameter = {
            "scid": settings.SCID_PLACEHOLDER,
            "method": f"did:webvh:{settings.WEBVH_VERSION}",
            "updateKeys": [],
        }

        if self.active_policy.get("portability"):
            server_parameter["portable"] = True

        if self.active_policy.get("prerotation"):
            server_parameter["nextKeyHashes"] = []

        if self.active_policy.get("witness"):
            witnesses = []
            for witness_id, entry in (self.known_witness_registry or {}).items():
                witness_info = {"id": witness_id}
                witnesses.append(witness_info)

            server_parameter["witness"] = {
                "threshold": 1,
                "witnesses": witnesses,
            }

        if self.active_policy.get("watcher"):
            server_parameter["watchers"] = [self.active_policy.get("watcher")]

        return server_parameter
