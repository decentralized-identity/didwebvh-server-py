"""Plugin for managing policies."""

import requests
from config import settings

from app.plugins import DidWebVH

webvh = DidWebVH()

class PolicyError(Exception):
    """Policy error."""
    pass
    

class PolicyModule:
    """Policy plugin."""

    def __init__(self):
        """Initialize the plugin."""
        
        # Reserved namespaces based on existing API routes
        self.reserved_namespaces = ["policy"]
        
        self.webvh_version: str = settings.WEBVH_VERSION
        self.webvh_witness: bool = settings.WEBVH_WITNESS
        self.webvh_watcher: str = settings.WEBVH_WATCHER
        self.webvh_portability: bool = settings.WEBVH_PORTABILITY
        self.webvh_prerotation: bool = settings.WEBVH_PREROTATION
        self.webvh_endorsement: bool = settings.WEBVH_ENDORSEMENT
        self.webvh_validity: int = settings.WEBVH_VALIDITY
        
        self.known_witness_key: str | None = settings.KNOWN_WITNESS_KEY
        self.known_witness_registry: dict = {}
        self.known_witness_registry_url: str | None = settings.KNOWN_WITNESS_REGISTRY

    def _find_witness_proof(self, proof_set, witness_id):
        return [
            proof for proof in proof_set 
            if proof.get('verificationMethod').split('#')[0] == witness_id
        ]

    def refresh_policy(self, policy):
        
        self.webvh_version: str = settings.WEBVH_VERSION
        self.webvh_witness: bool = settings.WEBVH_WITNESS
        self.webvh_watcher: str = settings.WEBVH_WATCHER
        self.webvh_portability: bool = settings.WEBVH_PORTABILITY
        self.webvh_prerotation: bool = settings.WEBVH_PREROTATION
        self.webvh_endorsement: bool = settings.WEBVH_ENDORSEMENT
        self.webvh_validity: int = settings.WEBVH_VALIDITY

    def load_known_witness_registry(self, registry):
        """Load known witness registry."""
        
        self.known_witness_registry = registry
        
        if self.known_witness_key:
            witness_id = f'did:key:{self.known_witness_key}'
            if witness_id not in self.known_witness_registry:
                self.known_witness_registry[witness_id] = {
                    'name': 'Default Server Witness'
                }

    def cache_known_witness_registry(self):
        """Cache known witness registry."""
        if self.known_witness_registry_url:
            r = requests.get(self.known_witness_registry_url)
            registry = r.json()
        
        for witness in registry.get('registry'):
            if not witness.startswith('did:key:'):
                raise PolicyError(f"Invalid witness registry: {self.known_witness_registry_url}")
            
        return self.known_witness_registry | registry.get('registry')
            
    def available_namespace(self, namespace):
        """Check if requested namespace is available."""
        return False if namespace in self.reserved_namespaces else True

    def validate_known_witness(self, document_state, witness_signature):
        """Validate known witness."""
        witness_id = document_state.params.get('witness').get('witnesses').get(0)
            
        if not witness_id:
            raise PolicyError("No witness")
        
        if witness_id not in self.known_witness_registry:
            self.cache_known_witness_registry()
            if witness_id not in self.known_witness_registry:
                raise PolicyError("Unknown witness")
        
        witness_proof = self._find_witness_proof(
            witness_signature.get('signatures'), 
            witness_id
        )
            
        if not witness_proof:
            raise PolicyError("No witness proof")
        

    def create_did(self, log_entry, witness_signature=None):
        """Apply policies to DID creation."""

        document_state = webvh.get_document_state([log_entry])
        webvh.verify_state_proofs(document_state)
        
        witness_rules = document_state.witness_rule
        # if self.webvh_witness:
        #     self.validate_known_witness(document_state, witness_signature)
            
        log_entries = [document_state.history_line()]
        witness_file = [witness_signature]
            
        return log_entries, witness_file

    def update_did(self, log_entry, log_entries, witness_signature=None, prev_witness_file=None):
        """Apply policies to DID updates."""
        prev_document_state = webvh.get_document_state(log_entries)
        if prev_document_state.params.get("deactivated"):
            raise PolicyError("DID is deactivated")
        
        document_state = webvh.get_document_state([log_entry], prev_document_state)
        webvh.verify_state_proofs(document_state)
        
        if prev_document_state.next_key_hashes:
            document_state._validate_key_rotation(
                prev_document_state.next_key_hashes, document_state.update_keys
            )
        
        witness_rules = prev_document_state.witness_rule
        # if self.webvh_witness:
        #     self.validate_known_witness(document_state, witness_signature)
            
        if document_state.deactivated:
            self.deactivate_did()
            
        log_entries.append(document_state.history_line())
        # witness_file = [prev_witness_file | witness_signature]
        witness_file = [witness_signature]
            
        return log_entries, witness_file

    def deactivate_did(self, log_entry, witness_signature=None):
        """Apply policies to DID deactivation."""
        return

    def proof_options(self):
        """Create new proof options."""
        return {
            'type': 'DataIntegrityProof',
            'cryptosuite': 'eddsa-jcs-2022',
            'proofPurpose': 'assertionMethod'
        }

    def parameters(self):
        """Create policy driven parameters."""
        server_parameter = {
            'scid': settings.SCID_PLACEHOLDER,
            'method': f'did:webvh:{self.webvh_version}',
            'portability': self.webvh_portability,
            'updateKeys': []
        }
        if self.webvh_prerotation:
            server_parameter['nextKeyHashes'] = []
        if self.webvh_witness:
            server_parameter['witness'] = {
                'threshold': 1,
                'witnesses': [{'id': witness} for witness in self.known_witness_registry]
            }
        if self.webvh_watcher:
            server_parameter['watchers'] = [self.webvh_watcher]
        return server_parameter

    # def check_attested_resource(self, attested_resource):
    #     """Validate a new attested resource."""
    #     proof_set = attested_resource.pop('proof')
    #     if self.resource_witness:
    #         witness_proof = next(
    #             (
    #                 proof
    #                 for proof in proof_set
    #                 if proof["verificationMethod"] != witness_proof["verificationMethod"]
    #             ),
    #             None,
    #         )
