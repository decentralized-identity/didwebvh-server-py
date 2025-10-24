"""SQLAlchemy database models."""

from sqlalchemy import Column, String, Text, Boolean, Integer, DateTime, JSON, Index, ForeignKey
from sqlalchemy.sql import func

from .base import Base


# Type aliases for cleaner code (defined after classes below)
# These are forward references, actual assignments are at the end of this file


class DidControllerRecord(Base):
    """DID controller with all associated data."""

    __tablename__ = "did_controllers"

    # Primary key
    scid = Column(String(255), primary_key=True, index=True)

    # DID information
    did = Column(String(500), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    namespace = Column(String(255), nullable=False, index=True)
    alias = Column(String(255), nullable=False, index=True)

    # Status
    deactivated = Column(Boolean, default=False, index=True, nullable=False)

    # Log file (list of log entries)
    logs = Column(JSON, nullable=False)

    # Witness file
    witness_file = Column(JSON, nullable=True)

    # WHOIS presentation
    whois_presentation = Column(JSON, nullable=True)

    # WebVH state and parameters
    parameters = Column(JSON, nullable=False)
    document = Column(JSON, nullable=False)

    # Metadata
    created = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Composite indexes for common query patterns
    __table_args__ = (
        Index("idx_controller_namespace_alias", "namespace", "alias"),
        Index("idx_controller_namespace_deactivated", "namespace", "deactivated"),
        Index("idx_controller_domain_deactivated", "domain", "deactivated"),
        Index("idx_controller_alias_deactivated", "alias", "deactivated"),
    )

    def __init__(
        self, logs: list, witness_file: list = None, whois_presentation: dict = None, **kwargs
    ):
        """Initialize DidControllerRecord from logs and associated data.

        All DID fields are derived from the document state in the logs.

        Args:
            logs: List of log entries
            witness_file: Optional witness file data
            whois_presentation: Optional whois presentation data
            **kwargs: Additional fields to override
        """
        from app.plugins import DidWebVH

        # Get document state from logs
        webvh = DidWebVH()
        state = webvh.get_document_state(logs)

        # Extract domain, namespace, alias from document_id
        # document_id format: did:webvh:{scid}:domain:namespace:alias
        did_parts = state.document_id.split(":")
        domain = did_parts[3] if len(did_parts) > 3 else ""
        namespace = did_parts[4] if len(did_parts) > 4 else ""
        alias = did_parts[5] if len(did_parts) > 5 else ""

        # Build the init data, only setting values not already in kwargs
        init_data = {
            "scid": state.scid,
            "did": state.document_id,
            "domain": domain,
            "namespace": namespace,
            "alias": alias,
            "deactivated": state.deactivated,
            "logs": logs,
            "witness_file": witness_file or [],
            "whois_presentation": whois_presentation or {},
            "parameters": state.params,  # Use computed params from state
            "document": state.document,  # Store the DID document
        }

        # Merge with kwargs, giving precedence to kwargs
        init_data.update(kwargs)

        # Call parent init
        super().__init__(**init_data)


class AttestedResourceRecord(Base):
    """Attested resources table."""

    __tablename__ = "attested_resources"

    # Primary key
    resource_id = Column(String(255), primary_key=True, index=True)

    # Relationships

    scid = Column(String(255), ForeignKey("did_controllers.scid"), primary_key=False)

    # Resource information
    resource_type = Column(String(100), nullable=False, index=True)
    resource_name = Column(String(255), nullable=False)

    # DID reference (denormalized for queries)
    did = Column(String(500), nullable=False, index=True)

    # Resource data
    attested_resource = Column(JSON, nullable=False)

    # MediaType
    media_type = Column(String(255), nullable=False, default="application/jsonld")

    # Composite indexes for common queries
    __table_args__ = (
        Index("idx_attested_scid_resource_type", "scid", "resource_type"),
        Index("idx_attested_did_resource_type", "did", "resource_type"),
    )

    def __init__(self, attested_resource: dict, **kwargs):
        """Initialize AttestedResourceRecord from an attested_resource dict.

        All fields are derived from the attested_resource.
        """
        if not (full_resource_id := attested_resource.get("id", "")):
            raise ValueError("attested_resource must have an 'id' field")

        did = full_resource_id.split("/")[0]
        scid = did.split(":")[2]

        # Extract metadata - try both "metadata" and "resourceMetadata" keys
        resource_metadata = attested_resource.get("metadata")

        digest = full_resource_id.split("/")[-1].split(".")[0]

        # Validate against metadata.resourceId if present
        resource_id = resource_metadata.get("resourceId")
        if resource_id and resource_id != digest:
            raise ValueError(
                f"Mismatch: extracted resource_id '{resource_id}' from id does not match "
                f"metadata.resourceId '{resource_id}'"
            )

        # Call parent init with all fields
        super().__init__(
            resource_id=resource_id,
            scid=scid,
            resource_type=resource_metadata.get("resourceType", "AttestedResource"),
            resource_name=resource_metadata.get("resourceName", resource_id),
            did=did,
            attested_resource=attested_resource,
        )


class AdminBackgroundTask(Base):
    """Background tasks table."""

    __tablename__ = "admin_background_tasks"

    # Primary key
    task_id = Column(String(36), primary_key=True, index=True)

    # Task information
    task_type = Column(String(50), nullable=False, index=True)
    status = Column(String(20), nullable=False, index=True)

    # Task data
    progress = Column(JSON, default={})
    message = Column(Text)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Composite index
    __table_args__ = (Index("idx_task_type_status", "task_type", "status"),)

    def to_dict(self):
        """Convert task to dictionary format."""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "status": self.status,
            "progress": self.progress or {},
            "message": self.message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ServerPolicy(Base):
    """Server policies table."""

    __tablename__ = "server_policies"

    # Primary key
    policy_id = Column(String(50), primary_key=True)

    # Policy data
    version = Column(String(20))
    witness = Column(Boolean, default=False)
    watcher = Column(String(500))
    portability = Column(Boolean, default=False)
    prerotation = Column(Boolean, default=False)
    endorsement = Column(Boolean, default=False)
    validity = Column(Integer, default=0)
    witness_registry_url = Column(String(500))

    # Full policy as JSON (for extensibility)
    policy_data = Column(JSON)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def to_dict(self):
        """Convert policy to dictionary format."""
        return {
            "version": self.version,
            "witness": self.witness,
            "watcher": self.watcher,
            "portability": self.portability,
            "prerotation": self.prerotation,
            "endorsement": self.endorsement,
            "validity": self.validity,
            "witness_registry_url": self.witness_registry_url,
        }


class KnownWitnessRegistry(Base):
    """Registries table (e.g., known witnesses)."""

    __tablename__ = "known_witness_registries"

    # Primary key
    registry_id = Column(String(50), primary_key=True)

    # Registry data
    registry_type = Column(String(50), nullable=False, index=True)
    registry_data = Column(JSON, nullable=False)

    # Metadata
    meta = Column(JSON)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def to_dict(self):
        """Convert registry to dictionary format."""
        return {"registry": self.registry_data, "meta": self.meta or {}}


class TailsFile(Base):
    """AnonCreds revocation registry tails files."""

    __tablename__ = "tails_files"

    # Primary key - base58 encoded SHA256 hash of file
    tails_hash = Column(String(100), primary_key=True, index=True)

    # File content stored as hex string
    file_content_hex = Column(Text, nullable=False)

    # File size in bytes
    file_size = Column(Integer, nullable=False)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
