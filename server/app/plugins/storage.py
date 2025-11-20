"""SQLAlchemy Storage Manager."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from config import settings
from app.db.base import Base
from app.db.models import (
    DidControllerRecord,
    AttestedResourceRecord,
    VerifiableCredentialRecord,
    AdminBackgroundTask,
    ServerPolicy,
    KnownWitnessRegistry,
    WitnessInvitation,
    TailsFile,
)
from app.plugins import DidWebVH
from app.utilities import extract_credential_metadata

logger = logging.getLogger(__name__)


class StorageManager:
    """SQLAlchemy-based storage manager for the DID WebVH server.

    Manages the database engine, sessions, and provides CRUD operations
    for all database entities including log entries, resources, tasks,
    policies, and registries.

    This class owns the database connection and session factory.
    """

    _instance = None
    _engine = None
    _SessionLocal = None

    def __new__(cls):
        """Singleton pattern to ensure single engine instance."""
        if cls._instance is None:
            cls._instance = super(StorageManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize the storage manager."""
        # Only initialize once
        if self._engine is not None:
            return

        self.db_url = settings.DATABASE_URL
        self.db_type = "sqlite" if "sqlite" in self.db_url else "postgres"

        # Create engine with appropriate settings
        if self.db_type == "sqlite":
            # SQLite specific configuration
            self._engine = create_engine(
                self.db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                echo=False,
            )
        elif self.db_type == "postgres":
            # PostgreSQL configuration
            self._engine = create_engine(
                self.db_url, pool_pre_ping=True, pool_size=10, max_overflow=20, echo=False
            )
        else:
            raise ValueError(f"Invalid database type: {self.db_type}")

        # Create session factory
        self._SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self._engine)

        logger.info(f"StorageManager initialized with {self.db_type} database")

    @property
    def engine(self):
        """Get the SQLAlchemy engine."""
        return self._engine

    @property
    def SessionLocal(self):
        """Get the session factory."""
        return self._SessionLocal

    async def provision(self, recreate: bool = False):
        """Provision the database schema.

        Similar to AskarStorage.provision(), this creates all database tables.

        Args:
            recreate: If True, drop all tables before creating them (useful for tests)
        """
        logger.info("DB provisioning started.")
        try:
            if recreate:
                logger.info("Dropping all existing tables...")
                Base.metadata.drop_all(bind=self._engine)
                logger.info("All tables dropped.")

            logger.info("Creating database tables...")
            Base.metadata.create_all(bind=self._engine, checkfirst=True)
            logger.info("DB provisioning finished.")
        except Exception as e:
            logger.error(f"DB provisioning failed: {str(e)}")
            raise Exception(f"DB provisioning failed: {str(e)}")

    def init_db(self):
        """Initialize the database schema (sync version of provision).

        This is a synchronous wrapper around provision for convenience.
        Use provision() for async contexts.
        """
        asyncio.run(self.provision())

    def get_session(self) -> Session:
        """Get a new database session.

        Returns:
            Session: SQLAlchemy database session
        """
        return self._SessionLocal()

    def get_db(self):
        """Dependency injection helper for FastAPI endpoints.

        Yields:
            Session: SQLAlchemy database session

        Example:
            @router.get("/items")
            async def get_items(db: Session = Depends(StorageManager().get_db)):
                items = db.query(Item).all()
                return items
        """
        db = self.get_session()
        try:
            yield db
        finally:
            db.close()

    def _create_and_commit(self, session: Session, obj) -> Any:
        """Helper method to add, commit, and refresh a new object.

        Args:
            session: SQLAlchemy session
            obj: The object to add and commit

        Returns:
            The committed and refreshed object
        """
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    def _create_with_session(self, obj) -> Any:
        """Helper method to create an object with automatic session management.

        Args:
            obj: The object to create and commit

        Returns:
            The committed and refreshed object
        """
        with self.get_session() as session:
            return self._create_and_commit(session, obj)

    def _commit_and_refresh(self, session: Session, obj) -> Any:
        """Helper method to commit and refresh an existing object.

        Args:
            session: SQLAlchemy session
            obj: The object to commit and refresh

        Returns:
            The committed and refreshed object
        """
        session.commit()
        session.refresh(obj)
        return obj

    def _get_by_field(self, model_class, field_name: str, field_value: Any) -> Optional[Any]:
        """Helper method to get a record by a single field value.

        Args:
            model_class: The SQLAlchemy model class
            field_name: Name of the field to filter by
            field_value: Value to filter by

        Returns:
            The first matching record or None
        """
        with self.get_session() as session:
            field = getattr(model_class, field_name)
            return session.query(model_class).filter(field == field_value).first()

    # ========== DID Controller Operations ==========

    def create_did_controller(
        self,
        logs: List[Dict],
        witness_file: Optional[List[Dict]] = None,
        whois_presentation: Optional[Dict] = None,
    ) -> DidControllerRecord:
        """Create a new DID controller record - extracts all data from logs.

        Args:
            logs: Log entries (required - contains all DID info)
            witness_file: Optional witness file
            whois_presentation: Optional WHOIS presentation

        Returns:
            DidControllerRecord: The created record
        """

        session = self.get_session()
        try:
            # Create controller - let the model's __init__ derive all fields from logs
            controller = DidControllerRecord(
                logs=logs, witness_file=witness_file, whois_presentation=whois_presentation
            )
            controller = self._create_and_commit(session, controller)
            logger.info(f"Successfully committed DID controller {controller.scid} to database")
            return controller
        except Exception as e:
            logger.error(f"Error creating DID controller: {e}", exc_info=True)
            session.rollback()
            raise
        finally:
            session.close()

    def update_did_controller(
        self,
        scid: str,
        logs: Optional[List[Dict]] = None,
        witness_file: Optional[List[Dict]] = None,
        whois_presentation: Optional[Dict] = None,
    ) -> Optional[DidControllerRecord]:
        """Update an existing DID controller record - re-extracts data from logs if provided.

        Args:
            scid: The SCID of the controller to update
            logs: Optional new log entries (if provided, re-extracts state/parameters/deactivated)
            witness_file: Optional witness file
            whois_presentation: Optional WHOIS presentation

        Returns:
            Optional[DidControllerRecord]: The updated record or None if not found
        """
        with self.get_session() as session:
            controller = (
                session.query(DidControllerRecord).filter(DidControllerRecord.scid == scid).first()
            )
            if controller:
                # Update logs and re-extract derived data
                if logs is not None:
                    controller.logs = logs

                    # Re-extract state and parameters from updated logs
                    webvh = DidWebVH()
                    state = webvh.get_document_state(logs)
                    params = state.params if hasattr(state, "params") else state.parameters

                    controller.parameters = params
                    controller.document = (
                        state.document
                        if isinstance(state.document, dict)
                        else state.document.model_dump()
                        if hasattr(state.document, "model_dump")
                        else dict(state.document)
                    )
                    controller.deactivated = params.get("deactivated", False) if params else False

                # Update optional fields
                if witness_file is not None:
                    controller.witness_file = witness_file
                if whois_presentation is not None:
                    controller.whois_presentation = whois_presentation

                if logs is not None or witness_file is not None or whois_presentation is not None:
                    controller = self._commit_and_refresh(session, controller)
            return controller

    def _apply_did_controller_filters(self, query, filters: Dict[str, Any]):
        """Apply filters to a DID controller query."""
        if "scid" in filters:
            query = query.filter(DidControllerRecord.scid == filters["scid"])
        if "did" in filters:
            query = query.filter(DidControllerRecord.did == filters["did"])
        if "domain" in filters:
            query = query.filter(DidControllerRecord.domain == filters["domain"])
        if "namespace" in filters:
            query = query.filter(DidControllerRecord.namespace == filters["namespace"])
        if "alias" in filters:
            query = query.filter(DidControllerRecord.alias == filters["alias"])
        if "deactivated" in filters:
            query = query.filter(DidControllerRecord.deactivated == filters["deactivated"])
        return query

    def get_did_controllers(
        self, filters: Optional[Dict[str, Any]] = None, limit: Optional[int] = None, offset: int = 0
    ) -> List[DidControllerRecord]:
        """Get DID controllers with optional filters and pagination."""
        with self.get_session() as session:
            query = session.query(DidControllerRecord)

            if filters:
                query = self._apply_did_controller_filters(query, filters)

            if limit is not None:
                query = query.offset(offset).limit(limit)

            return query.all()

    def count_did_controllers(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count DID controllers with optional filters."""
        with self.get_session() as session:
            query = session.query(DidControllerRecord)

            if filters:
                query = self._apply_did_controller_filters(query, filters)

            return query.count()

    # ========== Resource Operations ==========

    def create_resource(self, scid: str, attested_resource: Dict) -> AttestedResourceRecord:
        """Create a new resource - extracts metadata from attested_resource.

        Args:
            scid: The SCID from the parent DidControllerRecord (FK relationship)
            attested_resource: The full attested resource object

        Returns:
            AttestedResourceRecord: The created record
        """
        # The model's __init__ will extract all fields from attested_resource
        # Pass scid as kwarg to ensure FK relationship is correct (overrides extracted value)
        resource = AttestedResourceRecord(attested_resource=attested_resource, scid=scid)
        return self._create_with_session(resource)

    def get_resource(self, resource_id: str) -> Optional[AttestedResourceRecord]:
        """Get a resource by ID."""
        return self._get_by_field(AttestedResourceRecord, "resource_id", resource_id)

    def _apply_resource_filters(self, query, filters: Dict[str, Any]):
        """Apply filters to a resource query, including conditional join for namespace/alias."""
        # Only join when we need to filter by namespace or alias
        needs_join = (filters.get("namespace") and filters["namespace"]) or (
            filters.get("alias") and filters["alias"]
        )
        if needs_join:
            query = query.join(
                DidControllerRecord, AttestedResourceRecord.scid == DidControllerRecord.scid
            )

        # Filter by namespace (via join)
        if "namespace" in filters and filters["namespace"]:
            query = query.filter(DidControllerRecord.namespace == filters["namespace"])
        # Filter by alias (via join)
        if "alias" in filters and filters["alias"]:
            query = query.filter(DidControllerRecord.alias == filters["alias"])
        # Filter by scids (list) - supports single or multiple scids
        if "scids" in filters and filters["scids"]:
            query = query.filter(AttestedResourceRecord.scid.in_(filters["scids"]))
        if "did" in filters and filters["did"]:
            query = query.filter(AttestedResourceRecord.did == filters["did"])
        if "resource_type" in filters and filters["resource_type"]:
            query = query.filter(AttestedResourceRecord.resource_type == filters["resource_type"])
        if "resource_id" in filters and filters["resource_id"]:
            query = query.filter(AttestedResourceRecord.resource_id == filters["resource_id"])

        return query

    def get_resources(
        self, filters: Optional[Dict[str, Any]] = None, limit: Optional[int] = None, offset: int = 0
    ) -> List[AttestedResourceRecord]:
        """Get resources with optional filters and pagination."""
        with self.get_session() as session:
            query = session.query(AttestedResourceRecord)

            if filters:
                query = self._apply_resource_filters(query, filters)

            if limit is not None:
                query = query.offset(offset).limit(limit)

            return query.all()

    def get_resources_witnessed_by(self, witness_did: str) -> List[AttestedResourceRecord]:
        """Return resources that contain proofs signed by the specified witness DID."""
        with self.get_session() as session:
            resources = session.query(AttestedResourceRecord).all()

        witnessed_resources: List[AttestedResourceRecord] = []
        for resource in resources:
            proofs = resource.attested_resource.get("proof")
            if not proofs:
                continue

            if isinstance(proofs, dict):
                iterable = [proofs]
            elif isinstance(proofs, list):
                iterable = proofs
            else:
                continue

            for proof in iterable:
                verification_method = proof.get("verificationMethod", "")
                if verification_method and verification_method.split("#")[0] == witness_did:
                    witnessed_resources.append(resource)
                    break

        return witnessed_resources

    def count_resources(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count resources with optional filters."""
        with self.get_session() as session:
            query = session.query(AttestedResourceRecord)

            if filters:
                query = self._apply_resource_filters(query, filters)

            return query.count()

    def update_resource(self, attested_resource: Dict) -> Optional[AttestedResourceRecord]:
        """Update an existing resource - extracts resource_id from attested_resource.

        Args:
            attested_resource: The full attested resource object

        Returns:
            Optional[AttestedResourceRecord]: The updated record or None if not found
        """
        with self.get_session() as session:
            # Extract resource_id from metadata
            resource_id = attested_resource.get("metadata", {}).get("resourceId")

            resource = (
                session.query(AttestedResourceRecord)
                .filter(AttestedResourceRecord.resource_id == resource_id)
                .first()
            )
            if resource:
                resource.attested_resource = attested_resource
                resource = self._commit_and_refresh(session, resource)
            return resource

    def delete_resource(self, resource_id: str) -> bool:
        """Delete a resource."""
        with self.get_session() as session:
            resource = (
                session.query(AttestedResourceRecord)
                .filter(AttestedResourceRecord.resource_id == resource_id)
                .first()
            )
            if resource:
                session.delete(resource)
                session.commit()
                return True
            return False

    # ========== Credential Operations ==========

    def create_credential(  # noqa: C901
        self,
        scid: str,
        verifiable_credential: Dict,
        custom_id: Optional[str] = None,
        verified: bool = True,
        verification_method: Optional[str] = None,
    ) -> VerifiableCredentialRecord:
        """Create a new credential.

        Args:
            scid: The SCID from the parent DidControllerRecord (FK relationship)
            verifiable_credential: The full verifiable credential object
            custom_id: Optional custom credential ID (overrides verifiable_credential.id)
            verified: Whether the credential has been verified (defaults to True)
            verification_method: Verification method ID used (e.g., did:webvh:...#key-1)

        Returns:
            VerifiableCredentialRecord: The created record
        """
        with self.get_session() as session:
            # Extract metadata from credential (handles both enveloped and regular)
            try:
                metadata = extract_credential_metadata(verifiable_credential, custom_id)
            except Exception as e:
                logger.error(f"Failed to extract credential metadata: {e}")
                raise

            # Create credential record
            credential = VerifiableCredentialRecord(
                credential_id=metadata["credential_id"],
                scid=scid,
                issuer_did=metadata["issuer_did"],
                credential_type=metadata["credential_type"],
                subject_id=metadata["subject_id"],
                verifiable_credential=verifiable_credential,
                valid_from=metadata["valid_from"],
                valid_until=metadata["valid_until"],
                verified=verified,
                verification_method=verification_method,
            )
            return self._create_and_commit(session, credential)

    def get_credential(self, credential_id: str) -> Optional[VerifiableCredentialRecord]:
        """Get a credential by ID."""
        return self._get_by_field(VerifiableCredentialRecord, "credential_id", credential_id)

    def _apply_credential_filters(self, query, filters: Dict[str, Any]):
        """Apply filters to a credential query."""
        if "scid" in filters:
            query = query.filter(VerifiableCredentialRecord.scid == filters["scid"])
        if "issuer_did" in filters:
            query = query.filter(VerifiableCredentialRecord.issuer_did == filters["issuer_did"])
        if "subject_id" in filters:
            query = query.filter(VerifiableCredentialRecord.subject_id == filters["subject_id"])
        if "credential_id" in filters:
            query = query.filter(
                VerifiableCredentialRecord.credential_id == filters["credential_id"]
            )
        if "revoked" in filters:
            query = query.filter(VerifiableCredentialRecord.revoked == filters["revoked"])
        return query

    def get_credentials(
        self, filters: Optional[Dict[str, Any]] = None, limit: Optional[int] = None, offset: int = 0
    ) -> List[VerifiableCredentialRecord]:
        """Get credentials with optional filters and pagination."""
        with self.get_session() as session:
            query = session.query(VerifiableCredentialRecord)

            if filters:
                query = self._apply_credential_filters(query, filters)

            if limit is not None:
                query = query.offset(offset).limit(limit)

            return query.all()

    def count_credentials(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count credentials with optional filters."""
        with self.get_session() as session:
            query = session.query(VerifiableCredentialRecord)

            if filters:
                query = self._apply_credential_filters(query, filters)

            return query.count()

    def update_credential(
        self,
        credential_id: str,
        verifiable_credential: Dict,
        verification_method: Optional[str] = None,
    ) -> Optional[VerifiableCredentialRecord]:
        """Update an existing credential.

        Args:
            credential_id: The storage credential ID (simple ID used for lookups)
            verifiable_credential: The full verifiable credential object
            verification_method: Updated verification method ID

        Returns:
            Optional[VerifiableCredentialRecord]: The updated record or None if not found
        """
        with self.get_session() as session:
            credential = (
                session.query(VerifiableCredentialRecord)
                .filter(VerifiableCredentialRecord.credential_id == credential_id)
                .first()
            )
            if credential:
                credential.verifiable_credential = verifiable_credential
                if verification_method:
                    credential.verification_method = verification_method
                credential.updated = datetime.now(timezone.utc)
                credential = self._commit_and_refresh(session, credential)
            return credential

    def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential."""
        with self.get_session() as session:
            credential = (
                session.query(VerifiableCredentialRecord)
                .filter(VerifiableCredentialRecord.credential_id == credential_id)
                .first()
            )
            if credential:
                session.delete(credential)
                session.commit()
                return True
            return False

    # ========== Task Operations ==========

    def create_task(
        self,
        task_id: str,
        task_type: str,
        status: str,
        progress: Optional[Dict] = None,
        message: Optional[str] = None,
    ) -> AdminBackgroundTask:
        """Create a new task."""
        task = AdminBackgroundTask(
            task_id=task_id,
            task_type=task_type,
            status=status,
            progress=progress or {},
            message=message,
        )
        return self._create_with_session(task)

    def get_task(self, task_id: str) -> Optional[AdminBackgroundTask]:
        """Get a task by ID."""
        return self._get_by_field(AdminBackgroundTask, "task_id", task_id)

    def get_tasks(self, filters: Optional[Dict[str, Any]] = None) -> List[AdminBackgroundTask]:
        """Get tasks with optional filters."""
        with self.get_session() as session:
            query = session.query(AdminBackgroundTask)

            if filters:
                if "task_type" in filters:
                    query = query.filter(AdminBackgroundTask.task_type == filters["task_type"])
                if "status" in filters:
                    query = query.filter(AdminBackgroundTask.status == filters["status"])

            return query.all()

    def update_task(
        self,
        task_id: str,
        status: Optional[str] = None,
        progress: Optional[Dict] = None,
        message: Optional[str] = None,
    ) -> Optional[AdminBackgroundTask]:
        """Update an existing task."""
        with self.get_session() as session:
            task = (
                session.query(AdminBackgroundTask)
                .filter(AdminBackgroundTask.task_id == task_id)
                .first()
            )
            if task:
                if status is not None:
                    task.status = status
                if progress is not None:
                    task.progress = progress
                if message is not None:
                    task.message = message
                if status is not None or progress is not None or message is not None:
                    task = self._commit_and_refresh(session, task)
            return task

    def delete_task(self, task_id: str) -> bool:
        """Delete a task."""
        with self.get_session() as session:
            task = (
                session.query(AdminBackgroundTask)
                .filter(AdminBackgroundTask.task_id == task_id)
                .first()
            )
            if task:
                session.delete(task)
                session.commit()
                return True
            return False

    # ========== Policy Operations ==========

    def create_or_update_policy(self, policy_id: str, policy_data: Dict) -> ServerPolicy:
        """Create or update a policy."""
        with self.get_session() as session:
            policy = session.query(ServerPolicy).filter(ServerPolicy.policy_id == policy_id).first()

            if policy:
                # Update existing
                for key, value in policy_data.items():
                    setattr(policy, key, value)
                # Also update the JSON policy_data column
                policy.policy_data = policy_data
                policy = self._commit_and_refresh(session, policy)
            else:
                # Create new
                policy = ServerPolicy(policy_id=policy_id, **policy_data)
                policy.policy_data = policy_data
                policy = self._create_and_commit(session, policy)
            return policy

    def get_policy(self, policy_id: str) -> Optional[ServerPolicy]:
        """Get a policy by ID."""
        return self._get_by_field(ServerPolicy, "policy_id", policy_id)

    # ========== Registry Operations ==========

    def create_or_update_registry(
        self, registry_id: str, registry_type: str, registry_data: Dict, meta: Optional[Dict] = None
    ) -> KnownWitnessRegistry:
        """Create or update a registry."""
        with self.get_session() as session:
            registry = (
                session.query(KnownWitnessRegistry)
                .filter(KnownWitnessRegistry.registry_id == registry_id)
                .first()
            )

            if registry:
                # Update existing
                registry.registry_type = registry_type
                registry.registry_data = registry_data
                if meta is not None:
                    registry.meta = meta
                registry = self._commit_and_refresh(session, registry)
            else:
                # Create new
                registry = KnownWitnessRegistry(
                    registry_id=registry_id,
                    registry_type=registry_type,
                    registry_data=registry_data,
                    meta=meta,
                )
                registry = self._create_and_commit(session, registry)
            return registry

    def get_registry(self, registry_id: str) -> Optional[KnownWitnessRegistry]:
        """Get a registry by ID."""
        return self._get_by_field(KnownWitnessRegistry, "registry_id", registry_id)

    # ========== Witness Invitation Operations ==========

    def create_or_update_witness_invitation(
        self,
        witness_did: str,
        invitation_url: str,
        invitation_payload: Dict[str, Any],
        invitation_id: Optional[str] = None,
        label: Optional[str] = None,
    ) -> WitnessInvitation:
        """Create or update a witness invitation record."""
        with self.get_session() as session:
            record = (
                session.query(WitnessInvitation)
                .filter(WitnessInvitation.witness_did == witness_did)
                .first()
            )

            if record:
                record.invitation_url = invitation_url
                record.invitation_payload = invitation_payload
                record.invitation_id = invitation_id or invitation_payload.get("@id")
                record.label = label or invitation_payload.get("label")
                record.goal_code = invitation_payload.get("goal_code")
                record.goal = invitation_payload.get("goal")
                record = self._commit_and_refresh(session, record)
            else:
                record = WitnessInvitation(
                    witness_did=witness_did,
                    invitation_url=invitation_url,
                    invitation_payload=invitation_payload,
                    invitation_id=invitation_id or invitation_payload.get("@id"),
                    label=label or invitation_payload.get("label"),
                    goal_code=invitation_payload.get("goal_code"),
                    goal=invitation_payload.get("goal"),
                )
                record = self._create_and_commit(session, record)
            return record

    def get_witness_invitation(self, witness_did: str) -> Optional[WitnessInvitation]:
        """Retrieve a stored witness invitation."""
        return self._get_by_field(WitnessInvitation, "witness_did", witness_did)

    def delete_witness_invitation(self, witness_did: str) -> None:
        """Delete a stored witness invitation."""
        with self.get_session() as session:
            record = (
                session.query(WitnessInvitation)
                .filter(WitnessInvitation.witness_did == witness_did)
                .first()
            )
            if record:
                session.delete(record)
                session.commit()

    # ========== Witness File Operations ==========

    def create_or_update_witness_file(
        self, scid: str, witness_proofs: List[Dict]
    ) -> DidControllerRecord:
        """Create or update a witness file."""
        with self.get_session() as session:
            controller = (
                session.query(DidControllerRecord).filter(DidControllerRecord.scid == scid).first()
            )
            if not controller:
                raise ValueError(f"No DID controller found with scid: {scid}")

            controller.witness_file = witness_proofs
            return self._commit_and_refresh(session, controller)

    def get_witness_file(self, scid: str) -> Optional[DidControllerRecord]:
        """Get a witness file by SCID."""
        return self._get_by_field(DidControllerRecord, "scid", scid)

    # ========== WHOIS Presentation Operations ==========

    def create_or_update_whois(self, scid: str, presentation: Dict) -> DidControllerRecord:
        """Create or update a WHOIS presentation."""
        with self.get_session() as session:
            controller = (
                session.query(DidControllerRecord).filter(DidControllerRecord.scid == scid).first()
            )
            if not controller:
                raise ValueError(f"No DID controller found with scid: {scid}")

            controller.whois_presentation = presentation
            return self._commit_and_refresh(session, controller)

    def get_whois(self, scid: str) -> Optional[DidControllerRecord]:
        """Get a WHOIS presentation by SCID."""
        return self._get_by_field(DidControllerRecord, "scid", scid)

    # ========== Helper Methods (Query by Namespace and Identifier) ==========

    def get_did_controller_by_scid(self, scid: str) -> Optional[DidControllerRecord]:
        """Get a DID controller by SCID."""
        return self._get_by_field(DidControllerRecord, "scid", scid)

    def get_did_controller_by_alias(
        self, namespace: str, identifier: str
    ) -> Optional[DidControllerRecord]:
        """Get a log entry by namespace and identifier (alias)."""
        with self.get_session() as session:
            return (
                session.query(DidControllerRecord)
                .filter(
                    DidControllerRecord.namespace == namespace,
                    DidControllerRecord.alias == identifier,
                )
                .first()
            )

    def get_whois_by_identifier(self, namespace: str, alias: str) -> Optional[DidControllerRecord]:
        """Get a WHOIS presentation by namespace and alias."""
        with self.get_session() as session:
            return (
                session.query(DidControllerRecord)
                .filter(
                    DidControllerRecord.namespace == namespace,
                    DidControllerRecord.alias == alias,
                )
                .first()
            )

    # ========== Tails File Operations ==========

    def create_tails_file(
        self, tails_hash: str, file_content_hex: str, file_size: int
    ) -> TailsFile:
        """Create a new tails file."""
        tails_file = TailsFile(
            tails_hash=tails_hash, file_content_hex=file_content_hex, file_size=file_size
        )
        return self._create_with_session(tails_file)

    def get_tails_file(self, tails_hash: str) -> Optional[TailsFile]:
        """Get a tails file by hash."""
        return self._get_by_field(TailsFile, "tails_hash", tails_hash)
