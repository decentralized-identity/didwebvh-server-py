"""Models for explorer UI data structures."""

from typing import Optional, List, Dict, Any, TYPE_CHECKING
from pydantic import Field
from app.models.base import CustomBaseModel
from app.utilities import (
    beautify_date,
    resource_details,
    decode_enveloped_credential,
    resource_id_to_url,
)
from app.avatar_generator import generate_avatar
from app.plugins.storage import StorageManager
from config import settings

if TYPE_CHECKING:
    from app.db.models import (
        DidControllerRecord,
        VerifiableCredentialRecord,
        AttestedResourceRecord,
    )


class DidResourceSummary(CustomBaseModel):
    """Resource summary for DID detail views."""

    type: str = Field(..., description="Resource type")
    digest: str = Field(..., description="Resource digest/ID")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional resource details")


class DidCredentialSummary(CustomBaseModel):
    """Credential summary for DID detail views."""

    id: str = Field(..., description="Credential ID")
    type: List[str] = Field(..., description="Credential types")
    subject_id: Optional[str] = Field(None, description="Subject DID")
    issued: str = Field("", description="Formatted issue date")
    valid_from: str = Field("", description="Formatted valid from date")
    valid_until: str = Field("", description="Formatted valid until date")
    revoked: bool = Field(False, description="Revocation status")
    verified: bool = Field(False, description="Verification status")


class ExplorerDidLinks(CustomBaseModel):
    """Links associated with a DID for explorer UI."""

    resolver: str = Field(..., description="Universal resolver link")
    log_file: str = Field(..., description="DID log file URL")
    witness_file: str = Field(..., description="Witness file URL")
    resource_query: str = Field(..., description="Resource query URL")
    whois_presentation: str = Field(..., description="WHOIS presentation URL")


class ExplorerDidRecord(CustomBaseModel):
    """DID record for explorer UI."""

    # Basic info
    did: str = Field(..., description="DID identifier")
    scid: str = Field(..., description="Self-certifying identifier")
    domain: str = Field(..., description="Domain")
    namespace: str = Field(..., description="Namespace")
    identifier: str = Field(..., description="Alias/identifier")
    created: str = Field("", description="Formatted creation date")
    updated: str = Field("", description="Formatted update date")
    deactivated: str = Field(..., description="Deactivation status as string")

    # Computed fields
    active: bool = Field(..., description="Active status")
    avatar: str = Field(..., description="Avatar data URL")
    witnesses: List[Dict[str, Any]] = Field(default_factory=list, description="Witness list")
    watchers: List[str] = Field(default_factory=list, description="Watcher URLs")
    resources: List[DidResourceSummary] = Field(
        default_factory=list, description="Associated resources"
    )
    credentials: List[DidCredentialSummary] = Field(
        default_factory=list, description="Associated credentials"
    )
    links: ExplorerDidLinks = Field(..., description="Related links")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="DID parameters")
    version_id: str = Field("", description="Latest version ID")
    version_time: str = Field("", description="Latest version timestamp")

    # Raw data (for detail views)
    logs: List[Dict[str, Any]] = Field(default_factory=list, description="DID log entries")
    witness_file: Optional[List[Dict[str, Any]]] = Field(None, description="Witness file data")
    whois_presentation: Optional[Dict[str, Any]] = Field(None, description="WHOIS presentation")
    document: Dict[str, Any] = Field(default_factory=dict, description="DID document")

    @classmethod
    def from_controller(
        cls,
        controller: "DidControllerRecord",
    ) -> "ExplorerDidRecord":
        """Create an ExplorerDidRecord from a DidControllerRecord.

        Uses SQLAlchemy relationships for resources and credentials (batch-loaded).

        Args:
            controller: DID controller from database (with resources/credentials pre-loaded)

        Returns:
            ExplorerDidRecord instance
        """
        # Use stored avatar from database (generated once at creation time)
        did_avatar = controller.avatar or generate_avatar(controller.scid)

        # Transform resources to summaries (limit to first 5 for display)
        # controller.resources is batch-loaded via selectin relationship
        formatted_resources = [
            DidResourceSummary(
                type=r.resource_type,
                digest=r.resource_id,
                created=beautify_date(r.created),
                updated=beautify_date(r.updated),
                details={},
            )
            for r in (controller.resources[:5] if controller.resources else [])
        ]

        # Transform credentials to summaries (limit to first 5 for display)
        # controller.credentials is batch-loaded via selectin relationship
        formatted_credentials = [
            DidCredentialSummary(
                id=c.credential_id,
                type=c.credential_type,
                subject_id=c.subject_id,
                created=beautify_date(c.created),
                updated=beautify_date(c.updated),
                issued=beautify_date(c.created) if c.created else "",
                valid_from=beautify_date(c.valid_from) if c.valid_from else "",
                valid_until=beautify_date(c.valid_until) if c.valid_until else "",
                revoked=c.revoked,
                verified=c.verified,
            )
            for c in (controller.credentials[:5] if controller.credentials else [])
        ]

        # Generate links
        links = ExplorerDidLinks(
            resolver=f"{settings.UNIRESOLVER_URL}/#{controller.did}",
            log_file=f"https://{controller.domain}/{controller.namespace}/{controller.alias}/did.jsonl",
            witness_file=f"https://{controller.domain}/{controller.namespace}/{controller.alias}/did-witness.json",
            resource_query=f"https://{settings.DOMAIN}/explorer/resources?scid={controller.scid}",
            whois_presentation=f"https://{controller.domain}/{controller.namespace}/{controller.alias}/whois.vp",
        )

        return cls(
            # Basic info
            did=controller.did,
            scid=controller.scid,
            domain=controller.domain,
            namespace=controller.namespace,
            identifier=controller.alias,
            created=beautify_date(controller.logs[0].get("versionTime")) if controller.logs else "",
            updated=beautify_date(controller.logs[-1].get("versionTime"))
            if controller.logs
            else "",
            deactivated=str(controller.deactivated),
            # Computed fields
            active=not controller.deactivated,
            avatar=did_avatar,  # Reuse the avatar generated at the start
            witnesses=controller.parameters.get("witness", {}).get("witnesses", [])
            if controller.parameters
            else [],
            watchers=controller.parameters.get("watchers", []) if controller.parameters else [],
            resources=formatted_resources,
            credentials=formatted_credentials,
            links=links,
            parameters=controller.parameters or {},
            version_id=controller.logs[-1].get("versionId") if controller.logs else "",
            version_time=controller.logs[-1].get("versionTime") if controller.logs else "",
            # Raw data
            logs=controller.logs or [],
            witness_file=controller.witness_file,
            whois_presentation=controller.whois_presentation,
            document=controller.document or {},
        )


class ResourceAuthor(CustomBaseModel):
    """Author information for a resource."""

    scid: str = Field(..., description="Author SCID")
    domain: str = Field("", description="Author domain")
    namespace: str = Field("", description="Author namespace")
    alias: str = Field("", description="Author alias")
    avatar: str = Field("", description="Author avatar")


class ExplorerResourceRecord(CustomBaseModel):
    """Resource record for explorer UI."""

    # Basic info
    did: str = Field("", description="DID identifier")
    scid: str = Field(..., description="Self-certifying identifier")
    domain: str = Field("", description="Domain")
    namespace: str = Field("", description="Namespace")
    identifier: str = Field("", description="Alias/identifier")

    # Resource info
    resource_id: str = Field(..., description="Resource ID/digest")
    resource_name: Optional[str] = Field(None, description="Resource name")
    resource_type: str = Field(..., description="Resource type")
    media_type: Optional[str] = Field(None, description="Media type")
    created: str = Field("", description="Formatted creation date")
    url: str = Field("", description="Resource URL")

    # Author info (for template compatibility)
    author: ResourceAuthor = Field(..., description="Resource author information")

    # Full data
    attested_resource: Dict[str, Any] = Field(
        default_factory=dict, description="Full attested resource"
    )
    details: Dict[str, Any] = Field(default_factory=dict, description="Resource-specific details")

    @classmethod
    def from_resource_record(cls, resource: "AttestedResourceRecord") -> "ExplorerResourceRecord":
        """Create an ExplorerResourceRecord from an AttestedResourceRecord.

        Args:
            resource: Resource record from database

        Returns:
            ExplorerResourceRecord instance
        """
        attested_res = resource.attested_resource or {}
        res_id_full = attested_res.get("id", "")

        # Derive DID from resource id if present: did:webvh:.../resources/<digest>
        did_from_id = res_id_full.split("/resources/")[0] if "/resources/" in res_id_full else ""
        did_parts = did_from_id.split(":") if did_from_id else []
        domain = did_parts[3] if len(did_parts) >= 4 else ""
        namespace = did_parts[4] if len(did_parts) >= 5 else ""
        alias = did_parts[5] if len(did_parts) >= 6 else ""

        # Generate avatar for author
        avatar = generate_avatar(resource.scid)

        # Generate HTTPS resource URL from the DID-format ID
        if res_id_full:
            resource_url = resource_id_to_url(res_id_full)
        else:
            # Fallback: construct from parts
            resource_url = f"https://{domain}/{namespace}/{alias}/resources/{resource.resource_id}"

        # Create author object
        author = ResourceAuthor(
            scid=resource.scid,
            domain=domain,
            namespace=namespace,
            alias=alias,
            avatar=avatar,
        )

        return cls(
            # Basic info
            did=did_from_id,
            scid=resource.scid,
            domain=domain,
            namespace=namespace,
            identifier=alias,
            # Resource info
            resource_id=resource.resource_id,
            resource_name=resource.resource_name,
            resource_type=resource.resource_type,
            media_type=resource.media_type,
            created=beautify_date(attested_res.get("metadata", {}).get("created", "")),
            url=resource_url,
            # Author
            author=author,
            # Full data
            attested_resource=attested_res,
            details=resource_details(attested_res) if attested_res else {},
        )


class ExplorerCredentialRecord(CustomBaseModel):
    """Credential record for explorer UI."""

    # Basic info
    credential_id: str = Field(..., description="Credential ID")
    scid: str = Field(..., description="Self-certifying identifier of issuer")
    namespace: str = Field("", description="Namespace")
    alias: str = Field("", description="Alias/identifier")

    # Credential info
    issuer_did: str = Field(..., description="Issuer DID")
    subject_id: Optional[str] = Field(None, description="Subject DID")
    credential_type: str = Field(..., description="Primary credential type (formatted)")
    all_types: List[str] = Field(default_factory=list, description="All credential types")
    subject_type: Optional[str] = Field(None, description="Subject type if available")

    # Status
    revoked: bool = Field(False, description="Revocation status")
    verified: bool = Field(False, description="Verification status")

    # Validity
    valid_from: str = Field("", description="Formatted valid from date")
    valid_until: str = Field("", description="Formatted valid until date")

    # Metadata
    issuer_name: Optional[str] = Field(None, description="Issuer name")
    subject_name: Optional[str] = Field(None, description="Subject name from credentialSubject")
    avatar: str = Field("", description="Avatar data URL for issuer")
    did_method: str = Field("webvh", description="DID method")

    # Verification details
    verification_method: Optional[str] = Field(None, description="Verification method used")

    # Full credential
    verifiable_credential: Dict[str, Any] = Field(
        default_factory=dict, description="Full verifiable credential"
    )

    # Timestamps
    created: str = Field("", description="Formatted creation date")
    updated: str = Field("", description="Formatted update date")

    @classmethod
    def from_credential_record(
        cls,
        credential: "VerifiableCredentialRecord",
        did_controller: Optional["DidControllerRecord"] = None,
    ) -> "ExplorerCredentialRecord":
        """Create an ExplorerCredentialRecord from a VerifiableCredentialRecord.

        Args:
            credential: Credential record from database
            did_controller: Optional DID controller (if None, will look up by scid)

        Returns:
            ExplorerCredentialRecord instance
        """
        vc = credential.verifiable_credential

        # Decode credential (handles both enveloped and regular VCs)
        cred_types, subject = decode_enveloped_credential(vc)

        # Filter out "VerifiableCredential" to show only specific types
        specific_types = [t for t in cred_types if t != "VerifiableCredential"]

        # Format credential type for display (add spaces before capital letters)
        raw_type = specific_types[0] if specific_types else "VerifiableCredential"
        formatted_type = "".join([" " + c if c.isupper() else c for c in raw_type]).strip()

        # Get DID controller if not provided
        if not did_controller:
            storage = StorageManager()
            did_controller = storage.get_did_controller_by_scid(credential.scid)

        namespace_val = did_controller.namespace if did_controller else ""
        alias_val = did_controller.alias if did_controller else ""

        # Try to get subject type if present
        subject_type = None
        if isinstance(subject, dict):
            subject_types = subject.get("type", [])
            if isinstance(subject_types, list):
                subject_type = next(
                    (t for t in subject_types if t != "VerifiableCredential"),
                    subject_types[0] if subject_types else None,
                )
            else:
                subject_type = subject_types

        # Extract issuer name from credential
        issuer = vc.get("issuer", {})
        issuer_name = issuer.get("name") if isinstance(issuer, dict) else None

        # Extract subject name if available
        subject_name = None
        if isinstance(subject, dict):
            subject_name = subject.get("name")

        # Generate avatar for issuer
        avatar = generate_avatar(credential.scid)

        # Extract DID method
        did_method = (
            credential.issuer_did.split(":")[1] if ":" in credential.issuer_did else "unknown"
        )

        return cls(
            # Basic info
            credential_id=credential.credential_id,
            issuer_did=credential.issuer_did,
            subject_id=credential.subject_id or "N/A",
            scid=credential.scid,
            namespace=namespace_val,
            alias=alias_val,
            # Credential details
            credential_type=formatted_type,
            all_types=cred_types,
            subject_type=subject_type,
            revoked=credential.revoked,
            # Validity
            valid_from=beautify_date(credential.valid_from) if credential.valid_from else "N/A",
            valid_until=beautify_date(credential.valid_until) if credential.valid_until else "N/A",
            # Verification
            verified=credential.verified,
            verification_method=credential.verification_method,
            # Metadata
            issuer_name=issuer_name,
            subject_name=subject_name,
            avatar=avatar,
            did_method=did_method,
            # Full credential
            verifiable_credential=vc,
            # Timestamps
            created=beautify_date(credential.created),
            updated=beautify_date(credential.updated),
        )


class ExplorerWitnessRegistryMeta(CustomBaseModel):
    """Metadata for the known witness registry."""

    created: str = Field("", description="Registry creation timestamp")
    updated: str = Field("", description="Registry last update timestamp")

    @classmethod
    def from_meta(cls, meta: Optional[Dict[str, Any]]) -> "ExplorerWitnessRegistryMeta":
        """Create metadata model from registry meta dict."""
        if not meta:
            return cls(created="", updated="")

        return cls(
            created=beautify_date(meta.get("created")),
            updated=beautify_date(meta.get("updated")),
        )


class ExplorerWitnessRecord(CustomBaseModel):
    """Witness record for explorer UI."""

    id: str = Field(..., description="Witness DID")
    name: str = Field("", description="Witness display name")
    location: Optional[str] = Field(None, description="Witness location or region")
    url: Optional[str] = Field(None, description="Witness information URL")
    service_endpoint: Optional[str] = Field(
        None, description="Service endpoint exposed by the witness"
    )
    avatar: str = Field("", description="Avatar generated from witness DID")
    short_id: str = Field("", description="Abbreviated witness identifier")
    resolver_url: str = Field("", description="Universal resolver link for the witness DID")

    @classmethod
    def from_registry_entry(
        cls,
        witness_id: str,
        entry: Dict[str, Any],
    ) -> "ExplorerWitnessRecord":
        """Create a witness record from registry entry data."""
        name = entry.get("name") or witness_id.split(":")[-1]
        location = entry.get("location")
        url = entry.get("url")
        service_endpoint = entry.get("serviceEndpoint") or entry.get("service_endpoint")
        short_id = witness_id.split(":")[-1]

        return cls(
            id=witness_id,
            name=name,
            location=location,
            url=url,
            service_endpoint=service_endpoint,
            avatar=generate_avatar(witness_id),
            short_id=short_id,
            resolver_url=f"{settings.UNIRESOLVER_URL}/#{witness_id}",
        )
