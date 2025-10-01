"""Utility functions for the DID Web server."""

from config import settings
import jcs
import json
from multiformats import multibase, multihash
from datetime import datetime, timezone, timedelta

from operator import itemgetter

from app.models.storage import DidRecordTags, DidRecord, ResourceRecordTags, ResourceRecord

MULTIKEY_PARAMS = {"ed25519": {"length": 48, "prefix": "z6M"}}


# def tag_identifier(value):
#     return {
#         'scid': scid,
#         'author': controller_id,
#         'type': attested_resource.get('metadata').get('resourceType'),
#         'digest': resource_digest
#     }

# def tag_resource(value):
#     return {
#         'scid': scid,
#         'author': controller_id,
#         'type': attested_resource.get('metadata').get('resourceType'),
#         'digest': resource_digest
#     }


def sync_resource(resource):
    """Sync an attested resource to it's explorer record."""
    controller_id = resource.get("id").split("/")[0]
    scid, domain, namespace, alias = itemgetter(2, 3, 4, 5)(controller_id.split(":"))
    tags = ResourceRecordTags(
        did=controller_id,
        scid=scid,
        resource_id=resource.get("metadata").get("resourceId"),
        resource_type=resource.get("metadata").get("resourceType"),
    ).model_dump()

    resource_record = ResourceRecord(
        attested_resource=resource,
        details=resource_details(resource),
        url=resource_id_to_url(resource.get("id")),
        author=ResourceRecord.ResourceAuthor(
            avatar=f"{settings.AVATAR_URL}?seed={scid}",
            scid=scid,
            domain=domain,
            namespace=namespace,
            alias=alias,
        ),
        **tags,
    ).model_dump()
    return resource_record, tags


def sync_did_info(state, logs, did_resources, witness_file, whois_presentation):
    """Sync a DID info to it's explorer record."""
    did = state.document_id
    scid, domain, namespace, identifier = itemgetter(2, 3, 4, 5)(did.split(":"))
    tags = DidRecordTags(
        did=did,
        scid=scid,
        domain=domain,
        namespace=namespace,
        identifier=identifier,
        created=beautify_date(logs[0].get("versionTime")),
        updated=beautify_date(logs[-1].get("versionTime")),
        deactivated=str(state.deactivated),
    ).model_dump()

    did_record = DidRecord(
        logs=logs,
        witness_file=witness_file,
        whois_presentation=whois_presentation,
        avatar=f"{settings.AVATAR_URL}?seed={scid}",
        active=False if state.deactivated else True,
        witnesses=state.witness.get("witnesses", []) if state.witness else [],
        watchers=state.params.get("watchers", []),
        resources=[
            DidRecord.ResourceDetails(
                type=resource.get("metadata").get("resourceType"),
                digest=resource.get("metadata").get("resourceId"),
                details=resource_details(resource),
            )
            for resource in did_resources
        ],
        links=DidRecord.DidLinks(
            resolver=f"{settings.UNIRESOLVER_URL}/#{did}",
            log_file=f"{did_to_https(did)}/did.jsonl",
            witness_file=f"{did_to_https(did)}/did-witness.json",
            resource_query=f"https://{settings.DOMAIN}/explorer/resources?scid={scid}",
            whois_presentation=f"{did_to_https(did)}/whois.vp",
        ),
        **tags,
    ).model_dump()
    return did_record, tags


def did_to_https(did):
    """DID to https transformation."""
    domain, namespace, identifier = itemgetter(3, 4, 5)(did.split(":"))
    return f"https://{domain}/{namespace}/{identifier}"


def beautify_date(value):
    """Returns a human readable date from a ISO datetime string."""
    date_str = value.split("T")[0]
    date_obj = datetime.strptime(date_str, "%Y-%m-%d")
    return date_obj.strftime("%B %d, %Y")


def resource_id_to_url(resource_id):
    """Returns a resource url from it's id."""
    author_id = resource_id.split("/")[0]
    domain, namespace, identifier = itemgetter(3, 4, 5)(author_id.split(":"))
    path = "/".join(resource_id.split("/")[1:])
    return f"https://{domain}/{namespace}/{identifier}/{path}"


def resource_details(resource):
    """Returns resource specific details."""
    resource_type = resource.get("metadata").get("resourceType")
    if resource_type == "anonCredsSchema":
        return {
            "name": resource.get("content").get("name"),
            "version": resource.get("content").get("version"),
        }
    elif resource_type == "anonCredsCredDef":
        return {"tag": resource.get("content").get("tag")}
    elif resource_type == "anonCredsRevRegDef":
        return {
            "tag": resource.get("content").get("tag"),
            "size": resource.get("content").get("value").get("maxCredNum"),
        }
    elif resource_type == "anonCredsStatusList":
        return {
            "size": len(resource.get("content").get("revocationList")),
            "timestamp": resource.get("content").get("timestamp"),
        }
    return {}


def get_client_id(namespace, identifier):
    """Create the client id."""
    return f"{namespace}:{identifier}"


def is_valid_multikey(multikey, alg="ed25519"):
    """Test for multikey string."""
    if not multikey.startswith(MULTIKEY_PARAMS[alg]["prefix"]) or len(multikey) != 48:
        return False
    if len(multikey) != MULTIKEY_PARAMS[alg]["length"]:
        return False
    return True


def is_webvh_did(did):
    """Test for WebVH string."""
    try:
        assert did.split(":")[0] == "did"
        assert did.split(":")[1] == "webvh"
        assert did.split(":")[3]  # SCID
        assert did.split(":")[4] == settings.DOMAIN
        assert did.split(":")[5]  # namespace
        assert did.split(":")[6]  # identifier
        return True
    except AssertionError:
        return False


def digest_multibase(content):
    """Calculate digest multibase."""
    digest_multihash = multihash.digest(jcs.canonicalize(content), "sha2-256")
    digest_multibase = multibase.encode(digest_multihash, "base58btc")
    return digest_multibase


def to_did_web(namespace: str, identifier: str):
    """Convert namespace and identifier to a DID Web identifier."""
    return f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"


def derive_did(namespace, identifier):
    """Derive a DID from a namespace and identifier."""
    return f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"


def find_key(did_doc, kid):
    """Find a key in a DID document."""
    return next(
        (vm["publicKeyMultibase"] for vm in did_doc["verificationMethod"] if vm["id"] == kid),
        None,
    )


def find_proof(proof_set, kid):
    """Find a proof in a proof set."""
    return next(
        (proof for proof in proof_set if proof["verificationMethod"] == kid),
        None,
    )


def find_verification_method(did_doc, kid):
    """Find a verification method's public key given a key id."""
    return next(
        (vm["publicKeyMultibase"] for vm in did_doc["verificationMethod"] if vm["id"] == kid),
        None,
    )


def first_proof(proof):
    """Return the first proof from a proof set."""
    return proof if isinstance(proof, dict) else proof[0]


def timestamp(minutes_delta=None):
    """Create timestamps."""
    dt = (
        datetime.now(timezone.utc) + timedelta(minutes=minutes_delta)
        if minutes_delta
        else datetime.now(timezone.utc)
    )
    return str(dt.isoformat("T", "seconds")).replace("+00:00", "Z")


def webvh_to_web_doc(did_document, scid):
    """Trasform did webvh doc to did web."""
    return json.loads(json.dumps(did_document).replace(f"did:webvh:{scid}:", "did:web:"))
