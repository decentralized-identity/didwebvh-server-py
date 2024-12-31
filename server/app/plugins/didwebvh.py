from config import settings
from datetime import datetime
from app.models.did_log import LogParameters, InitialLogEntry
import canonicaljson
import json
from multiformats import multihash, multibase


class DidWebVH:
    def __init__(self):
        self.prefix = settings.DID_WEBVH_PREFIX
        self.method_version = f"{self.prefix}0.4"
        self.did_string_base = self.prefix + r"{SCID}:" + settings.DOMAIN

    def _init_parameters(self, update_key, next_key=None, ttl=100):
        # https://identity.foundation/trustdidweb/#generate-scid
        parameters = LogParameters(
            method=self.method_version, scid=r"{SCID}", updateKeys=[update_key]
        )
        return parameters

    def _init_state(self, did_doc):
        return json.loads(json.dumps(did_doc).replace("did:web:", self.prefix + r"{SCID}:"))

    def _generate_scid(self, log_entry):
        # https://identity.foundation/trustdidweb/#generate-scid
        jcs = canonicaljson.encode_canonical_json(log_entry)
        multihashed = multihash.digest(jcs, "sha2-256")
        encoded = multibase.encode(multihashed, "base58btc")[1:]
        return encoded

    def _generate_entry_hash(self, log_entry):
        # https://identity.foundation/trustdidweb/#generate-entry-hash
        jcs = canonicaljson.encode_canonical_json(log_entry)
        multihashed = multihash.digest(jcs, "sha2-256")
        encoded = multibase.encode(multihashed, "base58btc")[1:]
        return encoded

    def create(self, did_doc, update_key):
        # https://identity.foundation/trustdidweb/#create-register
        log_entry = InitialLogEntry(
            versionId=r"{SCID}",
            versionTime=str(datetime.now().isoformat("T", "seconds")),
            parameters=self._init_parameters(update_key=update_key),
            state=self._init_state(did_doc),
        ).model_dump()
        scid = self._generate_scid(log_entry)
        log_entry = json.loads(json.dumps(log_entry).replace("{SCID}", scid))
        log_entry_hash = self._generate_entry_hash(log_entry)
        log_entry["versionId"] = f"1-{log_entry_hash}"
        return log_entry
