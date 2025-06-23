from app.routers.identifiers import read_did_log
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from app.models.resource import AttestedResource
from app.models.web_schemas import ResourceUpload, ResourceOptions
from tests.fixtures import (
    TEST_ANONCREDS_SCHEMA,
    TEST_DID_NAMESPACE,
    TEST_DID_IDENTIFIER,
    TEST_DID,
)
from tests.mock_agents import WitnessAgent, ControllerAgent
import pytest
import asyncio
from anoncreds import (
    CredentialDefinition,
    RevocationRegistryDefinition,
    RevocationStatusList,
    Schema,
)
import json
from app.routers.resources import update_attested_resource, upload_attested_resource, get_resource


askar = AskarStorage()
asyncio.run(askar.provision(recreate=True))
verifier = AskarVerifier()
didwebvh = DidWebVH()

witness = WitnessAgent()
controller = ControllerAgent()


async def get_issuer_id():
    did_logs = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_logs = did_logs.body.decode().split("\n")[:-1]
    return json.loads(did_logs[-1]).get("state").get("id")


async def get_verification_method():
    did_logs = await read_did_log(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER)
    did_logs = did_logs.body.decode().split("\n")[:-1]
    return json.loads(did_logs[-1]).get("state").get("verificationMethod")[0].get("id")


def decode_response(response):
    return json.loads(response.body.decode())


@pytest.mark.asyncio
async def test_anoncreds():
    schema = Schema.create(
        TEST_ANONCREDS_SCHEMA["name"],
        TEST_ANONCREDS_SCHEMA["version"],
        controller.issuer_id,
        TEST_ANONCREDS_SCHEMA["attributes"],
    )

    attested_schema, schema_id = controller.attest_resource(schema.to_dict(), "anonCredsSchema")
    print(json.dumps(attested_schema, indent=2))

    await upload_attested_resource(
        ResourceUpload(
            attestedResource=AttestedResource.model_validate(attested_schema),
            options=ResourceOptions(),
        ),
    )
    fetched_schema = decode_response(
        await get_resource(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, schema_id.split("/")[-1])
    )
    assert fetched_schema.get("id") == schema_id

    cred_def_pub, cred_def_priv, cred_def_correctness = CredentialDefinition.create(
        schema_id, schema, controller.issuer_id, "tag", "CL", support_revocation=True
    )

    attested_cred_def, cred_def_id = controller.attest_resource(
        cred_def_pub.to_dict(), "anonCredsCredDef"
    )

    await upload_attested_resource(
        ResourceUpload(
            attestedResource=AttestedResource.model_validate(attested_cred_def),
            options=ResourceOptions(),
        ),
    )
    fetched_cred_def = decode_response(
        await get_resource(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, cred_def_id.split("/")[-1])
    )
    assert fetched_cred_def.get("id") == cred_def_id

    (rev_reg_def_pub, rev_reg_def_private) = RevocationRegistryDefinition.create(
        cred_def_id, cred_def_pub, controller.issuer_id, "some_tag", "CL_ACCUM", 10
    )

    attested_rev_reg_def, rev_reg_def_id = controller.attest_resource(
        rev_reg_def_pub.to_dict(), "anonCredsRevRegDef"
    )

    await upload_attested_resource(
        ResourceUpload(
            attestedResource=AttestedResource.model_validate(attested_rev_reg_def),
            options=ResourceOptions(),
        ),
    )
    fetched_rev_reg_def = decode_response(
        await get_resource(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, rev_reg_def_id.split("/")[-1])
    )
    assert fetched_rev_reg_def.get("id") == rev_reg_def_id

    time_create_rev_status_list = 12
    revocation_status_list = RevocationStatusList.create(
        cred_def_pub,
        rev_reg_def_id,
        rev_reg_def_pub,
        rev_reg_def_private,
        controller.issuer_id,
        True,
        time_create_rev_status_list,
    )

    attested_rev_reg_entry, rev_reg_entry_id = controller.attest_resource(
        revocation_status_list.to_dict(), "anonCredsRevRegEntry"
    )

    await upload_attested_resource(
        ResourceUpload(
            attestedResource=AttestedResource.model_validate(attested_rev_reg_entry),
            options=ResourceOptions(),
        ),
    )
    fetched_rev_reg_entry = decode_response(
        await get_resource(TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, rev_reg_entry_id.split("/")[-1])
    )
    assert fetched_rev_reg_entry.get("id") == rev_reg_entry_id

    fetched_rev_reg_def.pop("proof")
    updated_rev_reg_def = controller.sign(
        fetched_rev_reg_def
        | {
            "links": [
                {
                    "id": rev_reg_entry_id,
                    "type": "anonCredsRevRegEntry",
                    "timestamp": attested_rev_reg_entry["content"]["timestamp"],
                }
            ]
        }
    )

    await update_attested_resource(
        TEST_DID_NAMESPACE,
        TEST_DID_IDENTIFIER,
        rev_reg_def_id.split("/")[-1],
        ResourceUpload(
            attestedResource=AttestedResource.model_validate(updated_rev_reg_def),
            options=ResourceOptions(),
        ),
    )
    fetched_updated_rev_reg_def = await get_resource(
        TEST_DID_NAMESPACE, TEST_DID_IDENTIFIER, rev_reg_def_id.split("/")[-1]
    )
    assert decode_response(fetched_updated_rev_reg_def).get("id") == rev_reg_def_id
    assert (
        decode_response(fetched_updated_rev_reg_def).get("links")[0].get("id") == rev_reg_entry_id
    )
