from app.plugins import AskarStorage, AskarVerifier, DidWebVH
import json
import pytest
import asyncio
from tests.signer import sign

askar = AskarStorage()
asyncio.run(askar.provision(recreate=True))

verifier = AskarVerifier()
didwebvh = DidWebVH()


@pytest.mark.asyncio
async def test_storage():
    category = "test"
    key = "01"
    data = {"value": None}
    value_1 = "value_1"
    value_2 = "value_2"

    data["value"] = value_1
    await askar.store(category, key, data)
    fetched_data = await askar.fetch(category, key)
    assert fetched_data["value"] == value_1

    data["value"] = value_2
    await askar.update(category, key, data)
    fetched_data = await askar.fetch(category, key)
    assert fetched_data["value"] == value_2


# @pytest.mark.asyncio
# async def test_verify_di_proof():
#     document = await askar.fetch("didDocument", TEST_DID)
#     signed_document = sign(document)
#     proof = signed_document.pop("proof")
#     assert verifier.verify_proof(signed_document, proof)