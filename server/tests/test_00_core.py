from app.plugins import AskarStorage, AskarVerifier, DidWebVH
import pytest
import asyncio
from tests.fixtures import (
    TEST_DID_DOCUMENT,
)
from tests.mock_agents import ControllerAgent

askar = AskarStorage()
asyncio.run(askar.provision(recreate=True))

verifier = AskarVerifier()
didwebvh = DidWebVH()
controller = ControllerAgent()


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


@pytest.mark.asyncio
async def test_verify_di_proof():
    signed_document = controller.sign_log(TEST_DID_DOCUMENT)
    proof = signed_document.pop("proof")
    assert verifier.verify_proof(signed_document, proof)
