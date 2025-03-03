from app.routers.identifiers import request_did, read_did, read_did_log, create_didwebvh
from app.plugins import AskarStorage, AskarVerifier, DidWebVH
from app.models.web_schemas import RegisterInitialLogEntry
from app.models.did_log import LogEntry
from datetime import datetime, timezone
from tests.fixtures import (
    TEST_DOMAIN,
    TEST_DID_NAMESPACE,
    TEST_DID_IDENTIFIER,
    TEST_DID,
    TEST_DID_DOCUMENT,
    TEST_UPDATE_KEY,
    TEST_PROOF_OPTIONS,
)
from tests.mock_agents import WitnessAgent, ControllerAgent
import json
import pytest
import asyncio
from tests.signer import sign

askar = AskarStorage()
asyncio.run(askar.provision(recreate=True))
verifier = AskarVerifier()
didwebvh = DidWebVH()

witness = WitnessAgent()
controller = ControllerAgent()


@pytest.mark.asyncio
async def test_create_schema():
    pass


@pytest.mark.asyncio
async def test_create_cred_def():
    pass


@pytest.mark.asyncio
async def test_create_rev_def():
    pass


@pytest.mark.asyncio
async def test_create_rev_entry():
    pass


@pytest.mark.asyncio
async def test_update_rev_def():
    pass