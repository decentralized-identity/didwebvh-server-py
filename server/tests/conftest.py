import pytest
import io
import os
import hashlib
import base58
import uuid
from fastapi.testclient import TestClient
from app import app

TAILS_FILE_HEX = "00 02 03 11 55 d0 d8 69 6e 11 b2 c2 9a 5d 2b 6b df 47 28 30 ee ff d9 2b a4 83 dc ff ad 7c 66 a0 93 60 10 9b ca 4a 84 bc e1 20 af 6b da e6 58 bc 1b 25 6e f9 e6 b6 63 24 e1 c8 d3 04 1b 55 80 69 b2 71 21 eb 8a 71 0f 8a 16 c5 b4 b9 83 69 a0 21 db 84 8b 7f 31 82 f7 7c 63 45 31 c2 1c 85 45 e7 43 43 0c 55 29 64 7c fc 0c 43 bd ae d6 56 06 ae c5 2a cd ab 89 01 eb 36 74 ad 9b cf b6 46 83 4a fb 3a 13 38 cd 55 21 cb f2 4b 42 b9 bd 13 77 0f 7a ec 06 bb 95 40 f7 d2 ca d0 59 5e 7c b2 e8 af e4 50 0d 61 0c 29 a6 ea 8f dc 32 d8 83 2e aa c5 12 2f b6 eb de 72 8a 26 02 65 21 a4 56 34 53 58 b6 3a 05 d6 d5 86 64 03 fe a6 5e 0c 0a 08 09 5e be d6 9e 7d 6c 6a 7b d8 88 3c f2 e5 b1 75 9d 26 89 f5 1c a2 5f ab 0b 85 34 9e 31 9f 8e 4c 1a 49 9f f9 89 0c 21 dc 38 f3 af 7f 95 91 4b 75 de f9 4b df 00 fc 59 6f 1d 77 f9 c2 33 de 92 1d c9 82 87 c2 e6 75 2f 82 34 aa 0c 17 b1 7c 34 0e 2d c6 9d e6 22 39 54 01 b4 36 23 ba fd 95 da f5 36 7a e7 7a d5 d2 38 95 77 99 c3 a3 06 e7 a1 2c 47 b6 5c a1 07 e8 67 69 1e b0 ee 38 11 13 ed a4 6a 23 b7 63 f5 26 b0 2b c6 6e 94 72 60 85 60 94 72 d2 1e e5 09 6e ad 7b 22 17 d9 c6 43 c4 88 3c 3d c3 cb 2c ff 4c 30 f1 ca 0d 0b 6f fb 0a 35 1a 6e f9 45 9e 03 11 55 d0 d8 69 6e 11 b2 c2 9a 5d 2b 6b df 47 28 30 ee ff d9 2b a4 83 dc ff ad 7c 66 a0 93 60 10 9b ca 4a 84 bc e1 20 af 6b da e6 58 bc 1b 25 6e f9 e6 b6 63 24 e1 c8 d3 04 1b 55 80 69 b2 71 21 eb 8a 71 0f 8a 16 c5 b4 b9 83 69 a0 21 db 84 8b 7f 31 82 f7 7c 63 45 31 c2 1c 85 45 e7 43 43 0c 55 29 64 7c fc 0c 43 bd ae d6 56 06 ae c5 2a cd ab 89 01 eb 36 74 ad 9b cf b6 46 83 4a fb 3a 1f 18 64 10 73 85 d7 b9 42 1d 88 da 93 14 26 26 af 00 a8 df b5 44 46 a7 eb 88 42 15 5e 06 60 a5 17 4d 37 45 8d 52 de 6e 50 55 b6 e6 46 9e 28 9d 04 f4 5e 69 74 19 dd d6 92 e7 fc 6c 6c a5 28 02 0e 7e d3 3e 99 39 b0 fd fa 5a af 82 eb 37 dd 57 6d fe e1 51 0a 34 cd 22 22 45 85 f1 1a 4c 59 cc 24 40 f3 af 89 c6 79 1f e9 6e 44 9d e5 47 b2 fb 22 48 9b 70 2d 77 c8 d7 51 b3 df 52 9d 59 48 e0".replace(
    " ", ""
)


def create_tails_hash(tails_file):
    sha256 = hashlib.sha256()
    sha256.update(tails_file.read())
    digest = sha256.digest()
    return base58.b58encode(digest).decode("utf-8")


@pytest.fixture()
def valid_tails_file():
    """Generate a valid tails file."""
    tails_file_hex = TAILS_FILE_HEX[:-6] + str(uuid.uuid4())[:6]
    tails_file_bytes = bytes.fromhex(tails_file_hex)
    tails_file = io.BytesIO(tails_file_bytes)
    tails_hash = create_tails_hash(tails_file)

    return tails_file, tails_hash


@pytest.fixture()
def invalid_start_bytes_tails_file():
    """Generate invalid tails file."""
    tails_file_hex = "0003" + TAILS_FILE_HEX[4:]
    tails_file_bytes = bytes.fromhex(tails_file_hex)
    tails_file = io.BytesIO(tails_file_bytes)
    tails_hash = create_tails_hash(tails_file)

    return tails_file, tails_hash


@pytest.fixture()
def invalid_hash_tails_file():
    """Generate invalid tails file."""
    tails_file_hex = TAILS_FILE_HEX[:-6] + str(uuid.uuid4())[:6]
    tails_file_bytes = bytes.fromhex(tails_file_hex)
    tails_file = io.BytesIO(tails_file_bytes)
    tails_hash = create_tails_hash(tails_file)
    tails_hash = tails_hash[:-6] + str(uuid.uuid4())[:6]

    return tails_file, tails_hash


@pytest.fixture()
def invalid_size_tails_file():
    """Generate invalid tails file."""
    tails_file_hex = TAILS_FILE_HEX[:-2]
    tails_file_bytes = bytes.fromhex(tails_file_hex)
    tails_file = io.BytesIO(tails_file_bytes)
    tails_hash = create_tails_hash(tails_file)

    return tails_file, tails_hash


@pytest.fixture(scope="function")
def test_client():
    """Create a test client."""
    os.environ["ENABLE_TAILS"] = "true"
    os.environ["WEBVH_ENDORSEMENT"] = "false"
    with TestClient(app) as test_client:
        yield test_client
