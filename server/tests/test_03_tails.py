import pytest

from fastapi.testclient import TestClient

from app import app

TAILS_FILE_HASH = ""

# @pytest.mark.asyncio
# async def test_upload_tails_file():
#     REQUEST_BODY = {}
#     response = await upload_tails_file(REQUEST_BODY, TAILS_FILE_HASH)
#     decoded_response = response.body.decode()
#     assert decoded_response == TAILS_FILE_HASH


@pytest.mark.asyncio
async def test_upload_tails_file(valid_tails_file):
    tails_file, tails_hash = valid_tails_file
    with TestClient(app) as test_client:
        response = test_client.put(
            f"/tails/hash/{tails_hash}",
            files={"tails": (tails_hash, tails_file, "multipart/form-data")},
        )
    assert response.status_code == 201
    assert response.text == tails_hash


@pytest.mark.asyncio
async def test_upload_tails_file_invalid_start_bytes(invalid_start_bytes_tails_file):
    tails_file, tails_hash = invalid_start_bytes_tails_file
    with TestClient(app) as test_client:
        response = test_client.put(
            f"/tails/hash/{tails_hash}",
            files={"tails": (tails_hash, tails_file, "multipart/form-data")},
        )
    assert response.status_code == 400
    assert response.json() == {"detail": 'Tails file must start with "00 02".'}


@pytest.mark.asyncio
async def test_upload_tails_file_invalid_hash(invalid_hash_tails_file):
    tails_file, tails_hash = invalid_hash_tails_file
    with TestClient(app) as test_client:
        response = test_client.put(
            f"/tails/hash/{tails_hash}",
            files={"tails": (tails_hash, tails_file, "multipart/form-data")},
        )
    assert response.status_code == 400
    assert response.json() == {"detail": "tailsHash does not match hash of file."}


@pytest.mark.asyncio
async def test_upload_tails_file_invalid_size(invalid_size_tails_file):
    tails_file, tails_hash = invalid_size_tails_file
    with TestClient(app) as test_client:
        response = test_client.put(
            f"/tails/hash/{tails_hash}",
            files={"tails": (tails_hash, tails_file, "multipart/form-data")},
        )
    assert response.status_code == 400
    assert response.json() == {"detail": "Tails file is not the correct size."}


@pytest.mark.asyncio
async def test_upload_tails_file_invalid_headers(valid_tails_file):
    tails_file, tails_hash = valid_tails_file
    with TestClient(app) as test_client:
        response = test_client.put(f"/tails/hash/{tails_hash}", content=tails_file)
    assert response.status_code == 400
    assert response.json() == {"detail": "Expecting multipart/form-data content-type."}


@pytest.mark.asyncio
async def test_get_tails_file(valid_tails_file):
    tails_file, tails_hash = valid_tails_file
    with TestClient(app) as test_client:
        test_client.put(
            f"/tails/hash/{tails_hash}",
            files={"tails": (tails_hash, tails_file, "multipart/form-data")},
        )
        response = test_client.get(f"/tails/hash/{tails_hash}")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_get_tails_file_not_found(valid_tails_file):
    tails_file, tails_hash = valid_tails_file
    with TestClient(app) as test_client:
        response = test_client.get(f"/tails/hash/{tails_hash}")
    assert response.status_code == 404
