"""Unit tests for the tails router endpoints."""

import io
import uuid
import pytest
from fastapi.testclient import TestClient

from app import app
from app.plugins.storage import StorageManager
from tests.conftest import create_tails_hash, TAILS_FILE_HEX


@pytest.fixture(autouse=True)
async def setup_database():
    """Set up the database before each test."""
    storage = StorageManager()
    await storage.provision()
    yield
    # Tests clean up is handled by pytest-asyncio and test isolation


class TestUploadTailsFile:
    """Test cases for uploading tails files."""

    @pytest.mark.asyncio
    async def test_upload_tails_file_success(self, valid_tails_file):
        """Test successful tails file upload."""
        tails_file, tails_hash = valid_tails_file
        with TestClient(app) as test_client:
            response = test_client.put(
                f"/tails/hash/{tails_hash}",
                files={"tails": (tails_hash, tails_file, "multipart/form-data")},
            )
        assert response.status_code == 201
        assert response.text == tails_hash

    @pytest.mark.asyncio
    async def test_upload_tails_file_invalid_start_bytes(self, invalid_start_bytes_tails_file):
        """Test upload fails with invalid start bytes."""
        tails_file, tails_hash = invalid_start_bytes_tails_file
        with TestClient(app) as test_client:
            response = test_client.put(
                f"/tails/hash/{tails_hash}",
                files={"tails": (tails_hash, tails_file, "multipart/form-data")},
            )
        assert response.status_code == 400
        assert response.json() == {"detail": 'Tails file must start with "00 02".'}

    @pytest.mark.asyncio
    async def test_upload_tails_file_invalid_hash(self, invalid_hash_tails_file):
        """Test upload fails when hash doesn't match file content."""
        tails_file, tails_hash = invalid_hash_tails_file
        with TestClient(app) as test_client:
            response = test_client.put(
                f"/tails/hash/{tails_hash}",
                files={"tails": (tails_hash, tails_file, "multipart/form-data")},
            )
        assert response.status_code == 400
        assert response.json() == {"detail": "tailsHash does not match hash of file."}

    @pytest.mark.asyncio
    async def test_upload_tails_file_invalid_size(self, invalid_size_tails_file):
        """Test upload fails with invalid file size."""
        tails_file, tails_hash = invalid_size_tails_file
        with TestClient(app) as test_client:
            response = test_client.put(
                f"/tails/hash/{tails_hash}",
                files={"tails": (tails_hash, tails_file, "multipart/form-data")},
            )
        assert response.status_code == 400
        assert response.json() == {"detail": "Tails file is not the correct size."}

    @pytest.mark.asyncio
    async def test_upload_tails_file_invalid_headers(self, valid_tails_file):
        """Test upload fails without proper multipart/form-data header."""
        tails_file, tails_hash = valid_tails_file
        with TestClient(app) as test_client:
            response = test_client.put(f"/tails/hash/{tails_hash}", content=tails_file)
        assert response.status_code == 400
        assert response.json() == {"detail": "Expecting multipart/form-data content-type."}


class TestGetTailsFile:
    """Test cases for retrieving tails files."""

    @pytest.mark.asyncio
    async def test_get_tails_file_success(self, valid_tails_file):
        """Test successful retrieval of uploaded tails file."""
        tails_file, tails_hash = valid_tails_file
        with TestClient(app) as test_client:
            # First upload the file
            upload_response = test_client.put(
                f"/tails/hash/{tails_hash}",
                files={"tails": (tails_hash, tails_file, "multipart/form-data")},
            )
            assert upload_response.status_code == 201

            # Then retrieve it
            response = test_client.get(f"/tails/hash/{tails_hash}")

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"
        # Verify the content matches what was uploaded
        tails_file.seek(0)
        assert response.content == tails_file.read()

    @pytest.mark.asyncio
    async def test_get_tails_file_not_found(self, valid_tails_file):
        """Test retrieval of non-existent tails file returns 404."""
        tails_file, tails_hash = valid_tails_file
        with TestClient(app) as test_client:
            response = test_client.get(f"/tails/hash/{tails_hash}")
        assert response.status_code == 404
        assert response.json() == {"detail": "Not Found"}

    @pytest.mark.asyncio
    async def test_get_tails_file_with_different_hash(self, valid_tails_file):
        """Test retrieval with a different hash returns 404."""
        tails_file, tails_hash = valid_tails_file
        with TestClient(app) as test_client:
            # Upload with correct hash
            upload_response = test_client.put(
                f"/tails/hash/{tails_hash}",
                files={"tails": (tails_hash, tails_file, "multipart/form-data")},
            )
            assert upload_response.status_code == 201

            # Try to retrieve with different hash
            different_hash = "9" + tails_hash[1:]
            response = test_client.get(f"/tails/hash/{different_hash}")

        assert response.status_code == 404
        assert response.json() == {"detail": "Not Found"}


class TestTailsFileIntegration:
    """Integration tests for tails file operations."""

    @pytest.mark.asyncio
    async def test_upload_and_retrieve_multiple_files(self, valid_tails_file):
        """Test uploading and retrieving multiple tails files."""
        # Generate multiple unique tails files (use full UUID for better uniqueness)
        files = []
        for _ in range(3):
            # Use 12 hex chars from UUID to ensure uniqueness across test runs
            unique_suffix = str(uuid.uuid4()).replace("-", "")[:12]
            tails_file_hex = TAILS_FILE_HEX[:-12] + unique_suffix
            tails_file_bytes = bytes.fromhex(tails_file_hex)
            tails_file = io.BytesIO(tails_file_bytes)
            tails_hash = create_tails_hash(tails_file)
            files.append((tails_file, tails_hash))

        with TestClient(app) as test_client:
            # Upload all files
            for tails_file, tails_hash in files:
                tails_file.seek(0)
                response = test_client.put(
                    f"/tails/hash/{tails_hash}",
                    files={"tails": (tails_hash, tails_file, "multipart/form-data")},
                )
                assert response.status_code == 201
                assert response.text == tails_hash

            # Retrieve all files
            for tails_file, tails_hash in files:
                response = test_client.get(f"/tails/hash/{tails_hash}")
                assert response.status_code == 200

                # Verify content matches
                tails_file.seek(0)
                assert response.content == tails_file.read()

    @pytest.mark.asyncio
    async def test_storage_persistence(self, valid_tails_file):
        """Test that tails files persist in database storage."""
        tails_file, tails_hash = valid_tails_file
        storage = StorageManager()

        with TestClient(app) as test_client:
            # Upload file
            response = test_client.put(
                f"/tails/hash/{tails_hash}",
                files={"tails": (tails_hash, tails_file, "multipart/form-data")},
            )
            assert response.status_code == 201

        # Verify it's in the database
        stored_file = storage.get_tails_file(tails_hash)
        assert stored_file is not None
        assert stored_file.tails_hash == tails_hash
        assert stored_file.file_size > 0

        # Verify we can reconstruct the original file
        tails_file.seek(0)
        original_content = tails_file.read()
        stored_content = bytes.fromhex(stored_file.file_content_hex)
        assert stored_content == original_content
