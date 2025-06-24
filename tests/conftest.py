"""
Test configuration and fixtures for avidtools.
"""

import pytest
from typing import Dict, Any


@pytest.fixture
def sample_atlas_case_study() -> Dict[str, Any]:
    """Sample ATLAS case study data for testing."""
    return {
        "id": "AML.CS0001",
        "name": "Sample ATLAS Case Study",
        "target": "ML Model System",
        "summary": "This is a sample case study for testing purposes.",
        "incident-date": "2023-01-15",
        "reporter": "Test Reporter",
        "references": [
            {
                "title": "Reference 1",
                "url": "https://example.com/ref1"
            },
            {
                "title": "Reference 2",
                "url": "https://example.com/ref2"
            }
        ]
    }


@pytest.fixture
def sample_cve_data() -> Dict[str, Any]:
    """Sample CVE data for testing."""
    return {
        "id": "CVE-2023-12345",
        "descriptions": [
            {"lang": "en", "value": "Test CVE description"}
        ],
        "published": "2023-01-15T10:00:00.000Z",
        "lastModified": "2023-01-16T12:00:00.000Z",
        "sourceIdentifier": "test@example.com",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
        "cpe": [],
        "references": []
    }


@pytest.fixture
def mock_requests_get(mocker):
    """Mock requests.get for testing external API calls."""
    return mocker.patch("requests.get")


@pytest.fixture
def mock_nvdlib_search(mocker):
    """Mock nvdlib.searchCVE for testing CVE imports."""
    return mocker.patch("nvdlib.searchCVE")
