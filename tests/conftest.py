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
        "cveMetadata": {
            "cveId": "CVE-2023-12345",
            "datePublished": "2023-01-15T10:00:00.000Z",
            "dateUpdated": "2023-01-16T12:00:00.000Z",
            "assignerOrgId": "test@example.com",
        },
        "containers": {
            "cna": {
                "title": "Sample CVE title",
                "descriptions": [
                    {"lang": "en", "value": "Test CVE description"}
                ],
                "references": [
                    {"url": "https://example.com/advisory"},
                    {"url": "https://github.com/vendor/repo/issues/123"},
                ],
                "affected": [
                    {"vendor": "vendor", "product": "product"},
                    {"vendor": "other", "product": "software"},
                ],
            }
        },
    }


@pytest.fixture
def mock_requests_get(mocker):
    """Mock requests.get for testing external API calls."""
    return mocker.patch("requests.get")
