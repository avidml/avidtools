"""
Unit tests for CVE connector.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import date

from avidtools.connectors.cve import import_cve, convert_cve
from avidtools.datamodels.vulnerability import Vulnerability
from avidtools.datamodels.enums import ArtifactTypeEnum, ClassEnum, TypeEnum


class MockCVE:
    """Mock CVE object for testing."""
    
    def __init__(self, cve_data):
        self.id = cve_data["id"]
        self.descriptions = [
            Mock(value=desc["value"]) for desc in cve_data["descriptions"]
        ]
        self.published = cve_data["published"]
        self.lastModified = cve_data["lastModified"]
        self.sourceIdentifier = cve_data["sourceIdentifier"]
        self.url = cve_data["url"]
        self.cpe = [Mock(criteria=cpe) for cpe in cve_data.get("cpe", [])]
        self.references = [
            Mock(url=ref) for ref in cve_data.get("references", [])
        ]


class TestCVEConnector:
    """Test cases for CVE connector functions."""

    @patch('avidtools.connectors.cve.nvdlib.searchCVE')
    def test_import_cve_success(self, mock_search):
        """Test successful import of CVE."""
        cve_id = "CVE-2023-12345"
        mock_cve = MockCVE({
            "id": cve_id,
            "descriptions": [{"value": "Test description"}],
            "published": "2023-01-15T10:00:00.000Z",
            "lastModified": "2023-01-16T12:00:00.000Z",
            "sourceIdentifier": "test@example.com",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
        })
        
        mock_search.return_value = [mock_cve]
        
        result = import_cve(cve_id)
        assert result.id == cve_id
        mock_search.assert_called_once_with(cveId=cve_id)

    @patch('avidtools.connectors.cve.nvdlib.searchCVE')
    def test_import_cve_not_found(self, mock_search):
        """Test import CVE when not found."""
        mock_search.return_value = []
        
        with pytest.raises(IndexError):
            import_cve("CVE-9999-99999")

    def test_convert_cve_basic(self, sample_cve_data):
        """Test basic conversion of CVE to AVID vulnerability."""
        mock_cve = MockCVE(sample_cve_data)
        vuln = convert_cve(mock_cve)
        
        assert isinstance(vuln, Vulnerability)
        assert vuln.data_type == "AVID"
        
        # Check problemtype
        assert vuln.problemtype is not None
        assert vuln.problemtype.classof == ClassEnum.cve
        assert vuln.problemtype.type == TypeEnum.advisory
        assert vuln.problemtype.description.lang == "eng"
        assert vuln.problemtype.description.value == "Test CVE description"

    def test_convert_cve_with_cpe(self, sample_cve_data):
        """Test CVE conversion with CPE data."""
        sample_cve_data["cpe"] = [
            "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:other:software:2.0:*:*:*:*:*:*:*"
        ]
        
        mock_cve = MockCVE(sample_cve_data)
        vuln = convert_cve(mock_cve)
        
        # Check affects
        assert vuln.affects is not None
        assert len(vuln.affects.developer) == 2
        assert "vendor" in vuln.affects.developer
        assert "other" in vuln.affects.developer
        assert vuln.affects.deployer == []
        assert len(vuln.affects.artifacts) == 2
        assert vuln.affects.artifacts[0].type == ArtifactTypeEnum.system

    def test_convert_cve_references(self, sample_cve_data):
        """Test conversion of CVE references."""
        sample_cve_data["references"] = [
            "https://example.com/advisory",
            "https://github.com/vendor/repo/issues/123"
        ]
        
        mock_cve = MockCVE(sample_cve_data)
        vuln = convert_cve(mock_cve)
        
        assert vuln.references is not None
        assert len(vuln.references) == 3  # 1 NVD + 2 additional
        
        # Check NVD reference
        nvd_ref = vuln.references[0]
        assert nvd_ref.type == "source"
        assert nvd_ref.label == "NVD entry"
        assert nvd_ref.url == sample_cve_data["url"]
        
        # Check additional references
        for i, ref in enumerate(vuln.references[1:], 1):
            assert ref.type == "source"
            assert ref.url == sample_cve_data["references"][i-1]

    def test_convert_cve_description(self, sample_cve_data):
        """Test conversion of CVE description."""
        mock_cve = MockCVE(sample_cve_data)
        vuln = convert_cve(mock_cve)
        
        assert vuln.description is not None
        assert vuln.description.lang == "eng"
        assert vuln.description.value == f"{sample_cve_data['id']} Detail"

    def test_convert_cve_credit(self, sample_cve_data):
        """Test conversion of CVE credit information."""
        mock_cve = MockCVE(sample_cve_data)
        vuln = convert_cve(mock_cve)
        
        assert vuln.credit is not None
        assert len(vuln.credit) == 1
        assert vuln.credit[0].lang == "eng"
        assert vuln.credit[0].value == sample_cve_data["sourceIdentifier"]

    def test_convert_cve_dates(self, sample_cve_data):
        """Test conversion of CVE date fields."""
        mock_cve = MockCVE(sample_cve_data)
        vuln = convert_cve(mock_cve)
        
        assert vuln.published_date == date(2023, 1, 15)
        assert vuln.last_modified_date == date(2023, 1, 16)

    def test_convert_cve_empty_cpe(self, sample_cve_data):
        """Test CVE conversion with empty CPE list."""
        sample_cve_data["cpe"] = []
        
        mock_cve = MockCVE(sample_cve_data)
        vuln = convert_cve(mock_cve)
        
        assert vuln.affects is not None
        assert vuln.affects.developer == []
        assert vuln.affects.deployer == []
        assert vuln.affects.artifacts == []

    def test_convert_cve_empty_references(self, sample_cve_data):
        """Test CVE conversion with empty references."""
        sample_cve_data["references"] = []
        
        mock_cve = MockCVE(sample_cve_data)
        vuln = convert_cve(mock_cve)
        
        assert vuln.references is not None
        assert len(vuln.references) == 1  # Only NVD reference
        assert vuln.references[0].label == "NVD entry"
