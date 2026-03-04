"""
Unit tests for CVE connector.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import date
import requests

from avidtools.connectors.cve import (
    convert_cve_to_report,
    convert_cve_to_vuln,
    extract_cve_details,
    import_cve,
)
from avidtools.datamodels.report import Report
from avidtools.datamodels.vulnerability import Vulnerability
from avidtools.datamodels.enums import ArtifactTypeEnum, ClassEnum, TypeEnum


class TestCVEConnector:
    """Test cases for CVE connector functions."""

    @patch("avidtools.connectors.cve.requests.get")
    def test_import_cve_success(self, mock_get, sample_cve_data):
        """Test successful import of CVE."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = sample_cve_data
        mock_get.return_value = mock_response

        result = import_cve("CVE-2023-12345")
        assert result == sample_cve_data
        mock_get.assert_called_once()

    @patch("avidtools.connectors.cve.requests.get")
    def test_import_cve_http_error(self, mock_get):
        """Test import CVE when not found."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "Not found"
        )
        mock_get.return_value = mock_response

        with pytest.raises(requests.HTTPError):
            import_cve("CVE-9999-99999")

    def test_extract_cve_details(self, sample_cve_data):
        """Test detail extraction from MITRE CVE JSON."""
        details = extract_cve_details(sample_cve_data)

        assert details["cve_id"] == "CVE-2023-12345"
        assert details["title"] == "Sample CVE title"
        assert details["description"] == "Test CVE description"
        assert details["published_date"] == "2023-01-15T10:00:00.000Z"
        assert details["last_modified_date"] == "2023-01-16T12:00:00.000Z"
        assert len(details["references"]) == 2
        assert len(details["affected_products"]) == 2

    def test_convert_cve_to_vuln_basic(self, sample_cve_data):
        """Test basic conversion of CVE to AVID vulnerability."""
        vuln = convert_cve_to_vuln(sample_cve_data)
        
        assert isinstance(vuln, Vulnerability)
        assert vuln.data_type == "AVID"
        
        # Check problemtype
        assert vuln.problemtype is not None
        assert vuln.problemtype.classof == ClassEnum.cve
        assert vuln.problemtype.type == TypeEnum.advisory
        assert vuln.problemtype.description.lang == "eng"
        assert (
            vuln.problemtype.description.value
            == "Sample CVE title (CVE-2023-12345)"
        )

    def test_convert_cve_to_vuln_with_affected_products(self, sample_cve_data):
        """Test CVE conversion with affected product data."""
        vuln = convert_cve_to_vuln(sample_cve_data)
        
        # Check affects
        assert vuln.affects is not None
        assert len(vuln.affects.developer) == 2
        assert "vendor" in vuln.affects.developer
        assert "other" in vuln.affects.developer
        assert len(vuln.affects.deployer) == 2
        assert len(vuln.affects.artifacts) == 2
        assert vuln.affects.artifacts[0].type == ArtifactTypeEnum.system

    def test_convert_cve_to_vuln_references(self, sample_cve_data):
        """Test conversion of CVE references."""
        vuln = convert_cve_to_vuln(sample_cve_data)
        
        assert vuln.references is not None
        assert len(vuln.references) == 3  # 1 NVD entry + 2 additional
        
        # Check base reference
        base_ref = vuln.references[0]
        assert base_ref.type == "source"
        assert base_ref.label == "NVD entry"
        assert (
            base_ref.url
            == "https://www.cve.org/CVERecord?id=CVE-2023-12345"
        )
        
        # Check additional references
        for i, ref in enumerate(vuln.references[1:], 1):
            assert ref.type == "source"
            assert ref.url == sample_cve_data["containers"]["cna"][
                "references"
            ][i - 1]["url"]

    def test_convert_cve_to_vuln_description(self, sample_cve_data):
        """Test conversion of CVE description."""
        vuln = convert_cve_to_vuln(sample_cve_data)
        
        assert vuln.description is not None
        assert vuln.description.lang == "eng"
        assert vuln.description.value == "Test CVE description"

    def test_convert_cve_to_vuln_credit(self, sample_cve_data):
        """Test conversion of CVE credit information."""
        vuln = convert_cve_to_vuln(sample_cve_data)
        
        assert vuln.credit is not None
        assert len(vuln.credit) == 1
        assert vuln.credit[0].lang == "eng"
        assert vuln.credit[0].value == sample_cve_data["cveMetadata"][
            "assignerOrgId"
        ]

    def test_convert_cve_to_vuln_dates(self, sample_cve_data):
        """Test conversion of CVE date fields."""
        vuln = convert_cve_to_vuln(sample_cve_data)
        
        assert vuln.published_date == date(2023, 1, 15)
        assert vuln.last_modified_date == date(2023, 1, 16)

    def test_convert_cve_to_vuln_empty_affected(self, sample_cve_data):
        """Test CVE conversion with empty affected products list."""
        sample_cve_data["containers"]["cna"]["affected"] = []
        vuln = convert_cve_to_vuln(sample_cve_data)
        
        assert vuln.affects is not None
        assert vuln.affects.developer == ["Unknown"]
        assert vuln.affects.deployer == ["Unknown"]
        assert len(vuln.affects.artifacts) == 1

    def test_convert_cve_to_vuln_empty_references(self, sample_cve_data):
        """Test CVE conversion with empty references."""
        sample_cve_data["containers"]["cna"]["references"] = []
        vuln = convert_cve_to_vuln(sample_cve_data)
        
        assert vuln.references is not None
        assert len(vuln.references) == 1  # Only base reference
        assert vuln.references[0].label == "NVD entry"

    def test_convert_cve_to_report(self, sample_cve_data):
        """Test conversion of CVE JSON to AVID report object."""
        report = convert_cve_to_report(sample_cve_data)

        assert isinstance(report, Report)
        assert report.data_type == "AVID"
        assert report.problemtype is not None
        assert report.problemtype.classof == ClassEnum.cve
