"""
Integration tests for avidtools.

These tests verify that different components work together correctly.
"""

import pytest
from unittest.mock import Mock, patch
import yaml

from avidtools.connectors.atlas import import_case_study, convert_case_study
from avidtools.datamodels.report import Report


class TestAtlasIntegration:
    """Integration tests for ATLAS workflow."""

    @pytest.mark.integration
    @patch('avidtools.connectors.atlas.requests.get')
    def test_full_atlas_workflow(self, mock_get):
        """Test complete ATLAS case study import and conversion workflow."""
        # Mock HTTP response with realistic ATLAS data
        case_study_data = {
            "id": "AML.CS0001",
            "name": "VirusTotal Poisoning",
            "target": "VirusTotal",
            "summary": (
                "Attackers submit clean files followed by malicious files "
                "with the same hash."
            ),
            "incident-date": "2020-01-01",
            "reporter": "MITRE",
            "references": [
                {
                    "title": "VirusTotal Documentation",
                    "url": "https://developers.virustotal.com/"
                }
            ]
        }
        
        # Mock the HTTP response
        mock_response = Mock()
        mock_response.content = yaml.dump(case_study_data).encode()
        mock_get.return_value = mock_response
        
        # Test the full workflow
        case_study_id = "AML.CS0001"
        
        # Step 1: Import case study
        imported_data = import_case_study(case_study_id)
        assert imported_data["id"] == case_study_id
        assert imported_data["name"] == "VirusTotal Poisoning"
        
        # Step 2: Convert to AVID report
        report = convert_case_study(imported_data)
        assert isinstance(report, Report)
        assert report.data_type == "AVID"
        
        # Step 3: Verify all data is properly converted
        assert report.affects.deployer == ["VirusTotal"]
        assert report.problemtype.description.value == "VirusTotal Poisoning"
        assert report.description.value.startswith("Attackers submit clean files")
        assert len(report.references) == 2  # Main + 1 additional
        assert report.credit[0].value == "MITRE"
        assert report.reported_date == "2020-01-01"
        
        # Verify HTTP call was made correctly
        expected_url = (
            "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/"
            f"data/case-studies/{case_study_id}.yaml"
        )
        mock_get.assert_called_once_with(expected_url)

    @pytest.mark.integration  
    def test_report_serialization(self):
        """Test that converted reports can be serialized properly."""
        # Create a minimal case study
        case_study = {
            "id": "AML.CS0002",
            "name": "Test Case",
            "target": "Test Target",
            "summary": "Test summary",
            "incident-date": "2023-01-01",
            "references": []
        }
        
        # Convert to report
        report = convert_case_study(case_study)
        
        # Test JSON serialization
        json_data = report.model_dump_json()
        assert isinstance(json_data, str)
        assert "AVID" in json_data
        assert "Test Case" in json_data
        
        # Test that serialized data can be loaded back
        report_dict = report.model_dump()
        assert report_dict["data_type"] == "AVID"
        assert report_dict["problemtype"]["description"]["value"] == "Test Case"
