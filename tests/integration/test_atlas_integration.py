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
        
        # Create mock responses
        case_study_response = Mock()
        case_study_response.content = yaml.dump(case_study_data).encode()
        case_study_response.text = yaml.dump(case_study_data)
        
        # Create empty mock responses for tactics and techniques
        tactics_response = Mock()
        tactics_response.content = yaml.dump([]).encode()
        tactics_response.text = yaml.dump([])
        
        techniques_response = Mock()
        techniques_response.content = yaml.dump([]).encode()
        techniques_response.text = yaml.dump([])
        
        # Configure mock to return different responses based on the URL
        def side_effect(url):
            if 'case-studies' in url:
                return case_study_response
            elif 'tactics.yaml' in url:
                return tactics_response
            elif 'techniques.yaml' in url:
                return techniques_response
            return Mock()
            
        mock_get.side_effect = side_effect
        
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
        assert report.description.value.startswith(
            "Attackers submit clean files")
        assert len(report.references) == 2  # Main + 1 additional
        assert report.credit[0].value == "MITRE"
        assert report.reported_date == "2020-01-01"
        
        # Verify HTTP calls were made
        expected_case_study_url = (
            "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main"
            f"/data/case-studies/{case_study_id}.yaml"
        )
        expected_tactics_url = (
            "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main"
            "/data/tactics.yaml"
        )
        expected_techniques_url = (
            "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main"
            "/data/techniques.yaml"
        )
        
        # Check that all necessary calls were made
        mock_get.assert_any_call(expected_case_study_url)
        mock_get.assert_any_call(expected_tactics_url)
        mock_get.assert_any_call(expected_techniques_url)

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
        assert (report_dict["problemtype"]["description"]["value"] ==
                "Test Case")

    @pytest.mark.integration
    def test_report_with_procedure(self):
        """Test that reports with procedure data include Impact.atlas."""
        # Create a case study with procedure data
        case_study = {
            "id": "AML.CS0003",
            "name": "Test Case with Procedure",
            "target": "Test Target",
            "summary": "Test summary with procedure",
            "incident-date": "2023-01-01",
            "references": [],
            "procedure": [
                {
                    "tactic": "AML.TA0002",
                    "technique": "AML.T0000",
                    "description": "Reconnaissance step"
                },
                {
                    "tactic": "AML.TA0003",
                    "technique": "AML.T0002",
                    "description": "Resource development step"
                }
            ]
        }
        
        # Convert to report
        report = convert_case_study(case_study)
        
        # Test that impact with atlas data is created
        assert report.impact is not None
        assert report.impact.atlas is not None
        assert len(report.impact.atlas) == 2
        
        # Test JSON serialization
        json_data = report.model_dump_json()
        assert "impact" in json_data
        assert "atlas" in json_data
        
        # Test that serialized data contains procedure steps
        report_dict = report.model_dump()
        assert "impact" in report_dict
        assert "atlas" in report_dict["impact"]
        assert len(report_dict["impact"]["atlas"]) == 2
        assert report_dict["impact"]["atlas"][0]["tactic"] == "AML.TA0002"
        assert report_dict["impact"]["atlas"][0]["technique"] == "AML.T0000"
