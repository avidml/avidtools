"""
Unit tests for ATLAS connector.
"""

import yaml
import responses

from avidtools.connectors.atlas import import_case_study, convert_case_study
from avidtools.datamodels.report import Report
from avidtools.datamodels.enums import ArtifactTypeEnum, ClassEnum, TypeEnum


class TestAtlasConnector:
    """Test cases for ATLAS connector functions."""

    @responses.activate
    def test_import_case_study_success(self):
        """Test successful import of ATLAS case study."""
        case_study_id = "AML.CS0001"
        mock_data = {
            "id": case_study_id,
            "name": "Test Case Study",
            "target": "ML System",
            "summary": "Test summary"
        }
        
        # Mock the HTTP response
        url = (
            "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/"
            f"data/case-studies/{case_study_id}.yaml"
        )
        responses.add(
            responses.GET,
            url,
            body=yaml.dump(mock_data),
            status=200
        )
        
        result = import_case_study(case_study_id)
        assert result["id"] == case_study_id
        assert result["name"] == "Test Case Study"

    @responses.activate
    def test_import_case_study_http_error(self):
        """Test import case study with HTTP error."""
        case_study_id = "AML.CS9999"
        
        # Mock HTTP error response
        url = (
            "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/"
            f"data/case-studies/{case_study_id}.yaml"
        )
        responses.add(
            responses.GET,
            url,
            status=404
        )
        
        # The function doesn't currently raise an exception for HTTP errors
        # It returns whatever yaml.safe_load returns for the error content
        result = import_case_study(case_study_id)
        # With a 404, the content will be empty and yaml.safe_load returns None
        assert result is None

    def test_convert_case_study_basic(self, sample_atlas_case_study):
        """Test basic conversion of ATLAS case study to AVID report."""
        report = convert_case_study(sample_atlas_case_study)
        
        assert isinstance(report, Report)
        assert report.data_type == "AVID"
        
        # Check affects
        assert report.affects is not None
        assert report.affects.developer == []
        assert report.affects.deployer == [sample_atlas_case_study["target"]]
        assert len(report.affects.artifacts) == 1
        assert report.affects.artifacts[0].type == ArtifactTypeEnum.system
        assert (
            report.affects.artifacts[0].name ==
            sample_atlas_case_study["target"]
        )
        
        # Check problemtype
        assert report.problemtype is not None
        assert report.problemtype.classof == ClassEnum.atlas
        assert report.problemtype.type == TypeEnum.advisory
        assert report.problemtype.description.lang == "eng"
        assert (
            report.problemtype.description.value ==
            sample_atlas_case_study["name"]
        )

    def test_convert_case_study_references(self, sample_atlas_case_study):
        """Test conversion of references in ATLAS case study."""
        report = convert_case_study(sample_atlas_case_study)
        
        assert report.references is not None
        assert len(report.references) == 3  # 1 source + 2 from references
        
        # Check main reference
        main_ref = report.references[0]
        assert main_ref.type == "source"
        assert main_ref.label == sample_atlas_case_study["name"]
        expected_url = (
            f"https://atlas.mitre.org/studies/"
            f"{sample_atlas_case_study['id']}"
        )
        assert main_ref.url == expected_url
        
        # Check additional references
        for i, ref in enumerate(report.references[1:], 1):
            expected_ref = sample_atlas_case_study["references"][i-1]
            assert ref.type == "source"
            assert ref.label == expected_ref["title"]
            assert ref.url == expected_ref["url"]

    def test_convert_case_study_description(self, sample_atlas_case_study):
        """Test conversion of description in ATLAS case study."""
        report = convert_case_study(sample_atlas_case_study)
        
        assert report.description is not None
        assert report.description.lang == "eng"
        assert report.description.value == sample_atlas_case_study["summary"]

    def test_convert_case_study_with_reporter(self, sample_atlas_case_study):
        """Test conversion with reporter information."""
        report = convert_case_study(sample_atlas_case_study)
        
        assert report.credit is not None
        assert len(report.credit) == 1
        assert report.credit[0].lang == "eng"
        assert report.credit[0].value == sample_atlas_case_study["reporter"]

    def test_convert_case_study_without_reporter(
        self, sample_atlas_case_study
    ):
        """Test conversion without reporter information."""
        case_study_no_reporter = sample_atlas_case_study.copy()
        del case_study_no_reporter["reporter"]
        
        report = convert_case_study(case_study_no_reporter)
        
        # Credit should be None when no reporter is provided
        assert report.credit is None

    def test_convert_case_study_reported_date(self, sample_atlas_case_study):
        """Test conversion of reported date."""
        report = convert_case_study(sample_atlas_case_study)
        
        assert report.reported_date == sample_atlas_case_study["incident-date"]

    def test_convert_case_study_empty_references(
        self, sample_atlas_case_study
    ):
        """Test conversion with empty references list."""
        case_study_empty_refs = sample_atlas_case_study.copy()
        case_study_empty_refs["references"] = []
        
        report = convert_case_study(case_study_empty_refs)
        
        assert report.references is not None
        assert len(report.references) == 1  # Only the main reference
