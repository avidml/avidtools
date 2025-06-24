"""
Unit tests for Inspect connector.
"""

import pytest
from unittest.mock import Mock, patch

from avidtools.connectors.inspect import (
    import_eval_log,
    convert_eval_log,
    human_readable_name
)
from avidtools.datamodels.report import Report
from avidtools.datamodels.enums import ArtifactTypeEnum, ClassEnum, TypeEnum


class MockEvalLog:
    """Mock EvalLog object for testing."""
    
    def __init__(self):
        self.eval = Mock()
        self.eval.model = "openai/gpt-4"
        self.eval.task = "benchmarks/truthfulqa"
        self.eval.dataset = Mock()
        self.eval.dataset.name = "truthfulqa"
        self.eval.dataset.location = "https://example.com/dataset"
        # Create a mock metric with proper name attribute
        mock_metric = Mock()
        mock_metric.name = "accuracy/score"
        
        # Create a mock scorer with proper name attribute
        mock_scorer = Mock()
        mock_scorer.name = "accuracy"
        mock_scorer.metrics = [mock_metric]
        
        self.eval.scorers = [mock_scorer]
        
        self.samples = [
            Mock(
                input="What is 2+2?",
                output="4",
                score=Mock(value=1.0)
            )
        ]
        
        # Create mock results with scores
        mock_score = Mock()
        mock_score.name = "accuracy"
        mock_score.metrics = {"accuracy": Mock(value=0.95)}
        
        self.results = Mock()
        self.results.scores = [mock_score]


class TestInspectConnector:
    """Test cases for Inspect connector functions."""

    @patch('avidtools.connectors.inspect.read_eval_log')
    def test_import_eval_log_success(self, mock_read_eval_log):
        """Test successful import of evaluation log."""
        file_path = "/path/to/eval.json"
        mock_eval_log = MockEvalLog()
        mock_read_eval_log.return_value = mock_eval_log
        
        result = import_eval_log(file_path)
        
        assert result == mock_eval_log
        mock_read_eval_log.assert_called_once_with(file_path)

    @patch('avidtools.connectors.inspect.read_eval_log')
    def test_import_eval_log_missing_import(self, mock_read_eval_log):
        """Test import when inspect_ai is not available."""
        mock_read_eval_log.side_effect = ImportError(
            "inspect_ai package is required for this functionality"
        )
        
        with pytest.raises(ImportError):
            import_eval_log("/path/to/eval.json")

    def test_human_readable_name_mapping(self):
        """Test human readable name mappings."""
        assert human_readable_name["openai"] == "OpenAI"
        assert human_readable_name["anthropic"] == "Anthropic"
        assert human_readable_name["google"] == "Google"
        assert human_readable_name["huggingface"] == "Hugging Face"
        assert human_readable_name["meta-llama"] == "Meta"

    @patch('avidtools.connectors.inspect.import_eval_log')
    def test_convert_eval_log_basic(self, mock_import):
        """Test basic conversion of evaluation log to AVID reports."""
        mock_eval_log = MockEvalLog()
        mock_import.return_value = mock_eval_log
        
        file_path = "/path/to/eval.json"
        reports = convert_eval_log(file_path)
        
        assert len(reports) == 1
        assert isinstance(reports[0], Report)
        
        report = reports[0]
        assert report.data_type == "AVID"

    @patch('avidtools.connectors.inspect.import_eval_log')
    def test_convert_eval_log_affects(self, mock_import):
        """Test conversion of affects information."""
        mock_eval_log = MockEvalLog()
        mock_import.return_value = mock_eval_log
        
        reports = convert_eval_log("/path/to/eval.json")
        report = reports[0]
        
        assert report.affects is not None
        assert report.affects.developer == ["OpenAI"]
        assert report.affects.deployer == ["openai/gpt-4"]
        assert len(report.affects.artifacts) == 1
        assert report.affects.artifacts[0].type == ArtifactTypeEnum.model
        assert report.affects.artifacts[0].name == "gpt-4"

    @patch('avidtools.connectors.inspect.import_eval_log')
    def test_convert_eval_log_problemtype(self, mock_import):
        """Test conversion of problemtype information."""
        mock_eval_log = MockEvalLog()
        mock_import.return_value = mock_eval_log
        
        reports = convert_eval_log("/path/to/eval.json")
        report = reports[0]
        
        assert report.problemtype is not None
        assert report.problemtype.classof == ClassEnum.llm
        assert report.problemtype.type == TypeEnum.measurement
        assert report.problemtype.description.lang == "eng"
        assert "gpt-4" in report.problemtype.description.value
        assert "truthfulqa" in report.problemtype.description.value

    @patch('avidtools.connectors.inspect.import_eval_log')
    def test_convert_eval_log_references(self, mock_import):
        """Test conversion of references."""
        mock_eval_log = MockEvalLog()
        mock_import.return_value = mock_eval_log
        
        reports = convert_eval_log("/path/to/eval.json")
        report = reports[0]
        
        assert report.references is not None
        assert len(report.references) == 1
        
        ref = report.references[0]
        assert ref.type == "source"
        assert "truthfulqa" in ref.label
        assert ref.url == "https://example.com/dataset"

    @patch('avidtools.connectors.inspect.import_eval_log')
    def test_convert_eval_log_metrics(self, mock_import):
        """Test conversion of metrics."""
        mock_eval_log = MockEvalLog()
        mock_import.return_value = mock_eval_log
        
        reports = convert_eval_log("/path/to/eval.json")
        report = reports[0]
        
        assert report.metrics is not None
        assert len(report.metrics) == 1
        
        metric = report.metrics[0]
        assert metric.name == "accuracy"
        assert metric.detection_method.name == "accuracy"
        assert metric.results["value"] == 0.95
        assert metric.results["scorer"] == "accuracy"

    @patch('avidtools.connectors.inspect.import_eval_log')
    def test_convert_eval_log_description(self, mock_import):
        """Test conversion of description."""
        mock_eval_log = MockEvalLog()
        mock_import.return_value = mock_eval_log
        
        reports = convert_eval_log("/path/to/eval.json")
        report = reports[0]
        
        assert report.description is not None
        assert report.description.lang == "eng"
        assert "gpt-4" in report.description.value
        assert "truthfulqa" in report.description.value
        assert "What is 2+2?" in report.description.value
        assert "4" in report.description.value

    @patch('avidtools.connectors.inspect.import_eval_log')
    def test_convert_eval_log_multiple_samples(self, mock_import):
        """Test conversion with multiple samples."""
        mock_eval_log = MockEvalLog()
        mock_eval_log.samples = [
            Mock(
                input="Question 1",
                output="Answer 1",
                score=Mock(value=0.8)
            ),
            Mock(
                input="Question 2",
                output="Answer 2",
                score=Mock(value=0.9)
            )
        ]
        mock_import.return_value = mock_eval_log
        
        reports = convert_eval_log("/path/to/eval.json")
        
        assert len(reports) == 2
        assert all(isinstance(r, Report) for r in reports)
        assert "Question 1" in reports[0].description.value
        assert "Question 2" in reports[1].description.value

    @patch('avidtools.connectors.inspect.import_eval_log')
    def test_convert_eval_log_different_model(self, mock_import):
        """Test conversion with different model provider."""
        mock_eval_log = MockEvalLog()
        mock_eval_log.eval.model = "anthropic/claude-3"
        mock_import.return_value = mock_eval_log
        
        reports = convert_eval_log("/path/to/eval.json")
        report = reports[0]
        
        assert report.affects.developer == ["Anthropic"]
        assert report.affects.deployer == ["anthropic/claude-3"]
        assert report.affects.artifacts[0].name == "claude-3"
