"""
Unit tests for AVID data model enums.
"""

from avidtools.datamodels.enums import (
    ArtifactTypeEnum,
    SepEnum,
    LifecycleEnum,
    ClassEnum,
    TypeEnum,
    MethodEnum,
)


class TestArtifactTypeEnum:
    """Test cases for ArtifactTypeEnum."""

    def test_artifact_type_values(self):
        """Test that ArtifactTypeEnum has expected values."""
        assert ArtifactTypeEnum.dataset == "Dataset"
        assert ArtifactTypeEnum.model == "Model"
        assert ArtifactTypeEnum.system == "System"

    def test_artifact_type_membership(self):
        """Test membership in ArtifactTypeEnum."""
        assert "Dataset" in ArtifactTypeEnum
        assert "Model" in ArtifactTypeEnum
        assert "System" in ArtifactTypeEnum
        assert "Unknown" not in ArtifactTypeEnum


class TestSepEnum:
    """Test cases for SepEnum."""

    def test_sep_enum_security_categories(self):
        """Test security-related SEP categories."""
        assert SepEnum.S0100 == "S0100: Software Vulnerability"
        assert SepEnum.S0200 == "S0200: Supply Chain Compromise"
        assert SepEnum.S0400 == "S0400: Model Bypass"

    def test_sep_enum_ethics_categories(self):
        """Test ethics-related SEP categories."""
        assert SepEnum.E0100 == "E0100: Bias/ Discrimination"
        assert SepEnum.E0200 == "E0200: Explainability"
        assert SepEnum.E0400 == "E0400: Misinformation"

    def test_sep_enum_performance_categories(self):
        """Test performance-related SEP categories."""
        assert SepEnum.P0100 == "P0100: Data issues"
        assert SepEnum.P0200 == "P0200: Model issues"
        assert SepEnum.P0400 == "P0400: Safety"


class TestLifecycleEnum:
    """Test cases for LifecycleEnum."""

    def test_lifecycle_enum_values(self):
        """Test that LifecycleEnum has expected values."""
        assert LifecycleEnum.L01 == "L01: Business Understanding"
        assert LifecycleEnum.L02 == "L02: Data Understanding"
        assert LifecycleEnum.L03 == "L03: Data Preparation"
        assert LifecycleEnum.L04 == "L04: Model Development"
        assert LifecycleEnum.L05 == "L05: Evaluation"
        assert LifecycleEnum.L06 == "L06: Deployment"

    def test_lifecycle_enum_ordering(self):
        """Test that lifecycle enums maintain expected order."""
        lifecycle_stages = [
            LifecycleEnum.L01, LifecycleEnum.L02, LifecycleEnum.L03,
            LifecycleEnum.L04, LifecycleEnum.L05, LifecycleEnum.L06
        ]
        assert len(lifecycle_stages) == 6


class TestClassEnum:
    """Test cases for ClassEnum."""

    def test_class_enum_values(self):
        """Test that ClassEnum has expected values."""
        assert ClassEnum.aiid == "AIID Incident"
        assert ClassEnum.atlas == "ATLAS Case Study"
        assert ClassEnum.cve == "CVE Entry"
        assert ClassEnum.llm == "LLM Evaluation"
        assert ClassEnum.na == "Undefined"


class TestTypeEnum:
    """Test cases for TypeEnum."""

    def test_type_enum_values(self):
        """Test that TypeEnum has expected values."""
        assert TypeEnum.issue == "Issue"
        assert TypeEnum.advisory == "Advisory"
        assert TypeEnum.measurement == "Measurement"
        assert TypeEnum.detection == "Detection"


class TestMethodEnum:
    """Test cases for MethodEnum."""

    def test_method_enum_values(self):
        """Test that MethodEnum has expected values."""
        assert MethodEnum.test == "Significance Test"
        assert MethodEnum.thres == "Static Threshold"
