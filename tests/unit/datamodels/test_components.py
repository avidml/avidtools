"""
Unit tests for AVID data model components.
"""

import pytest
from pydantic import ValidationError

from avidtools.datamodels.components import (
    LangValue,
    Artifact,
    Detection,
    Affects,
    Problemtype,
    Metric,
    Reference,
    AvidTaxonomy,
    Impact,
)
from avidtools.datamodels.enums import (
    ArtifactTypeEnum,
    ClassEnum,
    LifecycleEnum,
    MethodEnum,
    SepEnum,
    TypeEnum,
)


class TestLangValue:
    """Test cases for LangValue data model."""

    def test_lang_value_creation(self):
        """Test creating a valid LangValue instance."""
        lang_value = LangValue(lang="en", value="Test value")
        assert lang_value.lang == "en"
        assert lang_value.value == "Test value"

    def test_lang_value_validation(self):
        """Test LangValue validation."""
        with pytest.raises(ValidationError):
            LangValue(lang="en")  # Missing value

        with pytest.raises(ValidationError):
            LangValue(value="Test value")  # Missing lang


class TestArtifact:
    """Test cases for Artifact data model."""

    def test_artifact_creation(self):
        """Test creating a valid Artifact instance."""
        artifact = Artifact(type=ArtifactTypeEnum.model, name="Test Model")
        assert artifact.type == ArtifactTypeEnum.model
        assert artifact.name == "Test Model"

    def test_artifact_validation(self):
        """Test Artifact validation."""
        with pytest.raises(ValidationError):
            Artifact(type="invalid_type", name="Test Model")

        with pytest.raises(ValidationError):
            Artifact(type=ArtifactTypeEnum.model)  # Missing name


class TestDetection:
    """Test cases for Detection data model."""

    def test_detection_creation(self):
        """Test creating a valid Detection instance."""
        detection = Detection(type=MethodEnum.test, name="Statistical Test")
        assert detection.type == MethodEnum.test
        assert detection.name == "Statistical Test"


class TestAffects:
    """Test cases for Affects data model."""

    def test_affects_creation(self):
        """Test creating a valid Affects instance."""
        artifact = Artifact(type=ArtifactTypeEnum.model, name="Test Model")
        affects = Affects(
            developer=["OpenAI"],
            deployer=["Company A"],
            artifacts=[artifact]
        )
        assert affects.developer == ["OpenAI"]
        assert affects.deployer == ["Company A"]
        assert len(affects.artifacts) == 1
        assert affects.artifacts[0].name == "Test Model"

    def test_affects_empty_lists(self):
        """Test Affects with empty lists."""
        affects = Affects(developer=[], deployer=[], artifacts=[])
        assert affects.developer == []
        assert affects.deployer == []
        assert affects.artifacts == []


class TestProblemtype:
    """Test cases for Problemtype data model."""

    def test_problemtype_creation(self):
        """Test creating a valid Problemtype instance."""
        description = LangValue(lang="en", value="Test problem description")
        problemtype = Problemtype(
            classof=ClassEnum.llm,
            type=TypeEnum.measurement,
            description=description
        )
        assert problemtype.classof == ClassEnum.llm
        assert problemtype.type == TypeEnum.measurement
        assert problemtype.description.value == "Test problem description"

    def test_problemtype_optional_type(self):
        """Test Problemtype with optional type field."""
        description = LangValue(lang="en", value="Test description")
        problemtype = Problemtype(
            classof=ClassEnum.aiid,
            description=description
        )
        assert problemtype.classof == ClassEnum.aiid
        assert problemtype.type is None


class TestMetric:
    """Test cases for Metric data model."""

    def test_metric_creation(self):
        """Test creating a valid Metric instance."""
        detection = Detection(type=MethodEnum.test, name="T-test")
        metric = Metric(
            name="Accuracy",
            detection_method=detection,
            results={"value": 0.95, "confidence": 0.05}
        )
        assert metric.name == "Accuracy"
        assert metric.detection_method.name == "T-test"
        assert metric.results["value"] == 0.95


class TestReference:
    """Test cases for Reference data model."""

    def test_reference_creation(self):
        """Test creating a valid Reference instance."""
        reference = Reference(
            type="source",
            label="Test Reference",
            url="https://example.com"
        )
        assert reference.type == "source"
        assert reference.label == "Test Reference"
        assert reference.url == "https://example.com"

    def test_reference_optional_type(self):
        """Test Reference with optional type field."""
        reference = Reference(
            label="Test Reference",
            url="https://example.com"
        )
        assert reference.type is None
        assert reference.label == "Test Reference"


class TestAvidTaxonomy:
    """Test cases for AvidTaxonomy data model."""

    def test_avid_taxonomy_creation(self):
        """Test creating a valid AvidTaxonomy instance."""
        taxonomy = AvidTaxonomy(
            vuln_id="AVID-2023-001",
            risk_domain=["Security"],
            sep_view=[SepEnum.S0100],
            lifecycle_view=[LifecycleEnum.L04],
            taxonomy_version="1.0"
        )
        assert taxonomy.vuln_id == "AVID-2023-001"
        assert taxonomy.risk_domain == ["Security"]
        assert taxonomy.sep_view == [SepEnum.S0100]
        assert taxonomy.lifecycle_view == [LifecycleEnum.L04]

    def test_avid_taxonomy_optional_vuln_id(self):
        """Test AvidTaxonomy with optional vuln_id."""
        taxonomy = AvidTaxonomy(
            risk_domain=["Performance"],
            sep_view=[SepEnum.P0204],
            lifecycle_view=[LifecycleEnum.L05],
            taxonomy_version="1.0"
        )
        assert taxonomy.vuln_id is None


class TestImpact:
    """Test cases for Impact data model."""

    def test_impact_creation(self):
        """Test creating a valid Impact instance."""
        taxonomy = AvidTaxonomy(
            risk_domain=["Security"],
            sep_view=[SepEnum.S0100],
            lifecycle_view=[LifecycleEnum.L04],
            taxonomy_version="1.0"
        )
        impact = Impact(avid=taxonomy)
        assert impact.avid.risk_domain == ["Security"]
        assert impact.avid.taxonomy_version == "1.0"
