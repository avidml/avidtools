"""Unit tests for normalization utilities."""

from avidtools.connectors.utils import (
    apply_normalizations,
    choose_model_subject_label,
)


def test_apply_normalizations_sets_openai_deployer_for_gpt_model():
    """GPT model artifacts should normalize deployer to OpenAI."""
    report = {
        "affects": {
            "developer": ["Unknown"],
            "deployer": ["openai/gpt-4o"],
            "artifacts": [{"type": "Model", "name": "gpt-4o"}],
        },
        "problemtype": {"description": {"value": ""}},
    }

    updated = apply_normalizations(report)

    assert updated is True
    assert report["affects"]["deployer"] == ["OpenAI"]
    assert report["affects"]["artifacts"][0]["type"] == "System"


def test_apply_normalizations_sets_together_ai_deployer():
    """Together-prefixed deployers should normalize to Together AI."""
    report = {
        "affects": {
            "developer": ["Unknown"],
            "deployer": ["together/mistralai/Mistral-Small-24B"],
            "artifacts": [{"type": "Model", "name": "Mistral-Small-24B"}],
        },
        "problemtype": {"description": {"value": ""}},
    }

    updated = apply_normalizations(report)

    assert updated is True
    assert report["affects"]["deployer"] == ["Together AI"]
    assert report["affects"]["developer"] == ["Mistral"]


def test_choose_model_subject_label_prefers_ai_system_for_system_artifacts():
    """System artifact type should map description subject to AI system."""
    report = {
        "affects": {
            "artifacts": [
                {"type": "System", "name": "gpt-4o-mini-2024-07-18"}
            ]
        }
    }

    assert choose_model_subject_label(report) == "AI system"


def test_choose_model_subject_label_uses_llm_for_model_artifacts():
    """Model artifact type should keep description subject as LLM."""
    report = {
        "affects": {
            "artifacts": [
                {"type": "Model", "name": "gpt-4o-mini-2024-07-18"}
            ]
        }
    }

    assert choose_model_subject_label(report) == "llm"
