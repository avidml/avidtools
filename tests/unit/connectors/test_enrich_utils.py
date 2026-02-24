"""Unit tests for enrich normalization utilities."""

from avidtools.connectors.utils import apply_enrich_normalizations


def test_apply_enrich_normalizations_sets_openai_deployer_for_gpt_model():
    """GPT model artifacts should normalize deployer to OpenAI."""
    report = {
        "affects": {
            "developer": ["Unknown"],
            "deployer": ["openai/gpt-4o"],
            "artifacts": [{"type": "Model", "name": "gpt-4o"}],
        },
        "problemtype": {"description": {"value": ""}},
    }

    updated = apply_enrich_normalizations(report)

    assert updated is True
    assert report["affects"]["deployer"] == ["OpenAI"]
    assert report["affects"]["artifacts"][0]["type"] == "System"


def test_apply_enrich_normalizations_sets_together_ai_deployer():
    """Together-prefixed deployers should normalize to Together AI."""
    report = {
        "affects": {
            "developer": ["Unknown"],
            "deployer": ["together/mistralai/Mistral-Small-24B"],
            "artifacts": [{"type": "Model", "name": "Mistral-Small-24B"}],
        },
        "problemtype": {"description": {"value": ""}},
    }

    updated = apply_enrich_normalizations(report)

    assert updated is True
    assert report["affects"]["deployer"] == ["Together AI"]
    assert report["affects"]["developer"] == ["Mistral"]
