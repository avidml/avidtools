"""Reusable normalization helpers for review workflows."""

from __future__ import annotations

from typing import List, Optional


INSPECT_MODEL_PREFIX = "Evaluation of the LLM "
INSPECT_MODEL_SUFFIX = " on the "


def to_list(value):
    """Coerce a scalar or list-like input into a list of strings."""

    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


_to_list = to_list


def extract_model_names(
    report: dict,
    preferred_model_name: Optional[str] = None,
) -> List[str]:
    """Extract and deduplicate model names from report fields."""

    model_names: List[str] = []

    if preferred_model_name:
        model_names.append(str(preferred_model_name))

    affects = report.get("affects", {})
    artifacts = affects.get("artifacts")
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            artifact_name = artifact.get("name")
            if artifact_name:
                model_names.append(str(artifact_name))

    problem_desc = (
        report.get("problemtype", {})
        .get("description", {})
        .get("value", "")
    )
    if (
        isinstance(problem_desc, str)
        and problem_desc.startswith(INSPECT_MODEL_PREFIX)
        and INSPECT_MODEL_SUFFIX in problem_desc
    ):
        model_name = (
            problem_desc[len(INSPECT_MODEL_PREFIX):]
            .split(INSPECT_MODEL_SUFFIX, 1)[0]
            .strip()
        )
        if model_name:
            model_names.append(model_name)

    deduped: List[str] = []
    seen = set()
    for name in model_names:
        normalized = name.strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(normalized)

    return deduped


def _infer_developer_from_models(model_names: List[str]) -> Optional[str]:
    """Infer a canonical developer label from known model name patterns."""

    for model_name in model_names:
        normalized = model_name.lower()
        if "kimi" in normalized:
            return "Moonshot AI"
        if "llama" in normalized:
            return "Meta"
        if "mistral" in normalized:
            return "Mistral"
        if "deepseek" in normalized:
            return "DeepSeek"
    return None


def _infer_deployer(
    report: dict,
    model_names: List[str],
) -> Optional[str]:
    """Infer deployer label from deployer values and model patterns."""

    affects = report.get("affects", {})
    deployer_values = to_list(affects.get("deployer"))

    if any(
        value.strip().lower().startswith("together/")
        for value in deployer_values
    ):
        return "Together AI"

    if any("gpt" in model.lower() for model in model_names):
        return "OpenAI"

    if any("openai" in value.lower() for value in deployer_values):
        return "OpenAI"

    return None


def apply_model_developer_mapping(
    report: dict,
    model_names: Optional[List[str]] = None,
) -> bool:
    """Normalize developer/deployer fields for a report when inference matches."""

    affects = report.setdefault("affects", {})
    if model_names is None:
        model_names = extract_model_names(report)

    inferred_developer = _infer_developer_from_models(model_names)
    inferred_deployer = _infer_deployer(report, model_names)

    updated = False

    if inferred_developer is not None:
        current_developer = to_list(affects.get("developer"))
        if current_developer != [inferred_developer]:
            affects["developer"] = [inferred_developer]
            updated = True

    if inferred_deployer is not None:
        current_deployer = to_list(affects.get("deployer"))
        if current_deployer != [inferred_deployer]:
            affects["deployer"] = [inferred_deployer]
            updated = True
    elif inferred_developer is not None:
        current_deployer = to_list(affects.get("deployer"))
        if not current_deployer:
            affects["deployer"] = [inferred_developer]
            updated = True

    return updated


def apply_openai_system_artifact_type(
    report: dict,
    model_names: Optional[List[str]] = None,
) -> bool:
    """Set artifact type to System for GPT/OpenAI-context report artifacts."""

    affects = report.setdefault("affects", {})
    artifacts = affects.get("artifacts")
    if not isinstance(artifacts, list):
        return False

    if model_names is None:
        model_names = extract_model_names(report)

    developer_values = to_list(affects.get("developer"))
    deployer_values = to_list(affects.get("deployer"))

    openai_context = (
        any("gpt" in model.lower() for model in model_names)
        or any("openai" in value.lower() for value in developer_values)
        or any("openai" in value.lower() for value in deployer_values)
    )

    updated = False
    gpt_artifact_found = False

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        artifact_name = str(artifact.get("name", ""))
        if "gpt" in artifact_name.lower():
            artifact["type"] = "System"
            updated = True
            gpt_artifact_found = True

    if openai_context and not gpt_artifact_found:
        for artifact in artifacts:
            if isinstance(artifact, dict):
                artifact["type"] = "System"
                updated = True
                break

    return updated


def apply_normalizations(
    report: dict,
    preferred_model_name: Optional[str] = None,
) -> bool:
    """Apply the default normalization suite to a report."""

    model_names = extract_model_names(
        report,
        preferred_model_name=preferred_model_name,
    )
    artifacts_updated = apply_openai_system_artifact_type(
        report,
        model_names=model_names,
    )
    developer_updated = apply_model_developer_mapping(
        report,
        model_names=model_names,
    )
    return artifacts_updated or developer_updated


def apply_review_normalizations(
    report: dict,
    preferred_model_name: Optional[str] = None,
) -> bool:
    """Backward-compatible alias for default normalizations."""

    return apply_normalizations(
        report,
        preferred_model_name=preferred_model_name,
    )


def choose_model_subject_label(report: dict) -> str:
    """Choose whether descriptions should refer to an LLM or AI system."""

    affects = report.get("affects", {})
    artifacts = affects.get("artifacts")
    if isinstance(artifacts, list):
        has_system_artifact = False
        has_model_artifact = False
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            artifact_type = str(artifact.get("type", "")).strip().lower()
            if artifact_type == "system":
                has_system_artifact = True
            elif artifact_type in {"model", "llm", "language model"}:
                has_model_artifact = True

        if has_system_artifact and not has_model_artifact:
            return "AI system"
        if has_model_artifact:
            return "llm"

    model_names = extract_model_names(report)
    if any(name.strip() for name in model_names):
        return "llm"

    return "AI system"
