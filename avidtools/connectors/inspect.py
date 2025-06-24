from typing import List, Any

from ..datamodels.report import Report
from ..datamodels.components import (
    Affects,
    Artifact,
    ArtifactTypeEnum,
    Detection,
    LangValue,
    Metric,
    Problemtype,
    Reference,
)
from ..datamodels.enums import ClassEnum, MethodEnum, TypeEnum

try:
    from inspect_ai.log import read_eval_log, EvalLog
except ImportError:
    # Handle case where inspect_ai is not installed
    def read_eval_log(file_path):
        raise ImportError(
            "inspect_ai package is required for this functionality"
        )

    # Create a dummy EvalLog class for type hinting
    EvalLog = Any


human_readable_name = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google": "Google",
    "huggingface": "Hugging Face",
    "meta-llama": "Meta",
    "mistralai": "Mistral AI",
    "cohere": "Cohere",
}


def import_eval_log(file_path: str) -> Any:
    """Import an Inspect evaluation log from a file.

    Parameters
    ----------
    file_path : str
        Path to the evaluation log file (.eval or .json).

    Returns
    -------
    eval_log : EvalLog
        The loaded evaluation log.
    """
    return read_eval_log(file_path)


def convert_eval_log(file_path: str) -> List[Report]:
    """Convert an Inspect evaluation log into a list of AVID Report objects.

    Parameters
    ----------
    file_path : str
        Path to the evaluation log file (.eval or .json).

    Returns
    -------
    List[Report]
        A list of AVID Report objects created from the evaluation log.
    """
    eval_log = import_eval_log(file_path)
    reports = []

    for sample in eval_log.samples:
        report = Report()
        model_prefix = eval_log.eval.model.split("/", 1)[0]
        developer_name = human_readable_name[model_prefix]
        task = eval_log.eval.task.rsplit("/", 1)[-1]
        model_name = eval_log.eval.model.rsplit("/", 1)[-1]
        report.affects = Affects(
            developer=[developer_name],
            deployer=[eval_log.eval.model],
            artifacts=[Artifact(type=ArtifactTypeEnum.model, name=model_name)],
        )

        description_value = (
            f"Evaluation of the LLM {model_name} on the {task} "
            f"benchmark using Inspect Evals"
        )
        report.problemtype = Problemtype(
            classof=ClassEnum.llm,
            type=TypeEnum.measurement,
            description=LangValue(lang="eng", value=description_value),
        )

        dataset_label = (
            f"Inspect Evaluation Log for dataset: {eval_log.eval.dataset.name}"
        )
        report.references = [
            Reference(
                type="source",
                label=dataset_label,
                url=eval_log.eval.dataset.location,
            )
        ]

        metrics = ", ".join(
            [
                metric.name.rsplit("/", 1)[-1]
                for scorer in eval_log.eval.scorers
                for metric in scorer.metrics
            ]
        )
        scorer_desc = "|".join(
            [
                f"scorer: {scorer.name}, metrics: {metrics}"
                for scorer in eval_log.eval.scorers
            ]
        )
        report.metrics = []
        for sc in eval_log.results.scores:
            for k, v in sc.metrics.items():
                report.metrics.append(
                    Metric(
                        name=k,
                        detection_method=Detection(
                            type=MethodEnum.test, name=sc.name
                        ),
                        results={"value": v.value, "scorer": sc.name},
                    )
                )

        full_description = (
            f"Evaluation of the LLM {model_name} on the {task} "
            f"benchmark using Inspect Evals\n\n"
            f"Sample input: {sample.input}\n\n"
            f"Model output: {sample.output}\n\n"
            f"Scorer: {scorer_desc}\n\n"
            f"Score: {sample.score}"
        )
        report.description = LangValue(lang="eng", value=full_description)

        reports.append(report)

    return reports
