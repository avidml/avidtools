from typing import List

from ..datamodels.report import Report
from ..datamodels.components import *

from inspect_ai.log import read_eval_log, EvalLog


human_readable_name = {
    "openai": "OpenAI",
    "hf": "HuggingFace",
    "anthropic": "Anthropic",
    "google": "Google",
    "mistral": "Mistral",
    "X AI": "Grok",
    "meta": "Meta",
    "cohere": "Cohere",
    "perplexity": "Perplexity AI",
    "stability": "Stability AI",
    "nvidia": "NVIDIA",
    "ibm": "IBM Watson",
    "mosaic": "MosaicML",
    "databricks": "Databricks",
    "cerebras": "Cerebras Systems",
    "alibaba": "Alibaba Cloud",
    "baidu": "Baidu AI",
    "tencent": "Tencent AI",
    "together": "Together AI",
    "deepseek": "Deepseek AI",
}


def import_eval_log(file_path: str) -> EvalLog:
    """
    Import an Inspect evaluation log file and return an evaluation log object.

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
    """
    Convert an Inspect evaluation log into a list of AVID Report objects.

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
        developer_name = human_readable_name[eval_log.eval.model.split("/", 1)[0]]
        task = eval_log.eval.task.rsplit("/", 1)[-1]
        model_name = eval_log.eval.model.rsplit("/", 1)[-1]
        report.affects = {
            "developer":[developer_name],
            "deployer":[eval_log.eval.model],
            "artifacts":[
                {
                    "type": ArtifactTypeEnum.model.value,
                    "name": model_name
                }
            ]
        }
        
        report.problemtype = {
            "classof": ClassEnum.llm.value,
            "type": TypeEnum.measurement.value,
            "description": {
                "lang": 'eng',
                "value": f"Evaluation of the LLM {model_name} on the {task} benchmark using Inspect Evals",
            }
        }

        report.references = [
            Reference(
                type='source',
                label=f"Inspect Evaluation Log for dataset: {eval_log.eval.dataset.name}",
                url=eval_log.eval.dataset.location
            )
        ]
        
        metrics = ', '.join([metric.name.rsplit('/', 1)[-1] for scorer in eval_log.eval.scorers for metric in scorer.metrics])
        scorer_desc = '|'.join([f"scorer: {scorer.name}, metrics: {metrics}" for scorer in eval_log.eval.scorers])
        report.metrics = []
        for sc in eval_log.results.scores:
            for k, v in sc.metrics.items():
                report.metrics.append({"scorer": sc.name, "metrics": k, "value": v.value})
        
        report.description = {
            "lang": 'eng',
            "value": f"Evaluation of the LLM {model_name} on the {task} benchmark using Inspect Evals"
                  f"\n\nSample input: {sample.input}\n\n"
                  f"Model output: {sample.output}\n\n"
                  f"Scorer: {scorer_desc}\n\n"
                  f"Score: {sample.score}"
        }

        reports.append(report)

    return reports
