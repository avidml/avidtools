from typing import List

from ..datamodels.report import Report
from ..datamodels.components import *

from inspect_ai.log import read_eval_log, EvalLog

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

        report.affects = Affects(
            developer=[],
            deployer=[eval_log.eval.model],
            artifacts=[
                Artifact(
                    type=ArtifactTypeEnum.model,
                    name=eval_log.eval.model
                )
            ]
        )

        report.problemtype = Problemtype(
            classof=ClassEnum.llm,
            type=TypeEnum.measurement,
            description=LangValue(
                lang='eng',
                value=eval_log.eval.task
            )
        )

        report.references = [
            Reference(
                type='source',
                label='Inspect Evaluation Log',
                url=file_path
            )
        ]

        report.description = LangValue(
            lang='eng',
            value=f"Sample input: {sample.input}\n"
                  f"Model output: {sample.output}\n"
                  f"Score: {sample.score}"
        )

        reports.append(report)

    return reports
