import requests
import yaml

from ..datamodels.report import Report
from ..datamodels.components import (
    Affects,
    Artifact,
    ArtifactTypeEnum,
    ClassEnum,
    LangValue,
    Problemtype,
    Reference,
    TypeEnum,
)

ATLAS_HOME = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/data/case-studies/"
)


def import_case_study(case_study_id):
    """Import a case study from MITRE ATLAS website and return a yaml object.

    Parameters
    ----------
    case_study_id : str
        Identifier of the case studies to be imported.
        Has the format AML.CSXXXX

    Returns
    --------
    case_study : dict
        Dictionary containing the imported case study.
    """
    req = requests.get(ATLAS_HOME + case_study_id + ".yaml")
    case_study = yaml.safe_load(req.content)
    return case_study


def convert_case_study(case_study):
    """Convert a case study in the ATLAS schema into an AVID report object.

    Parameters
    ----------
    case_study : dict
        Dictionary containing the imported case study.

    Returns
    --------
    report : Report
        an AVID report object containing information in the case study.
    """
    report = Report()

    report.affects = Affects(
        developer=[],
        deployer=[case_study["target"]],
        artifacts=[Artifact(type=ArtifactTypeEnum.system, name=case_study["target"])],
    )

    report.problemtype = Problemtype(
        classof=ClassEnum.atlas,
        type=TypeEnum.advisory,
        description=LangValue(lang="eng", value=case_study["name"]),
    )

    report.references = [
        Reference(
            type="source",
            label=case_study["name"],
            url="https://atlas.mitre.org/studies/" + case_study["id"],
        )
    ] + [
        Reference(type="source", label=ref["title"], url=ref["url"])
        for ref in case_study["references"]
    ]

    report.description = LangValue(lang="eng", value=case_study["summary"])

    if "reporter" in list(case_study.keys()):
        report.credit = [LangValue(lang="eng", value=case_study["reporter"])]

    report.reported_date = case_study["incident-date"]

    return report
