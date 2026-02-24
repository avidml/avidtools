"""Connector utilities for importing and converting CVEs."""

import nvdlib
from datetime import datetime

from ..datamodels.vulnerability import Vulnerability
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


def import_cve(cve_id):
    """Import a CVE from the NVD API and return a JSON dump object.

    Parameters
    ----------
    cve_id : str
        Identifier of the CVE to be imported. Has the format CVE-2XXX-XXXXX

    Returns
    --------
    cve: nvdlib.classes.CVE
        JSON dump object containing the imported CVE information.
    """
    cv = nvdlib.searchCVE(cveId=cve_id)[0]
    return cv


def convert_cve(cve):
    """Convert a CVE into an AVID report object.

    Parameters
    ----------
    cve : nvdlib.classes.CVE
        JSON dump object containing the imported CVE information.

    Returns
    --------
    vuln : Vulnerability
        an AVID vulnerability object containing information in the CVE.
    """
    vuln = Vulnerability()

    aff = [c.criteria.split(":") for c in cve.cpe]
    vuln.affects = Affects(
        developer=[a[3] for a in aff],
        deployer=[],
        artifacts=[
            Artifact(type=ArtifactTypeEnum.system, name=":".join(a[4:])) for a in aff
        ],
    )

    vuln.problemtype = Problemtype(
        classof=ClassEnum.cve,
        type=TypeEnum.advisory,
        description=LangValue(lang="eng", value=cve.descriptions[0].value),
    )

    vuln.references = [Reference(type="source", label="NVD entry", url=cve.url)] + [
        Reference(type="source", label=ref.url, url=ref.url) for ref in cve.references
    ]

    vuln.description = LangValue(lang="eng", value=cve.id + " Detail")

    vuln.credit = [LangValue(lang="eng", value=cve.sourceIdentifier)]

    vuln.published_date = datetime.strptime(
        cve.published.split("T")[0], "%Y-%m-%d"
    ).date()
    vuln.last_modified_date = datetime.strptime(
        cve.lastModified.split("T")[0], "%Y-%m-%d"
    ).date()

    return vuln
