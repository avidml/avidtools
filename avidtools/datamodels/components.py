"""
Component data classes used in AVID report and vulnerability datamodels.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel

from .enums import (
    ArtifactTypeEnum,
    ClassEnum,
    LifecycleEnum,
    MethodEnum,
    SepEnum,
    TypeEnum,
)


class LangValue(BaseModel):
    """Generic class to store a string with its language specified."""

    lang: str
    value: str


class Artifact(BaseModel):
    """Type and name of an affected artifact."""

    type: ArtifactTypeEnum
    name: str


class Detection(BaseModel):
    """Method to detect a specific issue."""

    type: MethodEnum
    name: str


class Affects(BaseModel):
    """Information on Artifact(s) affected by this report."""

    developer: List[str]
    deployer: List[str]
    artifacts: List[Artifact]


class Problemtype(BaseModel):
    """Description of the problem a report/vuln is concerned with."""

    classof: ClassEnum
    type: Optional[TypeEnum] = None
    description: LangValue


class Metric(BaseModel):
    """Quantification of the issue in a specific report."""

    name: str
    detection_method: Detection
    results: Dict


class Reference(BaseModel):
    """Details for a reference of a report/vulnerability."""

    type: Optional[str] = None
    label: str
    # AnyUrl is a better fit, but keeping this because submissions
    # are not standard yet
    url: str

    class Config:  # type is excluded if None
        fields = {"type": {"exclude": True}}


class AtlasTaxonomy(BaseModel):
    """ATLAS taxonomy mappings representing attack procedure steps."""

    tactic: Optional[str] = None
    technique: Optional[str] = None
    description: Optional[str] = None

    class Config:  # Fields are excluded if None
        fields = {
            "tactic": {"exclude": True},
            "technique": {"exclude": True},
            "description": {"exclude": True}
        }


class AvidTaxonomy(BaseModel):
    """AVID taxonomy mappings of a report/vulnerability."""

    vuln_id: Optional[str] = None
    risk_domain: List[str]
    sep_view: List[SepEnum]
    lifecycle_view: List[LifecycleEnum]
    taxonomy_version: str

    class Config:  # vuln_id is excluded if None
        fields = {"vuln_id": {"exclude": True}}


class Impact(BaseModel):
    """Impact information of a report/vulnerability.

    E.g. different taxonomy mappings, harm and severity scores.
    """

    avid: AvidTaxonomy
    atlas: Optional[List[AtlasTaxonomy]] = None

    class Config:  # atlas is excluded if None
        fields = {"atlas": {"exclude": True}}
