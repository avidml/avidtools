from enum import Enum
from typing import Dict, List, Optional
from typing_extensions import TypedDict

from .enums import *

class LangValue(TypedDict):
    lang: str
    value: str

class Artifact(TypedDict):
    type: ArtifactTypeEnum
    name: str

class Metadata(TypedDict):
    report_id: str

class Affects(TypedDict):
    developer: List[str]
    deployer: List[str]
    artifacts: List[Artifact]
        
class Problemtype(TypedDict):
    classof: ClassEnum
    type: TypeEnum
    description: LangValue
        
class Metric(TypedDict):
    name: str
    features: Dict
    detection_method: Dict[MethodEnum, str]

class Reference(TypedDict):
    type: Optional[str]
    label: str
    url: str # AnyUrl is a better fit, but keeping this because submissions are not standard yet

class AvidTaxonomy(TypedDict):
    vuln_id: Optional[str]
    risk_domain: List[str]
    sep_view: List[SepEnum]
    lifecycle_view: List[LifecycleEnum]
    taxonomy_version: str
        
class Impact(TypedDict):
    avid: AvidTaxonomy