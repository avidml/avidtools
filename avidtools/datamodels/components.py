from typing import Dict, List, Optional
from typing_extensions import TypedDict
from pydantic import BaseModel

from .enums import *

class LangValue(BaseModel):
    lang: str
    value: str

class Artifact(BaseModel):
    type: ArtifactTypeEnum
    name: str

class Detection(BaseModel):
    type: MethodEnum
    name: str

class Affects(BaseModel):
    developer: List[str]
    deployer: List[str]
    artifacts: List[Artifact]
        
class Problemtype(BaseModel):
    classof: ClassEnum
    type: Optional[TypeEnum]
    description: LangValue
        
class Metric(BaseModel):
    name: str
    features: Dict
    detection_method: Detection

class Reference(BaseModel):
    type: Optional[str]
    label: str
    url: str # AnyUrl is a better fit, but keeping this because submissions are not standard yet

class AvidTaxonomy(BaseModel):
    vuln_id: Optional[str]
    risk_domain: List[str]
    sep_view: List[SepEnum]
    lifecycle_view: List[LifecycleEnum]
    taxonomy_version: str
        
class Impact(BaseModel):
    avid: AvidTaxonomy