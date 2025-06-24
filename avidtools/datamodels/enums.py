"""
Enumerations used in AVID report and vulnerability datamodels.
"""

from enum import Enum


class ArtifactTypeEnum(str, Enum):
    """Whether the artifact is a dataset, model, or system."""

    dataset = "Dataset"
    model = "Model"
    system = "System"


class SepEnum(str, Enum):
    """All (sub)categories of the SEP view of the AVID taxonomy."""

    S0100 = "S0100: Software Vulnerability"
    S0200 = "S0200: Supply Chain Compromise"
    S0201 = "S0201: Model Compromise"
    S0202 = "S0202: Software Compromise"
    S0300 = "S0300: Over-permissive API"
    S0301 = "S0301: Information Leak"
    S0302 = "S0302: Excessive Queries"
    S0400 = "S0400: Model Bypass"
    S0401 = "S0401: Bad Features"
    S0402 = "S0402: Insufficient Training Data"
    S0403 = "S0403: Adversarial Example"
    S0500 = "S0500: Exfiltration"
    S0501 = "S0501: Model inversion"
    S0502 = "S0502: Model theft"
    S0600 = "S0600: Data Poisoning"
    S0601 = "S0601: Ingest Poisoning"
    E0100 = "E0100: Bias/ Discrimination"
    E0101 = "E0101: Group fairness"
    E0102 = "E0102: Individual fairness"
    E0200 = "E0200: Explainability"
    E0201 = "E0201: Global explanations"
    E0202 = "E0202: Local explanations"
    E0300 = "E0300: User actions"
    E0301 = "E0301: Toxicity"
    E0302 = "E0302: Polarization/ Exclusion"
    E0400 = "E0400: Misinformation"
    E0401 = "E0401: Deliberative Misinformation"
    E0402 = "E0402: Generative Misinformation"
    P0100 = "P0100: Data issues"
    P0101 = "P0101: Data drift"
    P0102 = "P0102: Concept drift"
    P0103 = "P0103: Data entanglement"
    P0104 = "P0104: Data quality issues"
    P0105 = "P0105: Feedback loops"
    P0200 = "P0200: Model issues"
    P0201 = "P0201: Resilience/ Stability"
    P0202 = "P0202: OOD generalization"
    P0203 = "P0203: Scaling"
    P0204 = "P0204: Accuracy"
    P0300 = "P0300: Privacy"
    P0301 = "P0301: Anonymization"
    P0302 = "P0302: Randomization"
    P0303 = "P0303: Encryption"
    P0400 = "P0400: Safety"
    P0401 = "P0401: Psychological Safety"
    P0402 = "P0402: Physical safety"
    P0403 = "P0403: Socioeconomic safety"
    P0404 = "P0404: Environmental safety"


class LifecycleEnum(str, Enum):
    """All (sub)categories of the lifecycle view of the AVID taxonomy."""

    L01 = "L01: Business Understanding"
    L02 = "L02: Data Understanding"
    L03 = "L03: Data Preparation"
    L04 = "L04: Model Development"
    L05 = "L05: Evaluation"
    L06 = "L06: Deployment"


class ClassEnum(str, Enum):
    """All report/vulnerability classes."""

    aiid = "AIID Incident"
    atlas = "ATLAS Case Study"
    cve = "CVE Entry"
    llm = "LLM Evaluation"
    na = "Undefined"


class TypeEnum(str, Enum):
    """All report/vulnerability types."""

    issue = "Issue"
    advisory = "Advisory"
    measurement = "Measurement"
    detection = "Detection"


class MethodEnum(str, Enum):
    """The values a detection method can take."""

    test = "Significance Test"
    thres = "Static Threshold"
