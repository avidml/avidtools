"""
Class definitions for AVID report.

"""

from pydantic import BaseModel
from typing import List, Optional
from datetime import date

from .components import (
    Affects,
    Problemtype,
    Metric,
    Reference,
    LangValue,
    Impact,
)


class ReportMetadata(BaseModel):
    """Metadata class for a report."""

    report_id: str


class Report(BaseModel):
    """Top-level class to store an AVID report."""

    data_type: str = "AVID"
    """Namespace for the report.

    Set to AVID by default; change this only if adopting these datamodels
    for a custom vulnerability database.
    """

    data_version: Optional[str] = None
    """Latest version of the data."""

    metadata: Optional[ReportMetadata] = None
    """Metadata for the report."""

    affects: Optional[Affects] = None
    """Information on Artifact(s) affected by this report."""

    problemtype: Optional[Problemtype] = None
    """Description of the problem a report is concerned with."""

    metrics: Optional[List[Metric]] = None
    """Quantitative results for issues raised in a specific report."""

    references: Optional[List[Reference]] = None
    """References and their details."""

    description: Optional[LangValue] = None
    """High-level description."""

    impact: Optional[Impact] = None
    """Impact information, including taxonomy mappings and severity scores."""

    credit: Optional[List[LangValue]] = None
    """People credited for this report."""

    reported_date: Optional[date] = None
    """Date reported."""

    def save(self, location, append: bool = False, jsonl: bool = False):
        """Save a report as JSON or JSONL.

        Parameters
        ----------
        location : str
            Output filename including location.
        append : bool
            Append mode; useful when writing multiple JSONL records.
        jsonl : bool
            When true, writes one JSON object per line.
        """
        mode = "a" if append else "w"
        with open(location, mode, encoding="utf-8") as outfile:
            if jsonl:
                outfile.write(self.model_dump_json(exclude_none=True) + "\n")
            else:
                outfile.write(self.model_dump_json(exclude_none=True))
