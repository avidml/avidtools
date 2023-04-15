"""
Class definitions for AVID reports.
"""
from pydantic import BaseModel
from typing import List
from datetime import date

from .components import Affects, Problemtype, Metric, Reference, LangValue, Impact

class ReportMetadata(BaseModel):
    """Metadata class for a report."""
    report_id: str

class Report(BaseModel):
    """Top-level class to store an AVID report."""

    data_type: str = 'AVID'
    """Namespace for the report. Set to AVID by default, change this only if you're adopting these datamodels to stand up your own vulnerability database."""

    data_version: str = None
    """Latest version of the AVID database."""
    
    metadata: ReportMetadata = None
    """Metadata for the report."""
    
    affects: Affects = None
    """Information on Artifact(s) affected by this report."""
    
    problemtype: Problemtype = None
    """"""
    
    metrics: List[Metric] = None
    """"""
    
    references: List[Reference] = None
    """"""
    
    description: LangValue = None
    """"""
    
    impact: Impact = None
    """"""
    
    credit: List[LangValue] = None
    """"""
    
    reported_date: date = None
    """"""
    
    def save(self, location):
        """Save a report as a json file"""
        with open(location, "w") as outfile:
            outfile.write(self.json(indent=4))