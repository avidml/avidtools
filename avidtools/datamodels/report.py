"""
Class definitions for AVID report.

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
    """Latest version of the data."""
    
    metadata: ReportMetadata = None
    """Metadata for the report."""
    
    affects: Affects = None
    """Information on Artifact(s) affected by this report."""
    
    problemtype: Problemtype = None
    """Description of the problem a report is concerned with."""
    
    metrics: List[Metric] = None
    """Quantitative results pertaining to the issues raised in a specific report."""
    
    references: List[Reference] = None
    """References and their details."""
    
    description: LangValue = None
    """High-level description."""
    
    impact: Impact = None
    """Impact information, e.g. different taxonomy mappings, harm and severity scores."""
    
    credit: List[LangValue] = None
    """People credited for this report."""
    
    reported_date: date = None
    """Date reported."""
    
    def save(self, location):
        """Save a report as a json file.
        
        Parameters
        ----------
        location : str
            output *.json filename including location.
        """
        with open(location, "w") as outfile:
            outfile.write(self.json(indent=4))