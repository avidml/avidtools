"""
Class definitions for AVID report.

"""
from pydantic import BaseModel
from typing import List
from datetime import date

from .components import Metadata, Related, Affects, Problemtype, Metric, Reference, LangValue, Impact

class AvidObject(BaseModel):
    """Top-level class to store an AVID report."""

    data_type: str = 'AVID'
    """Namespace for the report. Set to AVID by default, change this only if you're adopting these datamodels to stand up your own vulnerability database."""

    data_version: str = None
    """Latest version of the data."""
    
    metadata: Metadata = None
    """Metadata for the report/vuln."""

    related_objects: List[Related] = None
    """Related objects"""
    
    affects: Affects = None
    """Information on Artifact(s) affected."""
    
    problemtype: Problemtype = None
    """Description of the problem this object is concerned with."""
    
    references: List[Reference] = None
    """References and their details."""
    
    description: LangValue = None
    """High-level description."""
    
    impact: Impact = None
    """Impact information, e.g. different taxonomy mappings, harm and severity scores."""
    
    credit: List[LangValue] = None
    """People credited for this report/vuln."""
    
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

class Report(AvidObject):
    metadata: Metadata = Metadata(object_id=None, object_type="Report")
    """Specify metadata type as Report"""
    
    metrics: List[Metric] = None
    """Quantitative results pertaining to the issues raised here."""

class Vulnerability(AvidObject):
    metadata: Metadata = Metadata(object_id=None, object_type="Vulnerability")
    """Specify metadata type as Vuln"""

    def ingest(self, report: Report):
        self.data_version = report.data_version
        self.affects = report.affects
        self.problemtype = report.problemtype
        self.description = report.description
        self.references = report.references
        self.impact = report.impact
        self.credit = report.credit
        self.published_date = date.today()
        self.last_modified_date = date.today()

        self.related_objects = [
            Related(
                object_id = report.metadata.object_id,
                object_type = "Report",
                object_name = report.description.value
            )
        ]