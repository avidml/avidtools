from pydantic import BaseModel
from typing import List
from datetime import date

from .components import Affects, Problemtype, Metric, Reference, LangValue, Impact

class ReportMetadata(BaseModel):
    report_id: str

class Report(BaseModel):
    data_type: str = 'AVID'
    data_version: str = None
    metadata: ReportMetadata = None
    affects: Affects = None
    problemtype: Problemtype = None
    metrics: List[Metric] = None
    references: List[Reference] = None
    description: LangValue = None
    impact: Impact = None
    credit: List[LangValue] = None
    reported_date: date = None
        
    def save(self, location):
        with open(location, "w") as outfile:
            outfile.write(self.json(indent=4))