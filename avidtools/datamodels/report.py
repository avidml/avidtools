from pydantic import BaseModel
from typing import List
from datetime import datetime

from .components import Metadata, Affects, Metric, Reference, LangValue, Impact

class Report(BaseModel):
    data_type: str = 'AVID'
    data_version: str = None
    metadata: Metadata = None
    affects: Affects = None
    problemtype: str = None
    metrics: List[Metric] = None
    references: List[Reference] = None
    description: LangValue = None
    impact: Impact = None
    credit: List[LangValue] = None
    reported_date: datetime = None
        
    def save(self, location):
        with open(location, "w") as outfile:
            outfile.write(self.json(indent=4))