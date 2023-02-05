import requests
import yaml

from avidtools.datamodels.report import Report
from avidtools.datamodels.components import *

ATLAS_HOME = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/data/case-studies/'

def import_case_study(case_study_id):
    req = requests.get(ATLAS_HOME+case_study_id+'.yaml')
    case_study = yaml.safe_load(req.content)
    return case_study
    
def convert_case_study(case_study):
    report = Report()
    
    report.affects = Affects(
        developer = [],
        deployer = [case_study['target']],
        artifacts = Artifact(
            type = ArtifactTypeEnum.system,
            name = case_study['target']
        )
    )    
    
    report.problemtype = Problemtype(
        classof = ClassEnum.atlas,
        type = TypeEnum.advisory,
        description = LangValue(
            lang = 'eng',
            value = case_study['name']
        )
    )
    
    report.references = [
        Reference(
            type = 'source',
            label = case_study['name'],
            url = 'https://atlas.mitre.org/studies/'+case_study['id']
        )
    ] + [
        Reference(
            type = 'source',
            label = ref['title'],
            url = ref['url']
        )
        for ref in case_study['references']
    ]
    
    report.description = LangValue(
        lang = 'eng',
        value = case_study['summary']
    )
    
    if 'reporter' in list(case_study.keys()):
        report.credit = LangValue(
            lang = 'eng',
            value = case_study['reporter']
        )
        
    report.reported_date = case_study['incident-date']
    
    return report