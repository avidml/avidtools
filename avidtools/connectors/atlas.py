import requests
import yaml
import re

from ..datamodels.report import Report
from ..datamodels.components import (
    Affects,
    Artifact,
    ArtifactTypeEnum,
    AtlasTaxonomy,
    AvidTaxonomy,
    ClassEnum,
    Impact,
    LangValue,
    Problemtype,
    Reference,
    TypeEnum,
)

ATLAS_HOME = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/data"
)

# Cache for tactics and techniques data to avoid repeated requests
_tactics_cache = None
_techniques_cache = None


def _load_atlas_data():
    """Load tactics and techniques data from ATLAS repository."""
    global _tactics_cache, _techniques_cache
    
    if _tactics_cache is None:
        # Load the raw YAML text to preserve anchors
        req = requests.get(f"{ATLAS_HOME}/tactics.yaml")
        tactics_raw = req.text
        _tactics_cache = {
            'raw': tactics_raw,
            'data': yaml.safe_load(req.content)
        }
    
    if _techniques_cache is None:
        # Load the raw YAML text to preserve anchors
        req = requests.get(f"{ATLAS_HOME}/techniques.yaml")
        techniques_raw = req.text
        _techniques_cache = {
            'raw': techniques_raw,
            'data': yaml.safe_load(req.content)
        }
    
    return _tactics_cache, _techniques_cache


def _build_reference_map(data_dict):
    """Build a mapping from anchor names to IDs from YAML data."""
    reference_map = {}
    
    # Parse the raw YAML to extract anchor-to-ID mappings
    raw_text = data_dict['raw']
    
    # Extract anchors from raw text and match with IDs from parsed data
    import re as regex_module
    anchor_pattern = r'^- &(\w+)'
    
    lines = raw_text.split('\n')
    current_anchor = None
    
    for line in lines:
        anchor_match = regex_module.match(anchor_pattern, line)
        if anchor_match:
            current_anchor = anchor_match.group(1)
        elif current_anchor and line.strip().startswith('id:'):
            # Extract ID
            id_match = regex_module.search(r'id:\s*(\S+)', line)
            if id_match:
                reference_map[current_anchor] = id_match.group(1)
                current_anchor = None
    
    return reference_map


def _resolve_wildcards(text, tactics_map, techniques_map):
    """Resolve {{reference.id}} wildcards in text using the reference maps."""
    if not isinstance(text, str):
        return text
    
    # Pattern to match {{something.id}}
    pattern = r'\{\{([^}]+)\.id\}\}'
    
    def replace_wildcard(match):
        reference = match.group(1).lower()
        
        # Try tactics first
        if reference in tactics_map:
            return tactics_map[reference]
        
        # Try techniques
        if reference in techniques_map:
            return techniques_map[reference]
        
        # If not found, return the original
        return match.group(0)
    
    return re.sub(pattern, replace_wildcard, text)


def _resolve_wildcards_recursive(obj, tactics_map, techniques_map):
    """Recursively resolve wildcards in a nested data structure."""
    if isinstance(obj, dict):
        return {
            key: _resolve_wildcards_recursive(
                value, tactics_map, techniques_map)
            for key, value in obj.items()
        }
    elif isinstance(obj, list):
        return [
            _resolve_wildcards_recursive(item, tactics_map, techniques_map)
            for item in obj
        ]
    elif isinstance(obj, str):
        return _resolve_wildcards(obj, tactics_map, techniques_map)
    else:
        return obj


def import_case_study(case_study_id):
    """Import a case study from MITRE ATLAS website and return a yaml object.

    Parameters
    ----------
    case_study_id : str
        Identifier of the case studies to be imported.
        Has the format AML.CSXXXX

    Returns
    --------
    case_study : dict
        Dictionary containing the imported case study.
    """
    req = requests.get(f"{ATLAS_HOME}/case-studies/{case_study_id}.yaml")
    case_study = yaml.safe_load(req.content)
    
    # Load tactics and techniques data for wildcard resolution
    try:
        tactics_data, techniques_data = _load_atlas_data()
        
        # Build reference maps
        tactics_map = _build_reference_map(tactics_data)
        techniques_map = _build_reference_map(techniques_data)
        
        # Resolve wildcards in the case study
        case_study = _resolve_wildcards_recursive(
            case_study, tactics_map, techniques_map)
            
    except Exception as e:
        print(f"[WARN] Could not resolve wildcards for case study "
              f"{case_study_id}: {e}")
    
    return case_study


def convert_case_study(case_study):
    """Convert a case study in the ATLAS schema into an AVID report object.

    Parameters
    ----------
    case_study : dict
        Dictionary containing the imported case study.

    Returns
    --------
    report : Report
        an AVID report object containing information in the case study.
    """
    report = Report()

    # Defensive: use .get() with defaults for all required fields
    target = case_study.get("target", "Unknown Target")
    case_id = case_study.get("id", "UnknownID")
    name = case_study.get("name", case_id)
    summary = case_study.get("summary", "No summary provided.")

    report.affects = Affects(
        developer=[],
        deployer=[target],
        artifacts=[Artifact(type=ArtifactTypeEnum.system, name=target)],
    )

    report.problemtype = Problemtype(
        classof=ClassEnum.atlas,
        type=TypeEnum.advisory,
        description=LangValue(lang="eng", value=name),
    )

    # Always add the main ATLAS case study reference
    report.references = [
        Reference(
            type="source",
            label=name,
            url="https://atlas.mitre.org/studies/" + case_id,
        )
    ]
    # Add additional references if present and valid (must be a list)
    try:
        refs = case_study.get("references")
        if isinstance(refs, list):
            for ref in refs:
                if (isinstance(ref, dict) and ref.get("title") and
                        ref.get("url")):
                    report.references.append(
                        Reference(
                            type="source",
                            label=ref.get("title", ""),
                            url=ref.get("url", "")
                        )
                    )
        # If 'references' is present but not a list, ignore it safely
    except Exception as e:
        # Log and continue
        print(f"[WARN] Could not process references for case study "
              f"{case_id}: {e}")

    report.description = LangValue(lang="eng", value=summary)

    if "reporter" in case_study:
        report.credit = [LangValue(lang="eng", value=case_study["reporter"])]

    report.reported_date = case_study.get("incident-date")

    # Process procedure information and add to impact
    if "procedure" in case_study and isinstance(case_study["procedure"], list):
        atlas_procedures = []
        for step in case_study["procedure"]:
            if isinstance(step, dict):
                atlas_step = AtlasTaxonomy(
                    tactic=step.get("tactic"),
                    technique=step.get("technique"),
                    description=step.get("description")
                )
                atlas_procedures.append(atlas_step)
        
        if atlas_procedures:
            # Create a minimal AvidTaxonomy for the Impact object
            # Since this is an ATLAS case study, create a basic AVID taxonomy
            avid_taxonomy = AvidTaxonomy(
                risk_domain=["Security"],  # Default risk domain
                sep_view=[],  # Empty for now as ATLAS doesn't map directly
                lifecycle_view=[],  # Empty for now - no direct mapping
                taxonomy_version="0.2"  # Current AVID taxonomy version
            )
            
            report.impact = Impact(
                avid=avid_taxonomy,
                atlas=atlas_procedures
            )

    return report
