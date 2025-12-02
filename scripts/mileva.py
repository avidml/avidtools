"""
Script to scrape CVE information from Milev.ai and NVD.

This script structures CVE data into AVID Vulnerability objects.

This script:
1. Scrapes unique CVE IDs from Milev.ai research digest pages
2. Fetches detailed CVE information from NVD
3. Structures the data into AVID Vulnerability objects
4. Saves all vulnerabilities to a JSONL file

Dependencies:
    - beautifulsoup4: For HTML parsing
    - requests: For HTTP requests
    - nvdlib: For fetching CVE data from NVD (already in dependencies)
"""

import re
import sys
import time
from datetime import date
from pathlib import Path
from typing import List, Optional, Set

import requests
from bs4 import BeautifulSoup

# Import AVID datamodels (sys.path modification required)
sys.path.insert(0, str(Path(__file__).parent.parent))  # noqa: E402

from avidtools.datamodels.components import (  # noqa: E402
    Affects,
    Artifact,
    AvidTaxonomy,
    Impact,
    LangValue,
    Problemtype,
    Reference,
)
from avidtools.datamodels.enums import (  # noqa: E402
    ArtifactTypeEnum,
    ClassEnum,
    LifecycleEnum,
    SepEnum,
)
from avidtools.datamodels.vulnerability import (  # noqa: E402
    Vulnerability,
    VulnMetadata,
)


def scrape_cve_ids_from_mileva(url: str) -> Set[str]:
    """
    Scrape unique CVE IDs from a Milev.ai research digest page.
    
    Args:
        url: URL of the Milev.ai research digest page
        
    Returns:
        Set of unique CVE IDs found on the page
    """
    print(f"Scraping CVE IDs from: {url}")
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching Milev.ai page: {e}")
        return set()
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find all CVE IDs using regex pattern (CVE-YYYY-NNNNN)
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
    
    # Search in all text content
    text_content = soup.get_text()
    cve_ids = set(cve_pattern.findall(text_content))
    
    # Also search in links
    for link in soup.find_all('a', href=True):
        href = link['href']
        cve_matches = cve_pattern.findall(href)
        cve_ids.update(cve_matches)
        
        # Check link text
        link_text = link.get_text()
        cve_matches = cve_pattern.findall(link_text)
        cve_ids.update(cve_matches)
    
    print(f"Found {len(cve_ids)} unique CVE IDs: {sorted(cve_ids)}")
    return cve_ids


def scrape_nvd_cve_details(cve_id: str) -> Optional[dict]:
    """
    Fetch CVE details from the MITRE CVE API.
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2024-12911')
        
    Returns:
        Dictionary containing CVE details, or None if fetching fails
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    print(f"Fetching CVE details from: {url}")
    
    try:
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'avidtools-cve-scraper/0.2'
        }
        response = requests.get(url, timeout=30, headers=headers)
        response.raise_for_status()
        cve_data = response.json()
    except requests.RequestException as e:
        print(f"Error fetching CVE data for {cve_id}: {e}")
        return None
    except ValueError as e:
        print(f"Error parsing JSON for {cve_id}: {e}")
        return None
    
    details = {
        'cve_id': cve_id,
        'url': f"https://www.cve.org/CVERecord?id={cve_id}",
        'description': None,
        'published_date': None,
        'last_modified_date': None,
        'cvss_score': None,
        'severity': None,
        'references': [],
        'cwe_ids': [],
        'affected_products': []
    }
    
    # Extract description from containers
    try:
        containers = cve_data.get('containers', {})
        cna = containers.get('cna', {})
        
        # Get description
        descriptions = cna.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                details['description'] = desc.get('value', '').strip()
                break
        if not details['description'] and descriptions:
            details['description'] = descriptions[0].get('value', '').strip()
        
        # Get published and modified dates
        date_published = cve_data.get('cveMetadata', {}).get('datePublished')
        if date_published:
            details['published_date'] = date_published
        
        date_updated = cve_data.get('cveMetadata', {}).get('dateUpdated')
        if date_updated:
            details['last_modified_date'] = date_updated
        
        # Get CVSS metrics
        metrics = cna.get('metrics', [])
        for metric in metrics:
            if 'cvssV3_1' in metric:
                cvss = metric['cvssV3_1']
                details['cvss_score'] = cvss.get('baseScore')
                details['severity'] = cvss.get('baseSeverity')
                break
            elif 'cvssV3_0' in metric:
                cvss = metric['cvssV3_0']
                details['cvss_score'] = cvss.get('baseScore')
                details['severity'] = cvss.get('baseSeverity')
                break
        
        # Get CWE IDs
        problem_types = cna.get('problemTypes', [])
        for pt in problem_types:
            for desc in pt.get('descriptions', []):
                cwe_id = desc.get('cweId')
                if cwe_id:
                    details['cwe_ids'].append(cwe_id)
        
        # Get references
        references = cna.get('references', [])
        for ref in references[:10]:  # Limit to 10 references
            ref_url = ref.get('url')
            if ref_url:
                details['references'].append(ref_url)
        
        # Get affected products
        affected = cna.get('affected', [])
        for aff in affected:
            vendor = aff.get('vendor', 'Unknown')
            product = aff.get('product', 'Unknown')
            details['affected_products'].append({
                'vendor': vendor,
                'product': product
            })
    
    except (KeyError, TypeError, AttributeError) as e:
        print(f"Warning: Error parsing some CVE fields for {cve_id}: {e}")
    
    print(f"Successfully fetched details for {cve_id}")
    return details


def create_vulnerability_from_cve(cve_details: dict) -> Vulnerability:
    """
    Create a Vulnerability object from CVE details.
    
    Args:
        cve_details: Dictionary containing CVE information from NVD
        
    Returns:
        Vulnerability object populated with CVE data
    """
    cve_id = cve_details['cve_id']
    
    # Create metadata
    metadata = VulnMetadata(vuln_id=cve_id)
    
    # Create description
    description = None
    if cve_details['description']:
        description = LangValue(
            lang="eng",
            value=cve_details['description']
        )
    
    # Create references
    references = [
        Reference(
            type="source",
            label="NVD",
            url=cve_details['url']
        )
    ]
    
    # Add additional references
    for ref_url in cve_details['references'][:5]:  # Limit to 5 references
        references.append(
            Reference(
                label="Reference",
                url=ref_url
            )
        )
    
    # Create problemtype
    problemtype_desc = cve_details['description'] or f"Vulnerability {cve_id}"
    if cve_details['cwe_ids']:
        cwe_list = ', '.join(cve_details['cwe_ids'])
        problemtype_desc = f"{cwe_list}: {problemtype_desc}"
    
    problemtype = Problemtype(
        classof=ClassEnum.cve,
        description=LangValue(
            lang="eng",
            value=problemtype_desc[:500]  # Limit length
        )
    )
    
    # Create affects - use affected products if available
    developers = []
    deployers = []
    artifacts = []
    
    if cve_details['affected_products']:
        # Extract unique vendors for developer and deployer
        vendors = set()
        for item in cve_details['affected_products']:
            vendor = item.get('vendor', 'Unknown')
            vendors.add(vendor)
            
            # Create artifact for each product
            product = item.get('product', 'Unknown')
            artifacts.append(
                Artifact(
                    type=ArtifactTypeEnum.system,
                    name=product
                )
            )
        
        developers = list(vendors)
        deployers = list(vendors)
    else:
        # Default values if none specified
        developers = ["Unknown"]
        deployers = ["Unknown"]
        artifacts.append(
            Artifact(
                type=ArtifactTypeEnum.system,
                name="Unknown System"
            )
        )
    
    affects = Affects(
        developer=developers,
        deployer=deployers,
        artifacts=artifacts
    )
    
    # Create impact with AVID taxonomy
    avid_taxonomy = AvidTaxonomy(
        vuln_id=cve_id,
        risk_domain=["Security"],
        sep_view=[SepEnum.S0100],  # Security - Software Vulnerability
        lifecycle_view=[LifecycleEnum.L06],  # Deployment
        taxonomy_version="0.2"
    )
    
    impact = Impact(avid=avid_taxonomy)
    
    # Parse dates
    published_date = None
    last_modified_date = None
    
    try:
        if cve_details['published_date']:
            # Parse date string (format: "MM/DD/YYYY")
            date_str = cve_details['published_date']
            date_match = re.search(r'(\d{1,2})/(\d{1,2})/(\d{4})', date_str)
            if date_match:
                month, day, year = date_match.groups()
                published_date = date(int(year), int(month), int(day))
    except (ValueError, AttributeError):
        pass
    
    try:
        if cve_details['last_modified_date']:
            date_str = cve_details['last_modified_date']
            date_match = re.search(r'(\d{1,2})/(\d{1,2})/(\d{4})', date_str)
            if date_match:
                month, day, year = date_match.groups()
                last_modified_date = date(int(year), int(month), int(day))
    except (ValueError, AttributeError):
        pass
    
    # Create Vulnerability object
    vulnerability = Vulnerability(
        data_type="AVID",
        data_version="0.2",
        metadata=metadata,
        affects=affects,
        problemtype=problemtype,
        references=references,
        description=description,
        impact=impact,
        published_date=published_date,
        last_modified_date=last_modified_date
    )
    
    return vulnerability


def save_vulnerabilities_to_jsonl(
    vulnerabilities: List[Vulnerability], output_path: str
):
    """
    Save a list of Vulnerability objects to a JSONL file.
    
    Args:
        vulnerabilities: List of Vulnerability objects
        output_path: Path to the output JSONL file
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for vuln in vulnerabilities:
            # Convert to JSON string using Pydantic's model_dump_json
            json_str = vuln.model_dump_json(exclude_none=True)
            f.write(json_str + '\n')
    
    print(f"\nSaved {len(vulnerabilities)} vulnerabilities to {output_path}")


def main():
    """Main execution function."""
    print("=" * 80)
    print("CVE Scraper - Milev.ai to AVID Vulnerability Converter")
    print("=" * 80)
    print()
    
    # Step 1: Scrape CVE IDs from Milev.ai
    mileva_url = "https://milev.ai/research/fortnightly-digest-31-march-2025/"
    cve_ids = scrape_cve_ids_from_mileva(mileva_url)
    
    if not cve_ids:
        print("No CVE IDs found. Exiting.")
        return
    
    print()
    print("-" * 80)
    print()
    
    # Step 2 & 3: Scrape NVD details and create Vulnerability objects
    vulnerabilities = []
    
    cve_list = sorted(cve_ids)
    
    for i, cve_id in enumerate(cve_list, 1):
        print(f"Processing {i}/{len(cve_list)}: {cve_id}")
        
        # Scrape CVE details from NVD
        cve_details = scrape_nvd_cve_details(cve_id)
        
        if cve_details:
            # Create Vulnerability object
            try:
                vulnerability = create_vulnerability_from_cve(cve_details)
                vulnerabilities.append(vulnerability)
                print(
                    f"✓ Successfully created Vulnerability object for "
                    f"{cve_id}"
                )
            except Exception as e:
                import traceback
                print(
                    f"✗ Error creating Vulnerability object for "
                    f"{cve_id}: {e}"
                )
                print("Full traceback:")
                traceback.print_exc()
        else:
            print(f"✗ Failed to scrape details for {cve_id}")
        
        print()
        
        # Be respectful to the API server - add a delay between requests
        if i < len(cve_list):
            time.sleep(2)  # 2 second delay between requests
    
    print("-" * 80)
    print()
    
    # Step 4: Save to JSONL
    if vulnerabilities:
        output_path = "mileva_cves.jsonl"
        save_vulnerabilities_to_jsonl(vulnerabilities, output_path)
        
        print()
        print("=" * 80)
        print(
            f"Complete! Processed {len(vulnerabilities)} out of "
            f"{len(cve_ids)} CVEs"
        )
        print("=" * 80)
    else:
        print("No vulnerabilities were successfully created.")


if __name__ == "__main__":
    main()
