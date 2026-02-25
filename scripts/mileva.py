"""
Script to scrape CVE information from Milev.ai and NVD.

This script structures CVE data into AVID Report objects.

This script:
1. Scrapes unique CVE IDs from Milev.ai research digest pages
2. Fetches detailed CVE information from NVD
3. Structures the data into AVID Report objects
4. Saves all vulnerabilities to a JSONL file

Dependencies:
    - beautifulsoup4: For HTML parsing
    - requests: For HTTP requests
    - aiohttp: For asynchronous HTTP requests to the MITRE CVE API
"""

import argparse
import asyncio
import re
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import List, Optional, Set

import aiohttp
import requests
from bs4 import BeautifulSoup

# Import AVID datamodels (sys.path modification required)
sys.path.insert(0, str(Path(__file__).parent.parent))  # noqa: E402

from avidtools.datamodels.components import (  # noqa: E402
    Affects,
    Artifact,
    AvidTaxonomy,
    CVSSScores,
    CWETaxonomy,
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
    TypeEnum,
)
from avidtools.datamodels.vulnerability import (  # noqa: E402
    Vulnerability,
    VulnMetadata,
)
from avidtools.datamodels.report import (  # noqa: E402
    Report,
)


def scrape_fortnightly_digest_urls(research_url: str) -> List[str]:
    """
    Scrape all fortnightly digest URLs from Milev.ai research page.
    
    Args:
        research_url: URL of the Milev.ai research page
        
    Returns:
        List of fortnightly digest URLs
    """
    print(f"Scraping fortnightly digest links from: {research_url}")
    
    try:
        response = requests.get(research_url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching research page: {e}")
        return []
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Find all links containing 'fortnightly-digest' in the href
    digest_urls = []
    for link in soup.find_all('a', href=True):
        href = link['href']
        if 'fortnightly-digest' in href.lower():
            # Handle relative URLs
            if href.startswith('/'):
                full_url = f"https://milev.ai{href}"
            elif not href.startswith('http'):
                full_url = f"https://milev.ai/{href}"
            else:
                full_url = href
            
            if full_url not in digest_urls:
                digest_urls.append(full_url)
    
    print(f"Found {len(digest_urls)} fortnightly digest pages")
    return digest_urls


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


async def scrape_nvd_cve_details(
    session: aiohttp.ClientSession, cve_id: str
) -> Optional[dict]:
    """
    Fetch CVE details from the MITRE CVE API asynchronously.
    
    Args:
        session: aiohttp ClientSession for making requests
        cve_id: CVE identifier (e.g., 'CVE-2024-12911')
        
    Returns:
        Dictionary containing CVE details, or None if fetching fails
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    
    try:
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'avidtools-cve-scraper/0.2'
        }
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=30), headers=headers
        ) as response:
            response.raise_for_status()
            cve_data = await response.json()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Error fetching CVE data for {cve_id}: {e}")
        return None
    except ValueError as e:
        print(f"Error parsing JSON for {cve_id}: {e}")
        return None
    
    details = {
        'cve_id': cve_id,
        'url': f"https://www.cve.org/CVERecord?id={cve_id}",
        'title': None,
        'description': None,
        'published_date': None,
        'last_modified_date': None,
        'cvss_score': None,
        'severity': None,
        'cvss_data': None,
        'references': [],
        'cwe_ids': [],
        'cwe_data': [],
        'affected_products': []
    }
    
    # Extract description from containers
    try:
        containers = cve_data.get('containers', {})
        cna = containers.get('cna', {})

        # Get CNA title
        title = cna.get('title')
        if isinstance(title, str):
            details['title'] = title.strip()
        
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
                details['cvss_data'] = cvss
                break
            elif 'cvssV3_0' in metric:
                cvss = metric['cvssV3_0']
                details['cvss_score'] = cvss.get('baseScore')
                details['severity'] = cvss.get('baseSeverity')
                details['cvss_data'] = cvss
                break
        
        # Get CWE data with descriptions
        problem_types = cna.get('problemTypes', [])
        for pt in problem_types:
            for desc in pt.get('descriptions', []):
                cwe_id = desc.get('cweId')
                if cwe_id:
                    details['cwe_ids'].append(cwe_id)
                    details['cwe_data'].append({
                        'cweId': cwe_id,
                        'description': desc.get('description', ''),
                        'lang': desc.get('lang', 'en')
                    })
        
        # Get references
        references = cna.get('references', [])
        for ref in references:
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


def create_description(cve_id: str, cve_details: dict) -> Optional[LangValue]:
    """Create description LangValue object."""
    if cve_details['description']:
        return LangValue(lang="eng", value=cve_details['description'])
    return None


def create_references(cve_details: dict) -> List[Reference]:
    """Create references list from CVE details."""
    references = [
        Reference(
            type="source",
            label="NVD entry",
            url=cve_details['url']
        )
    ]
    
    for ref_url in cve_details['references']:
        references.append(
            Reference(
                type="source",
                label=ref_url,
                url=ref_url
            )
        )
    
    return references


def create_problemtype(cve_id: str, cve_details: dict) -> Problemtype:
    """Create problemtype from CVE details."""
    problemtype_desc = cve_details.get('title') or f"Vulnerability {cve_id}"
    
    return Problemtype(
        classof=ClassEnum.cve,
        type=TypeEnum.advisory,
        description=LangValue(
            lang="eng",
            value=problemtype_desc
        )
    )


def create_affects(cve_details: dict) -> Affects:
    """Create affects from CVE details."""
    developers = []
    deployers = []
    artifacts = []
    
    if cve_details['affected_products']:
        vendors = set()
        for item in cve_details['affected_products']:
            vendor = item.get('vendor', 'Unknown')
            vendors.add(vendor)
            
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
        developers = ["Unknown"]
        deployers = ["Unknown"]
        artifacts.append(
            Artifact(
                type=ArtifactTypeEnum.system,
                name="Unknown System"
            )
        )
    
    return Affects(
        developer=developers,
        deployer=deployers,
        artifacts=artifacts
    )


def create_impact(
    cve_id: str, cve_details: dict, include_vuln_id: bool = False
) -> Impact:
    """Create impact with AVID taxonomy, CVSS, and CWE."""
    avid_taxonomy = AvidTaxonomy(
        vuln_id=cve_id if include_vuln_id else None,
        risk_domain=["Security"],
        sep_view=[SepEnum.S0100],
        lifecycle_view=[LifecycleEnum.L06],
        taxonomy_version="0.2"
    )
    
    cvss = None
    if cve_details.get('cvss_data'):
        cvss_data = cve_details['cvss_data']
        cvss = CVSSScores(
            version=cvss_data.get('version', '3.0'),
            vectorString=cvss_data.get('vectorString', ''),
            baseScore=cvss_data.get('baseScore', 0.0),
            baseSeverity=cvss_data.get('baseSeverity', 'UNKNOWN'),
            attackVector=cvss_data.get('attackVector'),
            attackComplexity=cvss_data.get('attackComplexity'),
            privilegesRequired=cvss_data.get('privilegesRequired'),
            userInteraction=cvss_data.get('userInteraction'),
            scope=cvss_data.get('scope'),
            confidentialityImpact=cvss_data.get('confidentialityImpact'),
            integrityImpact=cvss_data.get('integrityImpact'),
            availabilityImpact=cvss_data.get('availabilityImpact')
        )
    
    cwe = None
    if cve_details.get('cwe_data'):
        cwe = []
        for cwe_item in cve_details['cwe_data']:
            cwe.append(
                CWETaxonomy(
                    cweId=cwe_item['cweId'],
                    description=cwe_item.get('description'),
                    lang=cwe_item.get('lang')
                )
            )
    
    return Impact(
        avid=avid_taxonomy,
        cvss=cvss,
        cwe=cwe
    )


def parse_date(date_str: Optional[str]) -> Optional[date]:
    """Parse ISO 8601 date string to date object."""
    if not date_str:
        return None
    try:
        date_only = date_str.split('T')[0]
        return date.fromisoformat(date_only)
    except (ValueError, AttributeError, TypeError):
        return None


def create_report_from_cve(cve_details: dict) -> Report:
    """
    Create a Report object from CVE details.
    
    Args:
        cve_details: Dictionary containing CVE information from API
        
    Returns:
        Report object populated with CVE data
    """
    cve_id = cve_details['cve_id']
    description = create_description(cve_id, cve_details)
    references = create_references(cve_details)
    problemtype = create_problemtype(cve_id, cve_details)
    affects = create_affects(cve_details)
    impact = create_impact(cve_id, cve_details, include_vuln_id=False)
    reported_date = parse_date(cve_details.get('published_date'))
    
    return Report(
        data_type="AVID",
        data_version="0.2",
        affects=affects,
        problemtype=problemtype,
        references=references,
        description=description,
        impact=impact,
        reported_date=reported_date
    )


def create_vulnerability_from_cve(cve_details: dict) -> Vulnerability:
    """
    Create a Vulnerability object from CVE details.
    
    Args:
        cve_details: Dictionary containing CVE information from NVD
        
    Returns:
        Vulnerability object populated with CVE data
    """
    cve_id = cve_details['cve_id']
    
    metadata = VulnMetadata(vuln_id=cve_id)
    description = create_description(cve_id, cve_details)
    references = create_references(cve_details)
    problemtype = create_problemtype(cve_id, cve_details)
    affects = create_affects(cve_details)
    impact = create_impact(cve_id, cve_details, include_vuln_id=True)
    published_date = parse_date(cve_details.get('published_date'))
    last_modified_date = parse_date(cve_details.get('last_modified_date'))
    
    return Vulnerability(
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
    
    print(f"Saved {len(vulnerabilities)} vulnerabilities to {output_path}")


async def process_single_cve(
    session: aiohttp.ClientSession, cve_id: str, index: int, total: int
) -> Optional[Report]:
    """
    Process a single CVE: fetch details and create Report object.
    
    Args:
        session: aiohttp ClientSession
        cve_id: CVE identifier
        index: Current index (for progress display)
        total: Total number of CVEs
        
    Returns:
        Report object or None if failed
    """
    print(f"Processing {index}/{total}: {cve_id}")
    
    cve_details = await scrape_nvd_cve_details(session, cve_id)
    
    if cve_details:
        try:
            report = create_report_from_cve(cve_details)
            print(f"✓ Successfully created Report for {cve_id}")
            return report
        except Exception as e:
            print(f"✗ Error creating Report for {cve_id}: {e}")
            return None
    else:
        print(f"✗ Failed to fetch details for {cve_id}")
        return None


async def process_cves_async(
    cve_list: List[str], max_concurrent: int = 10
) -> List[Report]:
    """
    Process multiple CVEs concurrently using async/await.
    
    Args:
        cve_list: List of CVE IDs to process
        max_concurrent: Maximum number of concurrent requests
        
    Returns:
        List of Report objects
    """
    reports = []
    
    connector = aiohttp.TCPConnector(limit=max_concurrent)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Create tasks for all CVEs
        tasks = [
            process_single_cve(session, cve_id, i + 1, len(cve_list))
            for i, cve_id in enumerate(cve_list)
        ]
        
        # Process with progress updates
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect successful results
        for result in results:
            if isinstance(result, Report):
                reports.append(result)
    
    return reports


def save_reports_to_jsonl(reports: List[Report], output_path: str):
    """
    Save a list of Report objects to a JSONL file.
    
    Args:
        reports: List of Report objects
        output_path: Path to the output JSONL file
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for report in reports:
            # Convert to JSON string using Pydantic's model_dump_json
            json_str = report.model_dump_json(exclude_none=True)
            f.write(json_str + '\n')
    
    print(f"Saved {len(reports)} reports to {output_path}")


def main(output_dir: Optional[Path] = None):
    """Main execution function.
    
    Args:
        output_dir: Directory to save output file. Defaults to script directory.
    """
    print("="*80)
    print("CVE Scraper - Milev.ai to AVID Vulnerability Converter")
    print("="*80)
    print()
    
    # Step 1: Scrape all fortnightly digest URLs
    research_url = "https://milev.ai/research/"
    digest_urls = scrape_fortnightly_digest_urls(research_url)
    
    if not digest_urls:
        print("No fortnightly digest pages found. Exiting.")
        return
    
    print()
    
    # Step 2: Scrape CVE IDs from all digest pages
    all_cve_ids = set()
    for digest_url in digest_urls:
        cve_ids = scrape_cve_ids_from_mileva(digest_url)
        all_cve_ids.update(cve_ids)
        time.sleep(1)  # Be respectful between page scrapes
    
    print()
    print(f"Total unique CVE IDs found across all digests: {len(all_cve_ids)}")
    
    if not all_cve_ids:
        print("No CVE IDs found. Exiting.")
        return
    
    print()
    print("-" * 80)
    print()
    
    # Step 3 & 4: Scrape CVE details and create Report objects (async)
    cve_list = sorted(all_cve_ids)
    
    print(f"Processing {len(cve_list)} CVEs with concurrent requests...")
    print()
    
    reports = asyncio.run(
        process_cves_async(cve_list, max_concurrent=10)
    )
    
    print("-" * 80)
    print()
    
    # Step 4: Save to JSONL file in avid-db/reports/review/
    if reports:
        print("Saving outputs...")
        
        # Generate timestamped filename
        utc_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"cve_digest_{utc_timestamp}.jsonl"
        
        # Determine output path (relative to this script's location)
        script_dir = Path(__file__).parent
        avid_db_path = script_dir.parent.parent / "avid-db"
        review_path = avid_db_path / "reports" / "review"
        output_path = review_path / filename
        
        save_reports_to_jsonl(reports, str(output_path))
        
        print()
        print("=" * 80)
        print(
            f"Complete! Successfully processed {len(reports)} out of "
            f"{len(cve_list)} CVEs into Report objects"
        )
        print("Output file:")
        print(f"  - {output_path}")
        print("=" * 80)
    else:
        print("No Reports were successfully created.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scrape CVE data from Milev.ai and convert to AVID Reports"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory for JSONL file (default: script directory)"
    )
    
    args = parser.parse_args()
    
    main(output_dir=args.output_dir)
