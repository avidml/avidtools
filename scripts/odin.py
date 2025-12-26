"""
Script to scrape AI security disclosures from 0din.ai and create AVID reports.

This script:
1. Discovers all disclosure pages by cycling through paginated URLs
2. Extracts disclosure UUIDs from each page
3. Scrapes each disclosure using the URL connector
4. Saves all reports to a JSONL file

Dependencies:
    - beautifulsoup4: For HTML parsing
    - requests: For HTTP requests
    - openai: For AI-powered report generation
    - aiohttp: For asynchronous HTTP requests
"""

import argparse
import asyncio
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set

import aiohttp
import requests
from bs4 import BeautifulSoup

# Import AVID datamodels (sys.path modification required)
sys.path.insert(0, str(Path(__file__).parent.parent))  # noqa: E402

from avidtools.connectors.url import URLConnector  # noqa: E402
from avidtools.datamodels.report import Report  # noqa: E402
from avidtools.datamodels.components import (  # noqa: E402
    Impact,
    OdinTaxonomy,
    JailbreakTaxonomyItem,
)


def scrape_disclosure_pages(base_url: str = "https://0din.ai/disclosures", max_pages: int = 6) -> List[str]:
    """
    Discover all disclosure pages by cycling through pagination.
    
    Args:
        base_url: Base URL for the disclosures page
        max_pages: Maximum number of pages to check (default: 6 for testing)
        
    Returns:
        List of unique page URLs
    """
    print(f"Discovering disclosure pages from: {base_url}")
    print(f"Processing {max_pages} page(s)")
    
    page_urls = []
    
    for page_num in range(1, max_pages + 1):
        page_url = f"{base_url}?page={page_num}"
        print(f"Checking page {page_num}: {page_url}")
        
        try:
            response = requests.get(page_url, timeout=30)
            response.raise_for_status()
            page_urls.append(page_url)
        except requests.RequestException as e:
            print(f"Error fetching page {page_num}: {e}")
            break
        
        time.sleep(0.5)  # Be respectful with rate limiting
    
    print(f"Found {len(page_urls)} disclosure page(s)")
    return page_urls


def extract_disclosure_uuids(page_url: str) -> Set[str]:
    """
    Extract disclosure UUIDs from a disclosure page.
    
    Looks for links with pattern: <a data-turbo-frame="_top" href="/disclosures/<uuid>">
    
    Args:
        page_url: URL of the disclosure page to scrape
        
    Returns:
        Set of unique disclosure UUIDs
    """
    print(f"Extracting UUIDs from: {page_url}")
    
    try:
        response = requests.get(page_url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching page: {e}")
        return set()
    
    soup = BeautifulSoup(response.content, 'html.parser')
    
    # Pattern to match UUIDs (standard UUID format)
    uuid_pattern = re.compile(
        r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        re.IGNORECASE
    )
    
    uuids = set()
    
    # Look for links with data-turbo-frame="_top" and href containing /disclosures/
    for link in soup.find_all('a', {'data-turbo-frame': '_top', 'href': True}):
        href = link['href']
        if '/disclosures/' in href:
            match = uuid_pattern.search(href)
            if match:
                uuid = match.group(1)
                uuids.add(uuid)
                print(f"  Found UUID: {uuid}")
    
    print(f"Found {len(uuids)} unique disclosure UUIDs")
    return uuids


def scrape_all_disclosure_uuids(page_urls: List[str], limit_per_page: Optional[int] = None) -> List[str]:
    """
    Extract all unique disclosure UUIDs from all pages.
    
    Args:
        page_urls: List of disclosure page URLs
        limit_per_page: If set, limit to this many UUIDs per page (for testing)
        
    Returns:
        Sorted list of unique disclosure UUIDs
    """
    all_uuids = set()
    
    for page_url in page_urls:
        uuids = extract_disclosure_uuids(page_url)
        if limit_per_page and uuids:
            # Take only the first N UUIDs from this page
            uuids = set(sorted(uuids)[:limit_per_page])
        all_uuids.update(uuids)
        time.sleep(1)  # Be respectful between page scrapes
    
    print(f"\nTotal unique disclosure UUIDs found: {len(all_uuids)}")
    return sorted(all_uuids)


def extract_odin_metadata_from_html(html_content: str, page_text: str) -> dict:
    """
    Extract 0DIN-specific metadata from already-scraped HTML content.
    
    Extracts Social Impact Score level and Jailbreak Taxonomy values.
    
    Args:
        html_content: HTML content from the page
        page_text: Text content from the page
        
    Returns:
        Dictionary with 'social_impact_score' and 'jailbreak_taxonomy' keys
    """
    print(f"Extracting 0DIN metadata from scraped content...")
    
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Extract Social Impact Score
    social_impact_score = None
    # Look for heading containing "Level X:" pattern (just the level and category)
    level_pattern = re.compile(r'Level [1-5]: [A-Za-z\s]+(?=\n|Violations|Example)', re.IGNORECASE)
    match = level_pattern.search(page_text)
    if match:
        social_impact_score = match.group(0).strip()
        print(f"  Found Social Impact Score: {social_impact_score}")
    
    # Extract Jailbreak Taxonomies from span elements under "Taxonomies" h3
    taxonomy_terms = []
    
    # Find h3 containing 'Taxonomies'
    h3_elements = soup.find_all('h3')
    for h3 in h3_elements:
        if 'Taxonom' in h3.get_text():
            # Get parent div
            parent = h3.find_parent('div')
            if parent:
                # Find all direct child span elements within divs
                divs = parent.find_all('div', recursive=True)
                for div in divs:
                    spans = div.find_all('span', recursive=False)
                    for span in spans:
                        text = span.get_text().strip()
                        if text:
                            taxonomy_terms.append(text)
            break
    
    # Group terms into sets of 3 for Category, Strategy, Technique
    jailbreak_taxonomy = []
    for i in range(0, len(taxonomy_terms), 3):
        group = taxonomy_terms[i:i+3]
        taxonomy_item = JailbreakTaxonomyItem(
            Category=group[0] if len(group) > 0 else None,
            Strategy=group[1] if len(group) > 1 else None,
            Technique=group[2] if len(group) > 2 else None
        )
        jailbreak_taxonomy.append(taxonomy_item)
    
    if jailbreak_taxonomy:
        print(f"  Found Jailbreak Taxonomies: {jailbreak_taxonomy}")
    
    return {
        "social_impact_score": social_impact_score,
        "jailbreak_taxonomy": jailbreak_taxonomy
    }


def create_impact(odin_metadata: dict) -> Impact:
    """
    Create Impact object with 0DIN taxonomy.
    
    Args:
        odin_metadata: Dictionary with social_impact_score and jailbreak_taxonomy
        
    Returns:
        Impact object with AVID and 0DIN taxonomy
    """
    # # Create AVID taxonomy (generic for 0DIN disclosures)
    # avid_taxonomy = AvidTaxonomy(
    #     risk_domain=["Security"],
    #     sep_view=[SepEnum.S0100],  # Adversarial Example
    #     lifecycle_view=[LifecycleEnum.L06],  # Deployment
    #     taxonomy_version="0.2"
    # )
    
    # Create 0DIN taxonomy
    odin_taxonomy = None
    if odin_metadata["social_impact_score"] or odin_metadata["jailbreak_taxonomy"]:
        odin_taxonomy = OdinTaxonomy(
            SocialImpactScore=odin_metadata["social_impact_score"],
            JailbreakTaxonomy=odin_metadata["jailbreak_taxonomy"] if odin_metadata["jailbreak_taxonomy"] else None
        )
    
    return Impact(
        odin=odin_taxonomy
    )


async def scrape_url_async(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Asynchronously scrape content from a URL.
    Uses cached HTML files from scraped_html/ directory if available.
    
    Args:
        session: aiohttp ClientSession
        url: URL to scrape
        
    Returns:
        Dictionary with scraped content
    """
    # Try to load from cache first
    if '/disclosures/' in url:
        uuid = url.split('/')[-1]
        cached_file = Path(__file__).parent / "scraped_html" / f"{uuid}.html"
        
        if cached_file.exists():
            print(f"  Using cached HTML from {cached_file.name}")
            content = cached_file.read_text(encoding='utf-8')
            soup = BeautifulSoup(content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style", "nav", "footer", "header"]):
                script.decompose()
            
            # Get title
            title = soup.title.string if soup.title else ""
            
            # Get main text content
            text = soup.get_text(separator="\n", strip=True)
            
            # Clean up whitespace
            lines = (line.strip() for line in text.splitlines())
            text = "\n".join(line for line in lines if line)
            
            return {
                "url": url,
                "title": title.strip(),
                "text": text,
                "html": str(soup)[:50000],
            }
    
    # Fall back to live scraping if no cache available
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
        response.raise_for_status()
        content = await response.read()
        
        soup = BeautifulSoup(content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.decompose()
        
        # Get title
        title = soup.title.string if soup.title else ""
        
        # Get main text content
        text = soup.get_text(separator="\n", strip=True)
        
        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        text = "\n".join(line for line in lines if line)
        
        return {
            "url": url,
            "title": title.strip(),
            "text": text,
            "html": str(soup)[:50000],
        }


async def process_disclosure_async(
    connector: URLConnector, session: aiohttp.ClientSession, uuid: str, index: int, total: int, base_url: str
) -> Optional[Report]:
    """
    Asynchronously process a single disclosure: scrape and create Report object with 0DIN metadata.
    
    Args:
        connector: URLConnector instance for AI calls
        session: aiohttp ClientSession for scraping
        uuid: Disclosure UUID
        index: Current index (for progress display)
        total: Total number of disclosures
        base_url: Base URL for disclosures
        
    Returns:
        Report object or None if failed
    """
    disclosure_url = f"{base_url}/{uuid}"
    print(f"\nProcessing {index}/{total}: {uuid}")
    print(f"URL: {disclosure_url}")
    
    try:
        # Step 1: Scrape the page once (async)
        print(f"Scraping URL: {disclosure_url}")
        scraped_data = await scrape_url_async(session, disclosure_url)
        print(f"Scraped content: {len(scraped_data['text'])} characters")
        
        # Step 2: Extract 0DIN metadata from scraped content
        odin_metadata = extract_odin_metadata_from_html(
            scraped_data['html'], 
            scraped_data['text']
        )
        
        # Step 3: Create report using AI
        print(f"Calling AI agent ({connector.model})...")
        prompt = connector._create_ai_prompt(scraped_data)
        
        for attempt in range(3):  # max_retries + 1
            try:
                response = connector.client.chat.completions.create(
                    model=connector.model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You are an AI security expert specializing in AI/ML vulnerabilities. You extract structured information from text and return valid JSON.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=4000,
                )

                ai_response = response.choices[0].message.content
                print(f"AI response received ({len(ai_response)} characters)")

                parsed_data = connector._parse_ai_response(ai_response)
                print("Successfully parsed AI response")

                report = connector._build_report_from_json(parsed_data)
                print(f"Created AVID report: {report.metadata.report_id if report.metadata else 'N/A'}")
                
                break
            except Exception as e:
                if attempt < 2:
                    print(f"Attempt {attempt + 1} failed: {str(e)}. Retrying...")
                    await asyncio.sleep(1)
                    continue
                else:
                    raise RuntimeError(f"Failed to create report after 3 attempts: {str(e)}")
        
        # Step 4: Create and populate Impact field
        impact = create_impact(odin_metadata)
        report.impact = impact
        
        print(f"✓ Successfully created Report for {uuid}")
        return report
    except Exception as e:
        print(f"✗ Error creating Report for {uuid}: {e}")
        return None


async def process_all_disclosures_async(
    uuids: List[str], api_key: Optional[str] = None, model: str = "gpt-4o-mini", max_concurrent: int = 2
) -> List[Report]:
    """
    Process all disclosures asynchronously using the URL connector.
    
    Args:
        uuids: List of disclosure UUIDs to process
        api_key: OpenAI API key
        model: OpenAI model to use
        max_concurrent: Maximum number of concurrent requests (reduced to 2 for rate limit stability)
        
    Returns:
        List of successfully created Report objects
    """
    reports = []
    base_url = "https://0din.ai/disclosures"
    
    # Initialize URL connector
    try:
        connector = URLConnector(api_key=api_key, model=model)
    except ValueError as e:
        print(f"Error initializing URL connector: {e}")
        return reports
    
    print(f"\nProcessing {len(uuids)} disclosures sequentially...")
    print("=" * 80)
    
    # Process sequentially instead of concurrently for reliability
    async with aiohttp.ClientSession() as session:
        for i, uuid in enumerate(uuids, 1):
            result = await process_disclosure_async(connector, session, uuid, i, len(uuids), base_url)
            if isinstance(result, Report):
                reports.append(result)
            await asyncio.sleep(0.5)  # Small delay between requests
    
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
    
    print(f"\nSaved {len(reports)} reports to {output_path}")


def download_page_if_needed(uuid: str, cached_html_dir: Path) -> bool:
    """
    Download and save a disclosure page if it doesn't exist locally.
    
    Args:
        uuid: Disclosure UUID
        cached_html_dir: Directory to save HTML files
        
    Returns:
        True if successful, False otherwise
    """
    cached_file = cached_html_dir / f"{uuid}.html"
    
    if cached_file.exists():
        return True
    
    url = f"https://0din.ai/disclosures/{uuid}"
    print(f"  Downloading {uuid}...")
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        cached_file.write_text(response.text, encoding='utf-8')
        print(f"    ✓ Saved to {cached_file.name}")
        return True
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return False


def main(
    page_number: int = 1,
    output_dir: Optional[Path] = None,
    api_key: Optional[str] = None,
    model: str = "gpt-4o-mini"
):
    """
    Main execution function.
    
    Args:
        page_number: Page number to scrape from 0din.ai (default: 1)
        output_dir: Directory to save output file. Defaults to script directory.
        api_key: OpenAI API key. Uses OPENAI_API_KEY env var if not provided.
        model: OpenAI model to use for report generation.
    """
    print("=" * 80)
    print("0din.ai Disclosure Scraper - AVID Report Generator")
    print("=" * 80)
    print()
    
    # Get API key from environment if not provided
    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY")
    
    if not api_key:
        print("Error: OpenAI API key required. Set OPENAI_API_KEY environment variable or use --api-key")
        return
    
    # Step 1: Get disclosure UUIDs from the specified page and download if needed
    print(f"Step 1: Extracting disclosure UUIDs from page {page_number}...")
    print("-" * 80)
    
    page_url = f"https://0din.ai/disclosures?page={page_number}"
    uuids_set = extract_disclosure_uuids(page_url)
    
    if not uuids_set:
        print(f"No disclosure UUIDs found on page {page_number}. Exiting.")
        return
    
    uuids_list = sorted(uuids_set)
    
    # Step 2: Ensure all disclosure HTML files are cached locally
    print(f"\nStep 2: Ensuring {len(uuids_list)} disclosures are cached locally...")
    print("-" * 80)
    
    cached_html_dir = Path(__file__).parent / "scraped_html"
    cached_html_dir.mkdir(exist_ok=True)
    
    for uuid in uuids_list:
        download_page_if_needed(uuid, cached_html_dir)
        time.sleep(0.3)  # Small delay between downloads
    
    print()
    print("-" * 80)
    print()
    
    # Step 3: Process all disclosures asynchronously
    print("Step 3: Processing disclosures and creating reports...")
    print("-" * 80)
    reports = asyncio.run(process_all_disclosures_async(uuids_list, api_key=api_key, model=model))
    
    print()
    print("=" * 80)
    print()
    
    # Step 4: Save reports to JSONL file
    if reports:
        print("Step 4: Saving reports...")
        print("-" * 80)
        
        # Generate timestamped filename
        utc_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"odin_disclosures_{utc_timestamp}.jsonl"
        
        # Determine output path
        if output_dir:
            output_path = output_dir / filename
        else:
            # Default to script directory
            script_dir = Path(__file__).parent
            output_path = script_dir / filename
        
        save_reports_to_jsonl(reports, str(output_path))
        
        print()
        print("=" * 80)
        print(
            f"Complete! Successfully processed {len(reports)} out of "
            f"{len(uuids_list)} disclosures into Report objects"
        )
        print()
        print("Output file:")
        print(f"  {output_path}")
        print("=" * 80)
    else:
        print("No Reports were successfully created.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scrape AI security disclosures from 0din.ai and convert to AVID Reports"
    )
    parser.add_argument(
        "--page",
        type=int,
        default=1,
        help="Page number to scrape from 0din.ai (default: 1)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory for JSONL file (default: script directory)"
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="OpenAI API key (default: use OPENAI_API_KEY environment variable)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-4o-mini",
        help="OpenAI model to use (default: gpt-4o-mini)"
    )
    
    args = parser.parse_args()
    
    main(page_number=args.page, output_dir=args.output_dir, api_key=args.api_key, model=args.model)