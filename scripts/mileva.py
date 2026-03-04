"""Script to scrape Milev.ai digests and build AVID reports from CVEs."""

import argparse
import asyncio
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent.parent))  # noqa: E402

from avidtools.connectors.cve import (  # noqa: E402
    fetch_reports_for_cves,
    save_reports_to_jsonl,
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

    soup = BeautifulSoup(response.content, "html.parser")

    # Find all links containing 'fortnightly-digest' in the href
    digest_urls = []
    for link in soup.find_all("a", href=True):
        href = link["href"]
        if "fortnightly-digest" in href.lower():
            # Handle relative URLs
            if href.startswith("/"):
                full_url = f"https://milev.ai{href}"
            elif not href.startswith("http"):
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

    soup = BeautifulSoup(response.content, "html.parser")

    # Find all CVE IDs using regex pattern (CVE-YYYY-NNNNN)
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}")

    # Search in all text content
    text_content = soup.get_text()
    cve_ids = set(cve_pattern.findall(text_content))

    # Also search in links
    for link in soup.find_all("a", href=True):
        href = link["href"]
        cve_matches = cve_pattern.findall(href)
        cve_ids.update(cve_matches)

        # Check link text
        link_text = link.get_text()
        cve_matches = cve_pattern.findall(link_text)
        cve_ids.update(cve_matches)

    print(f"Found {len(cve_ids)} unique CVE IDs: {sorted(cve_ids)}")
    return cve_ids


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scrape CVE data from Milev.ai and convert to AVID Reports"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory for JSONL file (default: script directory)",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("CVE Scraper - Milev.ai to AVID Report Converter")
    print("=" * 80)
    print()

    research_url = "https://milev.ai/research/"
    digest_urls = scrape_fortnightly_digest_urls(research_url)
    if not digest_urls:
        print("No fortnightly digest pages found. Exiting.")
        raise SystemExit(1)

    all_cve_ids: set[str] = set()
    for digest_url in digest_urls:
        all_cve_ids.update(scrape_cve_ids_from_mileva(digest_url))
        time.sleep(1)

    print()
    print(f"Total unique CVE IDs found across all digests: {len(all_cve_ids)}")
    if not all_cve_ids:
        print("No CVE IDs found. Exiting.")
        raise SystemExit(1)

    cve_ids = sorted(all_cve_ids)
    print(f"Requesting {len(cve_ids)} CVEs from connector...")

    reports = asyncio.run(fetch_reports_for_cves(cve_ids, max_concurrent=10))
    if not reports:
        print("No Reports were created.")
        raise SystemExit(1)

    utc_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"cve_digest_{utc_timestamp}.jsonl"
    script_dir = Path(__file__).parent
    default_output = (
        script_dir.parent.parent / "avid-db" / "reports" / "review" / filename
    )
    output_path = (
        (args.output_dir / filename) if args.output_dir else default_output
    )

    save_reports_to_jsonl(reports, str(output_path))
    print()
    print("=" * 80)
    print(
        "Complete! Successfully processed "
        f"{len(reports)} out of {len(cve_ids)} CVEs"
    )
    print("Output file:")
    print(f"  - {output_path}")
    print("=" * 80)
