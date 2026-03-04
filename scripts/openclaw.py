"""Script to scrape published OpenClaw CVE IDs and build AVID reports."""

import argparse
import asyncio
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Set

import requests

sys.path.insert(0, str(Path(__file__).parent.parent))  # noqa: E402

from avidtools.connectors.cve import (  # noqa: E402
    fetch_reports_for_cves,
    save_reports_to_jsonl,
)


def _extract_repo_owner_and_name(repo_url: str) -> tuple[str, str]:
    """Extract owner and repository name from a GitHub repository URL."""
    stripped = repo_url.rstrip("/")
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)", stripped)
    if not match:
        raise ValueError(f"Unsupported GitHub repository URL: {repo_url}")
    return match.group(1), match.group(2)


def scrape_published_cve_ids_from_openclaw(repo_url: str) -> Set[str]:
    """Scrape published CVE IDs from OpenClawCVEs README.

    This targets the "CVEs Published in cvelistV5" section to avoid
    RESERVED CVEs listed in the pipeline section.
    """
    print(f"Scraping published CVE IDs from: {repo_url}")

    try:
        owner, repo = _extract_repo_owner_and_name(repo_url)
    except ValueError as e:
        print(f"Error: {e}")
        return set()

    readme_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/README.md"

    try:
        response = requests.get(readme_url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching README from {readme_url}: {e}")
        return set()

    readme_text = response.text

    section_match = re.search(
        r"##\s+🚀\s+CVEs Published in cvelistV5.*?(?=\n##\s+|\Z)",
        readme_text,
        flags=re.DOTALL,
    )

    section_text = section_match.group(0) if section_match else readme_text

    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}")
    cve_ids = set(cve_pattern.findall(section_text))

    print(f"Found {len(cve_ids)} published CVE IDs: {sorted(cve_ids)}")
    return cve_ids


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scrape published CVEs from OpenClawCVEs and convert to AVID Reports"
    )
    parser.add_argument(
        "--repo-url",
        type=str,
        default="https://github.com/jgamblin/OpenClawCVEs/",
        help="OpenClaw CVE repository URL",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory for JSONL file (default: avid-db/reports/review)",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("CVE Scraper - OpenClawCVEs to AVID Report Converter")
    print("=" * 80)
    print()

    cve_ids = sorted(scrape_published_cve_ids_from_openclaw(args.repo_url))
    if not cve_ids:
        print("No published CVE IDs found. Exiting.")
        raise SystemExit(1)

    print(f"Requesting {len(cve_ids)} CVEs from connector...")
    reports = asyncio.run(fetch_reports_for_cves(cve_ids, max_concurrent=10))
    if not reports:
        print("No Reports were created.")
        raise SystemExit(1)

    utc_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"openclaw_cve_digest_{utc_timestamp}.jsonl"
    script_dir = Path(__file__).parent
    default_output = (
        script_dir.parent.parent / "avid-db" / "reports" / "review" / filename
    )
    output_path = (args.output_dir / filename) if args.output_dir else default_output

    save_reports_to_jsonl(reports, str(output_path))

    print()
    print("=" * 80)
    print(
        "Complete! Successfully processed "
        f"{len(reports)} out of {len(cve_ids)} published CVEs"
    )
    print("Output file:")
    print(f"  - {output_path}")
    print("=" * 80)
