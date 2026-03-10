"""Script to scrape Mindgard disclosures and build AVID reports."""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent.parent))  # noqa: E402

from avidtools.datamodels.components import (  # noqa: E402
    Affects,
    Artifact,
    ArtifactTypeEnum,
    ClassEnum,
    LangValue,
    Problemtype,
    Reference,
)
from avidtools.datamodels.report import Report  # noqa: E402


def _normalize_whitespace(value: str) -> str:
    return " ".join(value.split()).strip()


def _split_list_field(value: str) -> list[str]:
    text = _normalize_whitespace(value)
    if not text:
        return []

    parts = re.split(r"\s*(?:,|;|\band\b|\|)\s*", text, flags=re.IGNORECASE)
    out: list[str] = []
    for part in parts:
        cleaned = _normalize_whitespace(part)
        if cleaned and cleaned not in out:
            out.append(cleaned)
    return out


def _extract_field_cells(soup: BeautifulSoup) -> dict[str, BeautifulSoup]:
    """Map disclosure table header labels to their adjacent value cells."""
    field_cells: dict[str, BeautifulSoup] = {}

    for header in soup.select("p.tableheaders"):
        label = _normalize_whitespace(header.get_text(" ", strip=True))
        if not label:
            continue

        label_cell = header.find_parent("div", class_="w-layout-cell")
        if label_cell is None:
            continue

        value_cell = label_cell.find_next_sibling("div")
        if value_cell is None:
            continue

        classes = value_cell.get("class") or []
        if "divider" in classes:
            continue

        field_cells[label] = value_cell

    return field_cells


def _extract_timeline_published_on(timeline_text: str) -> Optional[str]:
    for pattern in (
        r"Published\s+on\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})",
        r"Disclosed\s+to\s+Vendor\s+on\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})",
    ):
        match = re.search(pattern, timeline_text, flags=re.IGNORECASE)
        if not match:
            continue

        raw_date = match.group(1)
        try:
            return datetime.strptime(raw_date, "%B %d, %Y").date().isoformat()
        except ValueError:
            continue

    return None


def _field_text(field_cells: dict[str, BeautifulSoup], label: str) -> str:
    value_cell = field_cells.get(label)
    if value_cell is None:
        return ""
    return _normalize_whitespace(value_cell.get_text(" ", strip=True))


def scrape_published_disclosure_links(source_url: str) -> list[str]:
    """Collect links to published disclosures from Mindgard source page."""
    print(f"Scraping published disclosure links from: {source_url}")

    try:
        response = requests.get(source_url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching source page: {e}")
        return []

    soup = BeautifulSoup(response.content, "html.parser")

    links: list[str] = []
    for anchor in soup.select('a[href*="/disclosures/"]'):
        href = anchor.get("href", "")
        if not href:
            continue

        full_url = urljoin(source_url, href)
        if "/disclosures/" not in full_url:
            continue

        if full_url not in links:
            links.append(full_url)

    print(f"Found {len(links)} disclosure links")
    return links


def scrape_disclosure_to_report(disclosure_url: str) -> Optional[Report]:
    """Scrape a single Mindgard disclosure page and map it to a Report."""
    print(f"Scraping disclosure: {disclosure_url}")

    try:
        response = requests.get(disclosure_url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching disclosure page {disclosure_url}: {e}")
        return None

    soup = BeautifulSoup(response.content, "html.parser")
    field_cells = _extract_field_cells(soup)

    title_node = soup.select_one("div.feature-heading-text.title.disclosure")
    problem_title = (
        _normalize_whitespace(title_node.get_text(" ", strip=True))
        if title_node
        else ""
    )

    vendor_text = _field_text(field_cells, "Affected Vendor(s)")
    product_text = _field_text(field_cells, "Affected Product(s)")
    summary_text = _field_text(field_cells, "Summary")
    credit_text = _field_text(field_cells, "Credit")
    timeline_text = _field_text(field_cells, "Timeline")

    developers = _split_list_field(vendor_text)
    products = _split_list_field(product_text)

    affects = None
    if developers or products:
        affects = Affects(
            developer=developers,
            deployer=[],
            artifacts=[
                Artifact(type=ArtifactTypeEnum.system, name=product)
                for product in products
            ],
        )

    problemtype = None
    if problem_title:
        problemtype = Problemtype(
            classof=ClassEnum.third_party,
            description=LangValue(lang="eng", value=problem_title),
        )

    references: list[Reference] = []
    seen_urls: set[str] = set()

    def add_reference(url: str, label: str) -> None:
        normalized_url = urljoin(disclosure_url, url).strip()
        normalized_label = _normalize_whitespace(label) or normalized_url
        if not normalized_url or normalized_url in seen_urls:
            return
        seen_urls.add(normalized_url)
        references.append(
            Reference(label=normalized_label, url=normalized_url)
        )

    add_reference(disclosure_url, "Mindgard Disclosure")

    for ref_field in ("Blog Post", "References"):
        value_cell = field_cells.get(ref_field)
        if value_cell is None:
            continue

        anchors = value_cell.find_all("a", href=True)
        for anchor in anchors:
            add_reference(anchor["href"], anchor.get_text(" ", strip=True))

    reported_date = _extract_timeline_published_on(timeline_text)

    credit_entries: list[LangValue] = []
    if credit_text:
        credit_entries.append(LangValue(lang="eng", value=credit_text))
    credit_entries.append(LangValue(lang="eng", value="Mindgard"))

    report = Report(
        affects=affects,
        problemtype=problemtype,
        references=references or None,
        description=(
            LangValue(lang="eng", value=summary_text)
            if summary_text
            else None
        ),
        credit=credit_entries,
        reported_date=reported_date,
    )

    return report


def scrape_mindgard_disclosures(
    source_url: str, limit: Optional[int] = None
) -> list[Report]:
    """Scrape Mindgard published disclosures into Report objects."""
    links = scrape_published_disclosure_links(source_url)
    if limit is not None and limit > 0:
        links = links[:limit]

    reports: list[Report] = []
    for link in links:
        report = scrape_disclosure_to_report(link)
        if report is not None:
            reports.append(report)

    print(
        "Successfully mapped "
        f"{len(reports)} reports from {len(links)} disclosures"
    )
    return reports


def save_reports_to_jsonl(reports: list[Report], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as outfile:
        for report in reports:
            outfile.write(report.model_dump_json(exclude_none=True) + "\n")
    print(f"Saved {len(reports)} reports to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Scrape Mindgard published disclosures "
            "and convert to AVID Reports"
        )
    )
    parser.add_argument(
        "--source-url",
        type=str,
        default="https://mindgard.ai/learn/disclosures",
        help="Mindgard disclosures source page URL",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Output directory for JSONL file "
            "(default: avid-db/reports/review)"
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional max number of disclosures to process",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("Disclosure Scraper - Mindgard to AVID Report Converter")
    print("=" * 80)
    print()

    reports = scrape_mindgard_disclosures(args.source_url, limit=args.limit)
    if not reports:
        print("No reports were created. Exiting.")
        raise SystemExit(1)

    utc_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"mindgard_disclosure_digest_{utc_timestamp}.jsonl"
    script_dir = Path(__file__).parent
    default_output = (
        script_dir.parent.parent / "avid-db" / "reports" / "review" / filename
    )
    output_path = (
        args.output_dir / filename if args.output_dir else default_output
    )

    save_reports_to_jsonl(reports, output_path)

    print()
    print("=" * 80)
    print(f"Complete! Successfully processed {len(reports)} disclosures")
    print("Output file:")
    print(f"  - {output_path}")
    print("=" * 80)
