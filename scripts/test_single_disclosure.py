"""
Test script to scrape a single 0din.ai disclosure.

This script tests the scraping of a specific disclosure page without 
processing multiple pages or using pagination.
"""

import os
import sys
from pathlib import Path

# Import AVID datamodels (sys.path modification required)
sys.path.insert(0, str(Path(__file__).parent.parent))

from avidtools.connectors.url import URLConnector
from avidtools.datamodels.components import (
    Impact,
    OdinTaxonomy,
)
from odin import extract_odin_metadata_from_html, create_impact


def test_single_disclosure(url: str, api_key: str):
    """
    Test scraping a single disclosure.
    
    Args:
        url: The disclosure URL to test
        api_key: OpenAI API key
    """
    print("=" * 80)
    print(f"Testing single disclosure scrape: {url}")
    print("=" * 80)
    print()
    
    # Step 1: Scrape the page once
    print("Step 1: Scraping page content...")
    print("-" * 80)
    connector = URLConnector(api_key=api_key)
    scraped_data = connector.scrape_url(url)
    print(f"✓ Scraped content: {len(scraped_data['text'])} characters")
    print()
    
    # Step 2: Extract 0DIN metadata
    print("Step 2: Extracting 0DIN metadata...")
    print("-" * 80)
    odin_metadata = extract_odin_metadata_from_html(
        scraped_data['html'], 
        scraped_data['text']
    )
    print(f"Social Impact Score: {odin_metadata['social_impact_score']}")
    print(f"Jailbreak Taxonomy: {odin_metadata['jailbreak_taxonomy']}")
    print()
    
    # Step 3: Create report using AI
    print("Step 3: Creating base report with AI...")
    print("-" * 80)
    prompt = connector._create_ai_prompt(scraped_data)
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
    parsed_data = connector._parse_ai_response(ai_response)
    report = connector._build_report_from_json(parsed_data)
    print(f"✓ Created report: {report.metadata.report_id if report.metadata else 'N/A'}")
    print()
    
    # Step 4: Create and populate Impact field
    print("Step 4: Creating Impact with 0DIN taxonomy...")
    print("-" * 80)
    impact = create_impact(odin_metadata)
    report.impact = impact
    print(f"✓ Impact created with 0DIN taxonomy")
    print()
    
    # Step 4: Display result
    print("=" * 80)
    print("Final Report Summary:")
    print("=" * 80)
    print(f"Report ID: {report.metadata.report_id if report.metadata else 'N/A'}")
    print(f"Description: {report.description.value[:100] if report.description else 'N/A'}...")
    if report.impact:
        if report.impact.odin:
            print(f"0DIN Social Impact: {report.impact.odin.SocialImpactScore}")
            print(f"0DIN Jailbreak Taxonomy: {report.impact.odin.JailbreakTaxonomy}")
    print()
    
    # Step 5: Save to file
    output_file = Path(__file__).parent / "test_disclosure_output.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json_str = report.model_dump_json(exclude_none=True, indent=2)
        f.write(json_str)
    
    print(f"✓ Saved report to: {output_file}")
    print("=" * 80)


if __name__ == "__main__":
    # Test URL
    test_url = "https://0din.ai/disclosures/2235061a-e292-474f-ac38-a510b80b5ef0"
    
    # Get API key
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        sys.exit(1)
    
    test_single_disclosure(test_url, api_key)
