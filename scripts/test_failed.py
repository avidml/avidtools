#!/usr/bin/env python3
"""Test the 5 failed disclosures individually to see error details."""

import os
import sys
import asyncio
import aiohttp
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from avidtools.connectors.url import URLConnector
from scripts.odin import scrape_url_async, extract_odin_metadata_from_html, create_impact

failed_uuids = [
    "8c6847ec-598f-4ba7-8d6f-2878f8c7aa41",
    "b18a7c49-7ad1-4db0-9993-3ecae165b3f4",
    "fd1db055-b87b-4400-ad87-6608b13bcbed",
    "cf0dc79f-3f59-4c65-a0c6-ba16855e466f",
    "4d590568-3622-41ae-b91a-eae8b5a4382e",
]

async def test_single(uuid):
    print(f"\n{'='*80}")
    print(f"Testing: {uuid}")
    print('='*80)
    
    url = f"https://0din.ai/disclosures/{uuid}"
    
    try:
        # Test scraping
        async with aiohttp.ClientSession() as session:
            scraped_data = await scrape_url_async(session, url)
            print(f"✓ Scraped: {len(scraped_data['text'])} characters")
            
            # Test metadata extraction
            metadata = extract_odin_metadata_from_html(scraped_data['html'], scraped_data['text'])
            print(f"✓ Metadata: {metadata['social_impact_score']}, {len(metadata['jailbreak_taxonomy'])} terms")
            
            # Test impact creation
            impact = create_impact(metadata)
            print(f"✓ Impact created")
            
            # Test AI call
            api_key = os.environ.get("OPENAI_API_KEY")
            if api_key:
                connector = URLConnector(api_key=api_key, model="gpt-4o-mini")
                prompt = connector._create_ai_prompt(scraped_data)
                print(f"✓ Prompt created: {len(prompt)} characters")
                
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
                print(f"✓ AI response: {len(ai_response)} characters")
                
                parsed_data = connector._parse_ai_response(ai_response)
                print(f"✓ Parsed successfully")
                
                report = connector._build_report_from_json(parsed_data)
                report.impact = impact
                print(f"✓ Report created: {report.metadata.report_id}")
            else:
                print("⚠ No API key - skipping AI test")
                
    except Exception as e:
        print(f"✗ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

async def main():
    for uuid in failed_uuids:
        await test_single(uuid)

if __name__ == "__main__":
    asyncio.run(main())
