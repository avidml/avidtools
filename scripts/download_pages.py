#!/usr/bin/env python3
"""Download all disclosure pages from 0din.ai page 1 for offline testing."""

import httpx
from pathlib import Path
from bs4 import BeautifulSoup

def main():
    # Create output directory
    output_dir = Path(__file__).parent / "scraped_html"
    output_dir.mkdir(exist_ok=True)
    
    # Get page 1 to extract UUIDs
    print("Fetching page 1 to get UUIDs...")
    page_url = "https://0din.ai/disclosures?page=1"
    response = httpx.get(page_url, timeout=30.0)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extract UUIDs
    links = soup.find_all('a', {'data-turbo-frame': '_top'})
    uuids = set()
    for link in links:
        href = link.get('href', '')
        if '/disclosures/' in href and href.count('/') == 2:
            uuid = href.split('/')[-1]
            uuids.add(uuid)
    
    print(f"Found {len(uuids)} UUIDs")
    
    # Download each disclosure page
    for i, uuid in enumerate(sorted(uuids), 1):
        url = f"https://0din.ai/disclosures/{uuid}"
        output_file = output_dir / f"{uuid}.html"
        
        if output_file.exists():
            print(f"[{i}/{len(uuids)}] Skipping {uuid} (already exists)")
            continue
        
        print(f"[{i}/{len(uuids)}] Downloading {uuid}...")
        try:
            response = httpx.get(url, timeout=30.0)
            output_file.write_text(response.text, encoding='utf-8')
            print(f"  ✓ Saved to {output_file}")
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    print(f"\nComplete! Downloaded pages to {output_dir}")

if __name__ == "__main__":
    main()
