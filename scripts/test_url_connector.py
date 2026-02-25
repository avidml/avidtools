#!/usr/bin/env python3
"""
Test script for URL connector.

Tests the URL connector by scraping the Aikido blog post and creating an AVID report.
"""

import os
import sys
from pathlib import Path

# Load .env file BEFORE importing anything else
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                # Remove quotes if present
                value = value.strip().strip('"').strip("'")
                os.environ[key] = value

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from avidtools.connectors.url import URLConnector


def main():
    """Main test function."""
    
    # Check if API key is set
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY not found in environment or .env file")
        print("Please set it with: export OPENAI_API_KEY='your-api-key'")
        print("Or add it to .env file in the repo root")
        sys.exit(1)

    # Test URL
    test_url = "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents"
    
    print("=" * 80)
    print("Testing URL Connector for AVID")
    print("=" * 80)
    print(f"URL: {test_url}")
    print(f"Model: gpt-4o-mini")
    print("=" * 80)
    print()

    try:
        # Create connector and generate report
        connector = URLConnector(api_key=api_key, model="gpt-4o-mini")
        report = connector.create_report_from_url(test_url)

        print()
        print("=" * 80)
        print("REPORT GENERATED SUCCESSFULLY")
        print("=" * 80)
        print()

        # Display report details
        print("Report Details:")
        print("-" * 80)
        
        if report.metadata:
            print(f"Report ID: {report.metadata.report_id}")
        
        if report.reported_date:
            print(f"Reported Date: {report.reported_date}")
        
        if report.description:
            print(f"\nDescription ({report.description.lang}):")
            print(f"  {report.description.value}")
        
        if report.affects:
            print(f"\nAffects:")
            print(f"  Developers: {', '.join(report.affects.developer)}")
            print(f"  Deployers: {', '.join(report.affects.deployer)}")
            if report.affects.artifacts:
                print(f"  Artifacts:")
                for artifact in report.affects.artifacts:
                    print(f"    - {artifact.type}: {artifact.name}")
        
        if report.problemtype:
            print(f"\nProblem Type:")
            print(f"  Class: {report.problemtype.classof}")
            if report.problemtype.type:
                print(f"  Type: {report.problemtype.type}")
            print(f"  Description: {report.problemtype.description.value}")
        
        if report.impact:
            print(f"\nImpact:")
            print(f"  AVID Taxonomy:")
            print(f"    Risk Domains: {', '.join(report.impact.avid.risk_domain)}")
            print(f"    SEP View: {', '.join([s.value for s in report.impact.avid.sep_view])}")
            print(f"    Lifecycle View: {', '.join([l.value for l in report.impact.avid.lifecycle_view])}")
            print(f"    Taxonomy Version: {report.impact.avid.taxonomy_version}")
            
            if report.impact.atlas:
                print(f"  ATLAS Taxonomy:")
                for atlas in report.impact.atlas:
                    if atlas.tactic:
                        print(f"    Tactic: {atlas.tactic}")
                    if atlas.technique:
                        print(f"    Technique: {atlas.technique}")
        
        if report.references:
            print(f"\nReferences:")
            for ref in report.references:
                print(f"  - {ref.label}: {ref.url}")
        
        print()
        print("=" * 80)
        
        # Save report to file
        output_file = "test_report.json"
        report.save(output_file)
        print(f"Report saved to: {output_file}")
        print("=" * 80)
        
        # Display JSON preview
        print()
        print("JSON Preview (first 1000 chars):")
        print("-" * 80)
        with open(output_file, "r") as f:
            json_content = f.read()
            print(json_content[:1000])
            if len(json_content) > 1000:
                print("...")
        print()
        
        return 0

    except Exception as e:
        print()
        print("=" * 80)
        print("ERROR")
        print("=" * 80)
        print(f"Failed to create report: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
