"""
Demo of URL connector usage (requires OPENAI_API_KEY).

This script provides instructions on how to use the URL connector.
"""

import sys


def main():
    """Display usage instructions."""
    print("=" * 80)
    print("AVID URL Connector Demo")
    print("=" * 80)
    print()
    print("The URL connector scrapes web content and uses AI to create AVID reports.")
    print()
    print("Setup:")
    print("------")
    print("1. Install dependencies:")
    print("   pip install openai beautifulsoup4 requests lxml")
    print()
    print("2. Set your OpenAI API key:")
    print("   export OPENAI_API_KEY='your-api-key-here'")
    print()
    print("Usage Example:")
    print("--------------")
    print()
    print("from avidtools.connectors.url import URLConnector")
    print()
    print("# Create connector")
    print("connector = URLConnector(model='gpt-4o-mini')")
    print()
    print("# Generate report from URL")
    print("url = 'https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents'")
    print("report = connector.create_report_from_url(url)")
    print()
    print("# Save report")
    print("report.save('report.json')")
    print()
    print("=" * 80)
    print()
    print("To run the test script:")
    print("  python scripts/test_url_connector.py")
    print()
    print("For more information, see: docs/URL_CONNECTOR.md")
    print("=" * 80)


if __name__ == "__main__":
    main()
