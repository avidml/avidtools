"""
Example usage of the URL connector for AVID.

This script demonstrates how to use the URLConnector to scrape a URL
and create an AVID report using AI.
"""

import os
from avidtools.connectors.url import URLConnector

# Set your OpenAI API key
# Either set it as an environment variable:
#   export OPENAI_API_KEY='your-api-key-here'
# Or pass it directly to the connector:
#   connector = URLConnector(api_key='your-api-key-here')

# Example URL
url = "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents"

# Create connector (will use OPENAI_API_KEY from environment)
connector = URLConnector(model="gpt-4o-mini")

# Generate report from URL
report = connector.create_report_from_url(url)

# Save report to file
report.save("example_report.json")

print(f"Report created with ID: {report.metadata.report_id}")
print(f"Report saved to: example_report.json")
