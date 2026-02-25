# URL Connector for AVID

A connector that scrapes web content and uses an AI agent (GPT-4o-mini) to create AVID (AI Vulnerability Database) reports automatically.

## Features

- **Web Scraping**: Extracts content from URLs using BeautifulSoup
- **AI-Powered Analysis**: Uses OpenAI's GPT-4o-mini to analyze content and extract structured vulnerability information
- **Automatic Report Generation**: Creates complete AVID reports with proper taxonomy mappings
- **Flexible Configuration**: Customizable model selection and API key management

## Installation

Install the required dependencies:

```bash
pip install openai beautifulsoup4 requests lxml
```

Or if using the project's pyproject.toml:

```bash
poetry install
```

## Setup

You need an OpenAI API key to use this connector. Set it as an environment variable:

```bash
export OPENAI_API_KEY='your-api-key-here'
```

Alternatively, you can pass it directly to the connector when creating an instance.

## Usage

### Basic Usage

```python
from avidtools.connectors.url import URLConnector

# Create connector
connector = URLConnector(model="gpt-4o-mini")

# Generate report from URL
url = "https://example.com/ai-vulnerability-article"
report = connector.create_report_from_url(url)

# Save report to file
report.save("report.json")
```

### With Custom API Key

```python
from avidtools.connectors.url import URLConnector

# Create connector with custom API key
connector = URLConnector(
    api_key="your-api-key-here",
    model="gpt-4o-mini"
)

# Generate report
report = connector.create_report_from_url(url)
```

### Using the Convenience Function

```python
from avidtools.connectors.url import fetch_and_convert

# One-liner to create a report
report = fetch_and_convert("https://example.com/article")
report.save("report.json")
```

## Example

Test the connector with the Aikido blog post about PromptPwnd:

```python
from avidtools.connectors.url import URLConnector

url = "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents"
connector = URLConnector(model="gpt-4o-mini")
report = connector.create_report_from_url(url)

print(f"Report ID: {report.metadata.report_id}")
print(f"Description: {report.description.value}")
report.save("promptpwnd_report.json")
```

## Running the Test Script

A test script is provided in `scripts/test_url_connector.py`:

```bash
# Set your API key
export OPENAI_API_KEY='your-api-key-here'

# Run the test
python scripts/test_url_connector.py
```

This will:
1. Scrape the Aikido blog post
2. Use GPT-4o-mini to analyze the content
3. Generate an AVID report
4. Display the report details
5. Save the report as `test_report.json`

## How It Works

1. **Web Scraping**: The connector fetches the URL and extracts the main text content, removing scripts, styles, and navigation elements.

2. **AI Analysis**: The scraped content is sent to GPT-4o-mini with a structured prompt that:
   - Describes the AVID report structure
   - Explains each field and its possible values
   - Asks the AI to extract relevant information from the content

3. **Report Construction**: The AI's JSON response is parsed and used to construct a proper `Report` object with all the appropriate datamodel components (Affects, Problemtype, Impact, etc.).

4. **Validation**: The Report object uses Pydantic models to ensure all data is properly typed and validated.

## Report Structure

The generated AVID report includes:

- **Report ID**: Unique identifier (AVID-YYYY-R-XXXX)
- **Metadata**: Report identification information
- **Affects**: Developers, deployers, and artifacts affected
- **Problemtype**: Classification of the vulnerability/issue
- **Description**: High-level description of the issue
- **Impact**: 
  - AVID taxonomy (risk domain, SEP view, lifecycle view)
  - ATLAS taxonomy (tactics and techniques)
- **References**: Links to sources
- **Reported Date**: Date of report creation

## Error Handling

The connector includes retry logic for AI response parsing. If the initial response cannot be parsed as valid JSON or doesn't match the expected structure, it will retry up to 2 times by default.

You can customize the retry behavior:

```python
report = connector.create_report_from_url(url, max_retries=5)
```

## Limitations

- Requires an active OpenAI API key with access to GPT-4o-mini
- Web scraping success depends on the target site's structure
- AI extraction quality depends on the clarity and completeness of the source content
- Some websites may block automated scraping

## Contributing

When adding new features or fixing bugs, please:
1. Update this README
2. Add tests to `tests/unit/connectors/test_url.py`
3. Ensure code follows the project's style guidelines
