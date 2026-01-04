"""
URL connector for AVID that scrapes web content and uses an AI agent to create AVID reports.
"""

import os
import json
from datetime import date
from typing import Optional
import requests
from bs4 import BeautifulSoup
from openai import OpenAI, AsyncOpenAI

from ..datamodels.report import Report, ReportMetadata
from ..datamodels.components import (
    Affects,
    Artifact,
    ArtifactTypeEnum,
    AtlasTaxonomy,
    AvidTaxonomy,
    ClassEnum,
    Impact,
    LangValue,
    Problemtype,
    Reference,
    TypeEnum,
    SepEnum,
    LifecycleEnum,
)


class URLConnector:
    """Connector to scrape URLs and create AVID reports using AI."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o-mini"):
        """
        Initialize the URL connector.

        Parameters
        ----------
        api_key : str, optional
            OpenAI API key. If not provided, will use OPENAI_API_KEY environment variable.
        model : str, default="gpt-4o-mini"
            The OpenAI model to use for report generation.
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "OpenAI API key must be provided either as parameter or "
                "through OPENAI_API_KEY environment variable"
            )
        self.model = model
        self.client = OpenAI(api_key=self.api_key)
        self.async_client = AsyncOpenAI(api_key=self.api_key)

    def scrape_url(self, url: str) -> dict:
        """
        Scrape content from a URL.

        Parameters
        ----------
        url : str
            The URL to scrape.

        Returns
        -------
        dict
            Dictionary containing scraped content with keys: url, title, text, html.
        """
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, "html.parser")

            # Remove script and style elements
            for script in soup(["script", "style", "nav", "footer", "header"]):
                script.decompose()

            # Get title
            title = soup.title.string if soup.title else ""

            # Get main text content
            text = soup.get_text(separator="\n", strip=True)

            # Clean up whitespace
            lines = (line.strip() for line in text.splitlines())
            text = "\n".join(line for line in lines if line)

            return {
                "url": url,
                "title": title.strip(),
                "text": text,
                "html": str(soup)[:50000],  # Limit HTML size
            }

        except Exception as e:
            raise RuntimeError(f"Failed to scrape URL {url}: {str(e)}")

    def _create_ai_prompt(self, scraped_data: dict) -> str:
        """
        Create a prompt for the AI agent to extract AVID report information.

        Parameters
        ----------
        scraped_data : dict
            The scraped content from the URL.

        Returns
        -------
        str
            The formatted prompt for the AI agent.
        """
        prompt = f"""You are an AI security expert tasked with analyzing web content about AI/ML vulnerabilities, incidents, or security issues and extracting structured information to create an AVID (AI Vulnerability Database) report.

The AVID Report follows this exact schema:

```json
{{
  "data_type": "AVID",
  "data_version": "string (optional)",
  "metadata": {{
    "report_id": "string (required, format: AVID-YYYY-R-XXXX)"
  }},
  "affects": {{
    "developer": ["list of developer organizations of the model/system involved"],
    "deployer": ["list of deployer organizations"],
    "artifacts": [
      {{
        "type": "Model|Dataset|System (required)",
        "name": "artifact name (required)"
      }}
    ]
  }},
  "problemtype": {{
    "classof": "AIID Incident|ATLAS Case Study|CVE Entry|LLM Evaluation|Third-party Report|Undefined (required, default: Third-party Report)",
    "type": "Issue|Advisory|Measurement|Detection (optional)",
    "description": {{
      "lang": "eng",
      "value": "description text"
    }}
  }},
  "metrics": [
    {{
      "name": "metric name",
      "detection_method": {{
        "type": "Significance Test|Static Threshold",
        "name": "method name"
      }},
      "results": {{}} or []
    }}
  ],
  "references": [
    {{
      "label": "reference label",
      "url": "reference url (MUST include source URL)"
    }}
  ],
  "description": {{
    "lang": "eng",
    "value": "high-level description"
  }},
  "impact": {{
    "avid": {{
      "risk_domain": ["list of risk domains"],
      "sep_view": ["list of SEP taxonomy IDs"],
      "lifecycle_view": ["list of lifecycle stage IDs"],
      "taxonomy_version": "version string"
    }},
    "atlas": [
      {{
        "tactic": "tactic name",
        "technique": "technique name",
        "subtechnique": "subtechnique name"
      }}
    ]
  }},
  "credit": [
    {{
      "lang": "eng",
      "value": "credited person or organization"
    }}
  ],
  "reported_date": "YYYY-MM-DD"
}}
```

All fields except those marked as required are optional. Omit fields if information is not available.

Here is the web content to analyze:

URL: {scraped_data['url']}
Title: {scraped_data['title']}

Content:
{scraped_data['text'][:15000]}

Please analyze this content and extract relevant information to create an AVID report. Return ONLY a valid JSON object with the following structure (all fields are optional except those marked as required):

{{
  "report_id": "string (required)",
  "affects": {{
    "developer": ["list of developers"],
    "deployer": ["list of deployers"],
    "artifacts": [
      {{
        "type": "Model|Dataset|System",
        "name": "artifact name"
      }}
    ]
  }},
  "problemtype": {{
    "classof": "Third-party Report",
    "type": "Issue|Advisory|Measurement|Detection",
    "description": {{
      "lang": "eng",
      "value": "description text"
    }}
  }},
  "description": {{
    "lang": "eng",
    "value": "high-level description"
  }},
  "references": [
    {{
      "label": "reference label",
      "url": "reference url"
    }}
  ],
  "reported_date": "{date.today().isoformat()}"
}}

Important guidelines:
- Be specific and accurate
- Extract actual names, organizations, and technical details from the content
- For the report_id, use format AVID-{date.today().year}-R-XXXX where XXXX is a random 4-digit number
- MUST include the source URL ({scraped_data['url']}) in references with an appropriate label
- If information is not available in the content, omit that field entirely (except report_id which is required)
- Return ONLY the JSON object, no additional text or explanation
"""
        return prompt

    def _parse_ai_response(self, response_text: str) -> dict:
        """
        Parse the AI response and extract JSON.

        Parameters
        ----------
        response_text : str
            The response text from the AI.

        Returns
        -------
        dict
            Parsed JSON data.
        """
        # Try to extract JSON from the response
        text = response_text.strip()

        # Remove markdown code blocks if present
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first and last lines if they're markdown delimiters
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse AI response as JSON: {str(e)}\nResponse: {text}")

    def _build_report_from_json(self, data: dict) -> Report:
        """
        Build a Report object from parsed JSON data.

        Parameters
        ----------
        data : dict
            The parsed JSON data from the AI.

        Returns
        -------
        Report
            The constructed AVID Report object.
        """
        # Build metadata
        metadata = None
        if "report_id" in data:
            metadata = ReportMetadata(report_id=data["report_id"])

        # Build affects
        affects = None
        if "affects" in data:
            affects_data = data["affects"]
            artifacts = []
            if "artifacts" in affects_data:
                for artifact_data in affects_data["artifacts"]:
                    artifact_type = ArtifactTypeEnum(artifact_data["type"])
                    artifact_name = artifact_data["name"]
                    
                    # Reclassify models as systems based on provider-specific rules
                    if artifact_type == ArtifactTypeEnum.model:
                        artifact_name_lower = artifact_name.lower()
                        
                        # OpenAI: All LLMs are systems
                        if "openai" in artifact_name_lower:
                            artifact_type = ArtifactTypeEnum.system
                        
                        # Anthropic: All LLMs are systems
                        elif "anthropic" in artifact_name_lower:
                            artifact_type = ArtifactTypeEnum.system
                        
                        # Google: Gemini series are systems, Gemma are models
                        elif "google" in artifact_name_lower or "gemini" in artifact_name_lower:
                            if "gemini" in artifact_name_lower:
                                artifact_type = ArtifactTypeEnum.system
                            # gemma remains as model
                        
                        # Cohere: All except Command R and Aya are systems
                        elif "cohere" in artifact_name_lower:
                            if "command r" not in artifact_name_lower and "aya" not in artifact_name_lower:
                                artifact_type = ArtifactTypeEnum.system
                        
                        # Mistral: Large, Medium, Moderation, Embed are systems
                        elif "mistral" in artifact_name_lower:
                            if any(variant in artifact_name_lower for variant in ["large", "medium", "moderation", "embed"]):
                                artifact_type = ArtifactTypeEnum.system
                        
                        # Alibaba: Qwen Max and Turbo are systems
                        elif "alibaba" in artifact_name_lower or "qwen" in artifact_name_lower:
                            if "qwen max" in artifact_name_lower or "qwen turbo" in artifact_name_lower:
                                artifact_type = ArtifactTypeEnum.system
                        
                        # Meta, Twitter/X, Mozilla remain as systems (closed APIs)
                        elif any(provider in artifact_name_lower for provider in ["twitter", "grok"]):
                            artifact_type = ArtifactTypeEnum.system
                    
                    artifacts.append(
                        Artifact(
                            type=artifact_type,
                            name=artifact_name,
                        )
                    )
            affects = Affects(
                developer=affects_data.get("developer", []),
                deployer=affects_data.get("deployer", []),
                artifacts=artifacts,
            )

        # Build problemtype
        problemtype = None
        if "problemtype" in data:
            pt_data = data["problemtype"]
            problemtype = Problemtype(
                classof=ClassEnum(pt_data["classof"]),
                type=TypeEnum(pt_data["type"]) if "type" in pt_data else None,
                description=LangValue(**pt_data["description"]),
            )

        # Build description
        description = None
        if "description" in data:
            description = LangValue(**data["description"])

        # Build impact
        impact = None
        if "impact" in data:
            impact_data = data["impact"]
            
            # Build AVID taxonomy
            avid_data = impact_data["avid"]
            avid_taxonomy = AvidTaxonomy(
                risk_domain=avid_data["risk_domain"],
                sep_view=[SepEnum(s) for s in avid_data["sep_view"]],
                lifecycle_view=[LifecycleEnum(l) for l in avid_data["lifecycle_view"]],
                taxonomy_version=avid_data["taxonomy_version"],
            )

            # Build ATLAS taxonomy if present
            atlas_taxonomy = None
            if "atlas" in impact_data:
                atlas_taxonomy = [
                    AtlasTaxonomy(**atlas_item)
                    for atlas_item in impact_data["atlas"]
                ]

            impact = Impact(avid=avid_taxonomy, atlas=atlas_taxonomy)

        # Build references
        references = None
        if "references" in data:
            references = [Reference(**ref) for ref in data["references"]]

        # Parse reported_date
        reported_date = None
        if "reported_date" in data:
            date_str = data["reported_date"]
            reported_date = date.fromisoformat(date_str)

        # Build the report
        report = Report(
            metadata=metadata,
            affects=affects,
            problemtype=problemtype,
            description=description,
            impact=impact,
            references=references,
            reported_date=reported_date,
        )

        return report

    def create_report_from_url(self, url: str, max_retries: int = 2) -> Report:
        """
        Scrape a URL and create an AVID report using AI.

        Parameters
        ----------
        url : str
            The URL to scrape and analyze.
        max_retries : int, default=2
            Maximum number of retries if AI response parsing fails.

        Returns
        -------
        Report
            The generated AVID Report object.
        """
        # Step 1: Scrape the URL
        print(f"Scraping URL: {url}")
        scraped_data = self.scrape_url(url)
        print(f"Scraped content: {len(scraped_data['text'])} characters")

        # Step 2: Create prompt for AI
        prompt = self._create_ai_prompt(scraped_data)

        # Step 3: Call AI agent
        print(f"Calling AI agent ({self.model})...")
        for attempt in range(max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
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
                print(f"AI response received ({len(ai_response)} characters)")

                # Step 4: Parse AI response
                parsed_data = self._parse_ai_response(ai_response)
                print("Successfully parsed AI response")

                # Step 5: Build Report object
                report = self._build_report_from_json(parsed_data)
                print(f"Created AVID report: {report.metadata.report_id if report.metadata else 'N/A'}")

                return report

            except (ValueError, json.JSONDecodeError) as e:
                if attempt < max_retries:
                    print(f"Attempt {attempt + 1} failed: {str(e)}. Retrying...")
                    continue
                else:
                    raise RuntimeError(
                        f"Failed to create report after {max_retries + 1} attempts: {str(e)}"
                    )
            except Exception as e:
                raise RuntimeError(f"Error creating report: {str(e)}")


def fetch_and_convert(url: str, api_key: Optional[str] = None, model: str = "gpt-4o-mini") -> Report:
    """
    Convenience function to scrape a URL and create an AVID report.

    Parameters
    ----------
    url : str
        The URL to scrape and analyze.
    api_key : str, optional
        OpenAI API key. If not provided, will use OPENAI_API_KEY environment variable.
    model : str, default="gpt-4o-mini"
        The OpenAI model to use for report generation.

    Returns
    -------
    Report
        The generated AVID Report object.
    """
    connector = URLConnector(api_key=api_key, model=model)
    return connector.create_report_from_url(url)
