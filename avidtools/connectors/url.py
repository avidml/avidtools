"""
URL connector for AVID that scrapes web content and uses an AI agent to create AVID reports.
"""

import os
import json
import re
from datetime import date
from typing import Any, Optional
from urllib.parse import urlparse
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
            title = (
                soup.title.string
                if soup.title and soup.title.string
                else ""
            )

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
        "report_id": "string (optional; omit for unpublished reports)"
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
            "value": "short title (required, concise, ideally <= 12 words)"
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

Please analyze this content and extract relevant information to create an AVID report. Return ONLY a valid JSON object with the following structure (all fields are optional unless explicitly noted):

{{
    "report_id": "string (optional; omit if unknown or unpublished)",
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
            "value": "short title (required, concise, ideally <= 12 words)"
    }}
  }},
    "description": {{
    "lang": "eng",
        "value": "full descriptive summary paragraph"
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
- problemtype.description.value MUST be a short title, not a paragraph. Summarize the actual issue concisely, do NOT mention the reporter, or that it's from a URL or article. You can mention the product as needed. Focus on the core vulnerability or issue.
- problemtype.type MUST be one of: Issue, Advisory, Measurement, Detection
- Type definitions (from AVID database):
    - Issue: qualitative evaluation based on a single sample or handful of samples
    - Advisory: qualitative evaluation based on multiple Incidents
    - Measurement: quantitative evaluation with associated data and metric
    - Detection: a Measurement deemed critical by a threshold or statistical test
- description.value should contain the detailed narrative description
- Credit guidance: include the research team/person and article author when available; include company only when a research team/person is not identified
- MUST include the source URL ({scraped_data['url']}) in references with an appropriate label
- If information is not available in the content, omit that field entirely
- Return ONLY the JSON object, no additional text or explanation
"""
        return prompt

    def _normalize_problemtype_title(
        self, parsed_data: dict[str, Any], scraped_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Ensure problemtype.description.value is a short title, not a long description."""
        problemtype = parsed_data.get("problemtype")
        if not isinstance(problemtype, dict):
            return parsed_data

        description_obj = problemtype.get("description")
        if not isinstance(description_obj, dict):
            return parsed_data

        current_title = description_obj.get("value")
        page_title = (scraped_data.get("title") or "").strip()

        if not isinstance(current_title, str) or not current_title.strip():
            if page_title:
                description_obj["value"] = page_title[:120].strip()
            return parsed_data

        normalized = " ".join(current_title.split())

        too_long = len(normalized) > 120 or len(normalized.split()) > 16
        if too_long and page_title:
            normalized = page_title

        normalized = re.split(r"[.!?]", normalized, maxsplit=1)[0].strip()
        if len(normalized) > 120:
            normalized = normalized[:117].rstrip() + "..."

        description_obj["value"] = normalized
        return parsed_data

    def _normalize_problemtype_type(
        self, parsed_data: dict[str, Any], scraped_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Ensure problemtype.type is always a valid TypeEnum value."""
        problemtype = parsed_data.get("problemtype")
        if not isinstance(problemtype, dict):
            parsed_data["problemtype"] = {
                "classof": ClassEnum.third_party.value,
                "type": TypeEnum.issue.value,
                "description": {"lang": "eng", "value": (scraped_data.get("title") or "Issue")[:120]},
            }
            return parsed_data

        raw_type = problemtype.get("type")
        normalized_raw_type = None
        if isinstance(raw_type, str) and raw_type.strip():
            mapping = {
                "issue": TypeEnum.issue.value,
                "advisory": TypeEnum.advisory.value,
                "measurement": TypeEnum.measurement.value,
                "detection": TypeEnum.detection.value,
            }
            normalized_raw_type = mapping.get(raw_type.strip().lower())

        classof = str(problemtype.get("classof") or "").lower()
        text = " ".join(
            [
                scraped_data.get("title") or "",
                (scraped_data.get("text") or "")[:5000],
            ]
        ).lower()
        url = str(scraped_data.get("url") or "").lower()

        if "cve entry" in classof or "advisory" in classof:
            inferred = TypeEnum.advisory.value
        elif any(k in text or k in url for k in ["benchmark", "evaluation", "measured", "metric", "score", "accuracy", "recall", "precision"]):
            inferred = TypeEnum.measurement.value
        elif any(k in text or k in url for k in ["detect", "detector", "detection", "flagged", "classifier"]):
            inferred = TypeEnum.detection.value
        elif any(k in text or k in url for k in ["cve-", "vulnerability", "vulnerable", "security bulletin", "advisory", "exploit", "rce", "xss", "csrf", "injection", "auth bypass", "data leak", "exposed", "critical vulnerability"]):
            inferred = TypeEnum.advisory.value
        else:
            inferred = TypeEnum.issue.value

        if normalized_raw_type == TypeEnum.issue.value and inferred == TypeEnum.advisory.value:
            problemtype["type"] = TypeEnum.advisory.value
        elif normalized_raw_type:
            problemtype["type"] = normalized_raw_type
        else:
            problemtype["type"] = inferred
        return parsed_data

    def _parse_ai_response(self, response_text: str) -> dict[str, Any]:
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
            parsed = json.loads(text)
            if not isinstance(parsed, dict):
                raise ValueError(
                    "AI response JSON must be an object at top level"
                )
            return parsed
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
                lifecycle_view=[
                    LifecycleEnum(stage)
                    for stage in avid_data["lifecycle_view"]
                ],
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

        # Build credit
        credit = None
        if "credit" in data and isinstance(data["credit"], list):
            credit = [LangValue(**entry) for entry in data["credit"]]

        # Build the report
        report = Report(
            metadata=metadata,
            affects=affects,
            problemtype=problemtype,
            description=description,
            impact=impact,
            references=references,
            credit=credit,
            reported_date=reported_date,
        )

        return report

    def _infer_credit_from_url(self, url: str) -> str:
        """Infer a default credit string from the source URL hostname."""
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lower().strip()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname or url

    def _normalized_hostname(self, url: str) -> str:
        hostname = (urlparse(url).hostname or "").lower().strip()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname

    def _meta_content_as_text(self, tag: Any) -> Optional[str]:
        """Return meta content as text when available and string-like."""
        raw_content = tag.get("content") if tag is not None else None
        if isinstance(raw_content, str):
            content = raw_content.strip()
            return content or None
        return None

    def _extract_author_person(self, scraped_data: dict[str, Any]) -> Optional[str]:
        """Extract an article author person from JSON-LD, metadata, or byline text."""
        try:
            soup = BeautifulSoup(scraped_data.get("html", ""), "html.parser")
        except Exception:
            soup = None

        candidates: list[str] = []

        if soup is not None:
            for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
                raw = (script.string or script.get_text() or "").strip()
                if not raw:
                    continue
                try:
                    payload = json.loads(raw)
                except Exception:
                    continue

                def collect_authors(node: Any) -> None:
                    if isinstance(node, dict):
                        author = node.get("author")
                        if isinstance(author, dict):
                            name = author.get("name")
                            if isinstance(name, str):
                                candidates.append(name)
                        elif isinstance(author, list):
                            for item in author:
                                if isinstance(item, dict) and isinstance(item.get("name"), str):
                                    candidates.append(item["name"])
                                elif isinstance(item, str):
                                    candidates.append(item)
                        elif isinstance(author, str):
                            candidates.append(author)

                        for value in node.values():
                            collect_authors(value)
                    elif isinstance(node, list):
                        for item in node:
                            collect_authors(item)

                collect_authors(payload)

            meta_keys = [
                ("name", "author"),
                ("property", "article:author"),
                ("name", "parsely-author"),
                ("name", "dc.creator"),
                ("name", "twitter:creator"),
            ]
            for attr, key in meta_keys:
                tag = soup.find("meta", attrs={attr: key})
                content = self._meta_content_as_text(tag)
                if content:
                    candidates.append(content)

            byline_nodes = soup.select('[class*="author" i], [class*="byline" i], [rel="author"]')
            for node in byline_nodes[:8]:
                text = node.get_text(" ", strip=True)
                if text:
                    candidates.append(text)

        text_snippet = (scraped_data.get("text") or "")[:12000]
        byline_patterns = [
            r"\bBy\s+([A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){1,3})\b",
            r"\bWritten\s+by\s+([A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){1,3})\b",
            r"\bAuthor\s*:?\s*([A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){1,3})\b",
        ]
        for pattern in byline_patterns:
            for match in re.finditer(pattern, text_snippet):
                candidates.append(match.group(1).strip())

        for candidate in candidates:
            value = candidate.strip(" @")
            value = re.sub(r"^(by|written by|author:)\s+", "", value, flags=re.IGNORECASE).strip()
            value = " ".join(value.split())
            if not value:
                continue
            if self._looks_like_person_name(value):
                return value
        return None

    def _extract_research_entity(self, scraped_data: dict[str, Any], url: str) -> Optional[str]:
        """Extract research team/person entity from page metadata or article text."""
        hostname = self._normalized_hostname(url)
        text = "\n".join(
            [
                scraped_data.get("title", "") or "",
                (scraped_data.get("text", "") or "")[:12000],
            ]
        )
        patterns = [
            r"\b([A-Z][A-Za-z0-9&'\-]+(?:\s+[A-Z][A-Za-z0-9&'\-]+){0,3}\s+Research)\b",
            r"\b([A-Z][A-Za-z0-9&'\-]+(?:\s+[A-Z][A-Za-z0-9&'\-]+){0,3}\s+Security\s+Team)\b",
            r"\b([A-Z][A-Za-z0-9&'\-]+(?:\s+[A-Z][A-Za-z0-9&'\-]+){0,3}\s+Labs)\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                found = match.group(1).strip()
                if hostname == "wiz.io" and "wiz" in found.lower():
                    return "Wiz Research"
                return found

        if hostname == "wiz.io":
            return "Wiz Research"

        return None

    def _extract_company_credit(self, scraped_data: dict[str, Any], url: str) -> str:
        """Extract organization/company name from page metadata, with hostname fallback."""
        try:
            soup = BeautifulSoup(scraped_data.get("html", ""), "html.parser")
        except Exception:
            soup = None

        if soup is not None:
            meta_keys = [
                ("property", "og:site_name"),
                ("name", "application-name"),
                ("name", "publisher"),
            ]
            for attr, key in meta_keys:
                tag = soup.find("meta", attrs={attr: key})
                content = self._meta_content_as_text(tag)
                if content:
                    return content

        return self._infer_credit_from_url(url)

    def _looks_like_person_name(self, value: str) -> bool:
        """Heuristic to identify person-name style values."""
        text = value.strip()
        lowered = text.lower()
        if "." in lowered:
            return False
        if any(
            token in lowered
            for token in [
                "research",
                "team",
                "security",
                "labs",
                "inc",
                "corp",
                "company",
                "browser",
                "blog",
                "media",
            ]
        ):
            return False
        if not re.match(r"^[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){1,3}$", text):
            return False
        parts = text.split()
        return 2 <= len(parts) <= 4

    def _looks_like_research_entity(self, value: str) -> bool:
        """Heuristic to identify team/person research entity values."""
        lowered = value.strip().lower()
        return any(
            token in lowered
            for token in [
                "research",
                "team",
                "security",
                "labs",
            ]
        )

    def _apply_credit_defaults(self, report: Report, scraped_data: dict[str, Any], url: str) -> None:
        """Assign credits using policy:
        1) company blog
        2) research team/person (if present, suppress company)
        3) article author person
        """
        existing_values = [
            entry.value.strip()
            for entry in (report.credit or [])
            if entry.value and entry.value.strip()
        ]

        research_entity = self._extract_research_entity(scraped_data, url)
        if not research_entity:
            for value in existing_values:
                if self._looks_like_research_entity(value):
                    research_entity = value
                    break

        author_person = self._extract_author_person(scraped_data)
        if not author_person:
            for value in existing_values:
                if self._looks_like_person_name(value) and value != research_entity:
                    author_person = value
                    break

        company_blog = self._extract_company_credit(scraped_data, url)

        ordered: list[str] = []
        if research_entity:
            ordered.append(research_entity)
        if author_person and author_person not in ordered:
            ordered.append(author_person)
        if not research_entity and company_blog and company_blog not in ordered:
            ordered.append(company_blog)

        report.credit = [LangValue(lang="eng", value=value) for value in ordered]

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

                ai_response = response.choices[0].message.content or ""
                print(f"AI response received ({len(ai_response)} characters)")

                # Step 4: Parse AI response
                parsed_data = self._parse_ai_response(ai_response)
                parsed_data = self._normalize_problemtype_title(
                    parsed_data, scraped_data
                )
                parsed_data = self._normalize_problemtype_type(
                    parsed_data, scraped_data
                )
                print("Successfully parsed AI response")

                # Step 5: Build Report object
                report = self._build_report_from_json(parsed_data)
                self._apply_credit_defaults(report, scraped_data, url)
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

        raise RuntimeError("Failed to create report: exhausted retries")


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
