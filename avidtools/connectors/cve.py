"""Connector utilities for importing and converting CVEs."""

import asyncio
from datetime import date
from pathlib import Path
from typing import Any, Optional

import requests

from ..datamodels.report import Report
from ..datamodels.vulnerability import Vulnerability
from ..datamodels.components import (
    Affects,
    AvidTaxonomy,
    Artifact,
    ArtifactTypeEnum,
    CVSSScores,
    CWETaxonomy,
    ClassEnum,
    Impact,
    LangValue,
    Problemtype,
    Reference,
    SepEnum,
    TypeEnum,
    LifecycleEnum,
)


def import_cve(cve_id):
    """Import a CVE JSON record from the MITRE CVE API.

    Parameters
    ----------
    cve_id : str
        Identifier of the CVE to be imported. Has the format CVE-2XXX-XXXXX

    Returns
    --------
    cve: dict
        JSON object containing CVE information.
    """
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    headers = {
        "Accept": "application/json",
        "User-Agent": "avidtools-cve-connector/0.1",
    }
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()


def _parse_date(date_str: Optional[str]) -> Optional[date]:
    if not date_str:
        return None
    try:
        return date.fromisoformat(date_str.split("T")[0])
    except (ValueError, TypeError, AttributeError):
        return None


def extract_cve_details(cve: dict[str, Any]) -> dict[str, Any]:
    """Extract normalized CVE details from a MITRE CVE JSON object."""
    cve_id = cve.get("cveMetadata", {}).get("cveId")
    containers = cve.get("containers", {})
    cna = containers.get("cna", {})

    details: dict[str, Any] = {
        "cve_id": cve_id,
        "url": (
            f"https://www.cve.org/CVERecord?id={cve_id}"
            if cve_id
            else None
        ),
        "title": None,
        "description": None,
        "published_date": cve.get("cveMetadata", {}).get("datePublished"),
        "last_modified_date": cve.get("cveMetadata", {}).get("dateUpdated"),
        "references": [],
        "affected_products": [],
        "source": cve.get("cveMetadata", {}).get("assignerOrgId")
        or cna.get("providerMetadata", {}).get("orgId"),
        "cvss_data": None,
        "cwe_data": [],
    }

    title = cna.get("title")
    if isinstance(title, str):
        details["title"] = title.strip()

    descriptions = cna.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            details["description"] = desc.get("value", "").strip()
            break
    if not details["description"] and descriptions:
        details["description"] = descriptions[0].get("value", "").strip()

    references = cna.get("references", [])
    for ref in references:
        ref_url = ref.get("url")
        if ref_url:
            details["references"].append(ref_url)

    affected = cna.get("affected", [])
    for aff in affected:
        vendor = aff.get("vendor")
        product = aff.get("product")
        if vendor or product:
            details["affected_products"].append(
                {
                    "vendor": vendor or "Unknown",
                    "product": product or "Unknown",
                }
            )

    metrics = cna.get("metrics", [])
    for metric in metrics:
        # Check for CVSS versions in priority order (newest first)
        if "cvssV4_0" in metric:
            details["cvss_data"] = metric["cvssV4_0"]
            break
        if "cvssV3_1" in metric:
            details["cvss_data"] = metric["cvssV3_1"]
            break
        if "cvssV3_0" in metric:
            details["cvss_data"] = metric["cvssV3_0"]
            break

    problem_types = cna.get("problemTypes", [])
    for pt in problem_types:
        for desc in pt.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id:
                details["cwe_data"].append(
                    {
                        "cweId": cwe_id,
                        "description": desc.get("description", ""),
                        "lang": desc.get("lang", "en"),
                    }
                )

    return details


def _create_description(cve_details: dict[str, Any]) -> Optional[LangValue]:
    description = cve_details.get("description")
    if description:
        return LangValue(lang="eng", value=description)
    return None


def _create_references(cve_details: dict[str, Any]) -> list[Reference]:
    references = [
        Reference(type="source", label="NVD entry", url=cve_details["url"])
    ]
    references.extend(
        Reference(type="source", label=ref_url, url=ref_url)
        for ref_url in cve_details["references"]
    )
    return references


def _create_problemtype(
    cve_id: str, cve_details: dict[str, Any]
) -> Problemtype:
    if cve_details.get("title"):
        problemtype_desc = f"{cve_details['title']} ({cve_id})"
    else:
        problemtype_desc = f"Vulnerability {cve_id}"
    return Problemtype(
        classof=ClassEnum.cve,
        type=TypeEnum.advisory,
        description=LangValue(lang="eng", value=problemtype_desc),
    )


def _create_affects(cve_details: dict[str, Any]) -> Affects:
    developers = []
    deployers = []
    artifacts = []

    if cve_details["affected_products"]:
        vendors = set()
        for item in cve_details["affected_products"]:
            vendor = item.get("vendor", "Unknown")
            vendors.add(vendor)
            product = item.get("product", "Unknown")
            artifacts.append(
                Artifact(type=ArtifactTypeEnum.system, name=product)
            )
        developers = list(vendors)
        deployers = list(vendors)
    else:
        developers = ["Unknown"]
        deployers = ["Unknown"]
        artifacts.append(
            Artifact(type=ArtifactTypeEnum.system, name="Unknown System")
        )

    return Affects(
        developer=developers,
        deployer=deployers,
        artifacts=artifacts,
    )


def _create_impact(
    cve_id: str, cve_details: dict[str, Any], include_vuln_id: bool = False
) -> Impact:
    avid_taxonomy = AvidTaxonomy(
        vuln_id=cve_id if include_vuln_id else None,
        risk_domain=["Security"],
        sep_view=[SepEnum.S0100],
        lifecycle_view=[LifecycleEnum.L06],
        taxonomy_version="0.2",
    )

    cvss = None
    if cve_details.get("cvss_data"):
        cvss_data = cve_details["cvss_data"]
        cvss = CVSSScores(
            version=cvss_data.get("version", "3.0"),
            vectorString=cvss_data.get("vectorString", ""),
            baseScore=cvss_data.get("baseScore", 0.0),
            baseSeverity=cvss_data.get("baseSeverity", "UNKNOWN"),
            attackVector=cvss_data.get("attackVector"),
            attackComplexity=cvss_data.get("attackComplexity"),
            privilegesRequired=cvss_data.get("privilegesRequired"),
            userInteraction=cvss_data.get("userInteraction"),
            scope=cvss_data.get("scope"),
            confidentialityImpact=cvss_data.get("confidentialityImpact"),
            integrityImpact=cvss_data.get("integrityImpact"),
            availabilityImpact=cvss_data.get("availabilityImpact"),
        )

    cwe = None
    if cve_details.get("cwe_data"):
        cwe = [
            CWETaxonomy(
                cweId=cwe_item["cweId"],
                description=cwe_item.get("description"),
                lang=cwe_item.get("lang"),
            )
            for cwe_item in cve_details["cwe_data"]
        ]

    return Impact(avid=avid_taxonomy, cvss=cvss, cwe=cwe)


def convert_cve_to_report(cve: dict[str, Any]) -> Report:
    """Convert a CVE JSON object into an AVID report object.

    Parameters
    ----------
    cve : dict
        MITRE CVE JSON object containing the imported CVE information.

    Returns
    --------
    report : Report
        an AVID report object containing information in the CVE.
    """
    cve_details = extract_cve_details(cve)
    cve_id = cve_details["cve_id"]

    return Report(
        data_type="AVID",
        data_version="0.2",
        affects=_create_affects(cve_details),
        problemtype=_create_problemtype(cve_id, cve_details),
        references=_create_references(cve_details),
        description=_create_description(cve_details),
        impact=_create_impact(cve_id, cve_details, include_vuln_id=False),
        reported_date=_parse_date(cve_details.get("published_date")),
    )


def convert_cve_to_vuln(cve):
    """Convert a CVE JSON object into an AVID vulnerability object.

    Parameters
    ----------
    cve : dict
        MITRE CVE JSON object containing the imported CVE information.

    Returns
    --------
    vuln : Vulnerability
        an AVID vulnerability object containing information in the CVE.
    """
    cve_details = extract_cve_details(cve)
    cve_id = cve_details["cve_id"]

    vuln = Vulnerability(
        data_type="AVID",
        data_version="0.2",
        affects=_create_affects(cve_details),
        problemtype=_create_problemtype(cve_id, cve_details),
        references=_create_references(cve_details),
        description=_create_description(cve_details),
        impact=_create_impact(cve_id, cve_details, include_vuln_id=True),
        published_date=_parse_date(cve_details.get("published_date")),
        last_modified_date=_parse_date(cve_details.get("last_modified_date")),
    )

    if cve_details.get("source"):
        vuln.credit = [LangValue(lang="eng", value=cve_details["source"])]

    return vuln


async def fetch_reports_for_cves(
    cve_ids: list[str], max_concurrent: int = 10
) -> list[Report]:
    """Import CVEs by ID and convert them into AVID reports."""
    reports: list[Report] = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async def process_single(cve_id: str):
        async with semaphore:
            cve_data = await asyncio.to_thread(import_cve, cve_id)
            return convert_cve_to_report(cve_data)

    tasks = [process_single(cve_id) for cve_id in cve_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Report):
            reports.append(result)

    return reports


def save_reports_to_jsonl(reports: list[Report], output_path: str) -> None:
    """Save a list of Report objects to a JSONL file."""
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    output_file.write_text("", encoding="utf-8")
    for report in reports:
        report.save(str(output_file), append=True, jsonl=True)
