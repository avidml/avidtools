"""Connector helpers for converting and normalizing Inspect evaluation reports."""

import json
import re
from html import unescape
from pathlib import Path
from typing import Any, List, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from ..datamodels.report import Report
from ..datamodels.components import (
    Affects,
    Artifact,
    ArtifactTypeEnum,
    Detection,
    LangValue,
    Metric,
    Problemtype,
    Reference,
)
from ..datamodels.enums import ClassEnum, MethodEnum, TypeEnum
from .utils import apply_review_normalizations, choose_model_subject_label

try:
    from inspect_ai.log import read_eval_log, EvalLog
except ImportError:
    # Handle case where inspect_ai is not installed
    def read_eval_log(file_path):
        raise ImportError(
            "inspect_ai package is required for this functionality"
        )

    # Create a dummy EvalLog class for type hinting
    EvalLog = Any


human_readable_name = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google": "Google",
    "huggingface": "Hugging Face",
    "meta-llama": "Meta",
    "mistralai": "Mistral AI",
    "cohere": "Cohere",
}

SITE_ROOT = "https://ukgovernmentbeis.github.io/inspect_evals"
CYSE2_URL = (
    "https://ukgovernmentbeis.github.io/inspect_evals/evals/"
    "cybersecurity/cyberseceval_2/"
)
PATTERN = re.compile(
    r"^Evaluation of the (?:LLM|AI system) (.+?) on the (.+?) benchmark using Inspect Evals$"
)
CATEGORY_CANDIDATES = ("safeguards", "scheming", "bias", "cybersecurity")


class UnsupportedInspectBenchmarkError(RuntimeError):
    """Raised when an Inspect benchmark cannot be resolved to a supported page."""

    pass


def import_eval_log(file_path: str) -> Any:
    """Import an Inspect evaluation log from a file.

    Parameters
    ----------
    file_path : str
        Path to the evaluation log file (.eval or .json).

    Returns
    -------
    eval_log : EvalLog
        The loaded evaluation log.
    """
    return read_eval_log(file_path)


def convert_eval_log(file_path: str, normalize: bool = False) -> List[Report]:
    """Convert an Inspect evaluation log into a list of AVID Report objects.

    Parameters
    ----------
    file_path : str
        Path to the evaluation log file (.eval or .json).
    normalize : bool
        If True, run normalize steps that fetch benchmark overview/scoring
        and apply report normalizations.

    Returns
    -------
    List[Report]
        A list of AVID Report objects created from the evaluation log.
    """
    eval_log = import_eval_log(file_path)
    reports = []

    for sample in eval_log.samples:
        report = Report()
        model_prefix = eval_log.eval.model.split("/", 1)[0]
        developer_name = human_readable_name[model_prefix]
        task = eval_log.eval.task.rsplit("/", 1)[-1]
        model_name = eval_log.eval.model.rsplit("/", 1)[-1]
        report.affects = Affects(
            developer=[developer_name],
            deployer=[eval_log.eval.model],
            artifacts=[Artifact(type=ArtifactTypeEnum.model, name=model_name)],
        )

        description_value = (
            f"Evaluation of the LLM {model_name} on the {task} "
            f"benchmark using Inspect Evals"
        )
        report.problemtype = Problemtype(
            classof=ClassEnum.llm,
            type=TypeEnum.measurement,
            description=LangValue(lang="eng", value=description_value),
        )

        dataset_label = (
            f"Inspect Evaluation Log for dataset: {eval_log.eval.dataset.name}"
        )
        report.references = [
            Reference(
                type="source",
                label=dataset_label,
                url=eval_log.eval.dataset.location,
            )
        ]

        metrics = ", ".join(
            [
                metric.name.rsplit("/", 1)[-1]
                for scorer in eval_log.eval.scorers
                for metric in scorer.metrics
            ]
        )
        scorer_desc = "|".join(
            [
                f"scorer: {scorer.name}, metrics: {metrics}"
                for scorer in eval_log.eval.scorers
            ]
        )
        report.metrics = []
        for sc in eval_log.results.scores:
            for k, v in sc.metrics.items():
                report.metrics.append(
                    Metric(
                        name=k,
                        detection_method=Detection(
                            type=MethodEnum.test, name=sc.name
                        ),
                        results={"value": v.value, "scorer": sc.name},
                    )
                )

        full_description = (
            f"Evaluation of the LLM {model_name} on the {task} "
            f"benchmark using Inspect Evals\n\n"
            f"Sample input: {sample.input}\n\n"
            f"Model output: {sample.output}\n\n"
            f"Scorer: {scorer_desc}\n\n"
            f"Score: {sample.score}"
        )
        report.description = LangValue(lang="eng", value=full_description)

        if normalize:
            report_payload = (
                report.model_dump()
                if hasattr(report, "model_dump")
                else report.dict()
            )
            normalize_report_data(report_payload)
            report = Report(**report_payload)

        reports.append(report)

    return reports


def _clean_html_to_text(fragment: str) -> str:
    """Strip HTML tags and normalize whitespace for section extraction."""

    text = re.sub(r"<script[\\s\\S]*?</script>", "", fragment, flags=re.I)
    text = re.sub(r"<style[\\s\\S]*?</style>", "", text, flags=re.I)
    text = re.sub(r"<br\\s*/?>", "\\n", text, flags=re.I)
    text = re.sub(r"</p>", "\\n\\n", text, flags=re.I)
    text = re.sub(r"<li[^>]*>", "- ", text, flags=re.I)
    text = re.sub(r"</li>", "\\n", text, flags=re.I)
    text = re.sub(
        r"</(h[1-6]|div|section|article|ul|ol|table|tr)>",
        "\\n",
        text,
        flags=re.I,
    )
    text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)
    text = text.replace("\\\\n", "\n")
    text = text.replace("\\\\t", "\t")
    text = re.sub(r"\\r", "", text)
    text = re.sub(r"[ \t]+\\n", "\\n", text)
    text = re.sub(r"\\n{3,}", "\\n\\n", text)
    return text.strip()


def _extract_section(html: str, section_id: str) -> str:
    """Extract a section body by heading id from an Inspect docs page."""

    candidates = [
        section_id,
        f"{section_id}Anchor",
        f"{section_id.lower()}anchor",
    ]

    marker_index = -1
    for candidate in candidates:
        marker = f'id="{candidate}"'
        marker_index = html.find(marker)
        if marker_index >= 0:
            break

    if marker_index < 0:
        return ""

    heading_start = html.rfind("<h", 0, marker_index)
    if heading_start < 0:
        return ""

    heading_close_tag_start = html.find("</h", marker_index)
    if heading_close_tag_start < 0:
        return ""

    heading_close_tag_end = html.find(">", heading_close_tag_start)
    if heading_close_tag_end < 0:
        return ""

    section_start = heading_close_tag_end + 1

    next_heading = re.search(
        r"<h[1-6][^>]*id=\"[^\"]+\"",
        html[section_start:],
        flags=re.I,
    )
    if next_heading:
        section_end = section_start + next_heading.start()
    else:
        section_end = len(html)

    fragment = html[section_start:section_end]
    return _clean_html_to_text(fragment)


def _fetch_sections(benchmark: str) -> Tuple[str, str, str]:
    """Fetch overview and scoring sections for a benchmark slug."""

    if benchmark.startswith("cyse2_"):
        try:
            with urlopen(CYSE2_URL, timeout=30) as response:
                html = response.read().decode("utf-8", errors="replace")
        except (HTTPError, URLError) as error:
            raise RuntimeError(
                "Failed to fetch Inspect Evals page for cyse2 benchmark: "
                f"{error}"
            ) from error

        overview = _extract_section(html, "overview")
        scoring = _extract_section(html, "scoring")
        if not overview or not scoring:
            fallback_overview = (
                f"The benchmark {benchmark} is implemented by "
                "Inspect Evals. More details are available "
                f"[here]({CYSE2_URL})."
            )
            fallback_scoring = (
                "Scoring details are available "
                f"[here]({CYSE2_URL})."
            )
            return benchmark, fallback_overview, fallback_scoring

        return benchmark, overview, scoring

    candidates = [benchmark]
    if "_" in benchmark:
        candidates.append(benchmark.split("_", 1)[0])

    for category in CATEGORY_CANDIDATES:
        for slug in candidates:
            try:
                url = f"{SITE_ROOT}/evals/{category}/{slug}/"
                with urlopen(url, timeout=30) as response:
                    html = response.read().decode("utf-8", errors="replace")
            except (HTTPError, URLError):
                continue

            overview = _extract_section(html, "overview")
            scoring = _extract_section(html, "scoring")
            if not overview or not scoring:
                fallback_overview = (
                    f"The benchmark {benchmark} is implemented by "
                    "Inspect Evals. More details are available "
                    f"[here]({url})."
                )
                fallback_scoring = (
                    "Scoring details are available "
                    f"[here]({url})."
                )
                return slug, fallback_overview, fallback_scoring

            return slug, overview, scoring

    raise UnsupportedInspectBenchmarkError(
        "No matching Inspect Evals page found under categories "
        f"{CATEGORY_CANDIDATES} for benchmark '{benchmark}'"
    )


def _build_new_description(
    model_name: str,
    overview: str,
    scoring: str,
    subject_label: str,
) -> str:
    """Build standardized normalized report description text."""

    subject_label_display = "LLM" if subject_label == "llm" else "AI system"

    return (
        f"{overview}\n\n"
        f"The {subject_label_display} {model_name} was evaluated "
        "on this benchmark.\n\n"
        "## Measurement details\n\n"
        f"{scoring}"
    )


def _build_problemtype_description(
    model_name: str,
    benchmark: str,
    subject_label: str,
) -> str:
    """Build standardized problemtype.description.value text."""

    subject_label_display = "LLM" if subject_label == "llm" else "AI system"
    return (
        f"Evaluation of the {subject_label_display} {model_name} "
        f"on the {benchmark} benchmark using Inspect Evals"
    )


def _first_line(text: str) -> str:
    """Return the first non-empty line from a text block."""

    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def normalize_report_data(report: dict):
    """Apply Inspect normalize transformations to a report dictionary."""

    problem_desc = (
        report.get("problemtype", {})
        .get("description", {})
        .get("value", "")
    )
    match = PATTERN.match(problem_desc)
    if not match:
        raise ValueError(
            "problemtype.description.value is not in expected format: "
            "Evaluation of the (LLM|AI system) $X on the $Y benchmark using "
            "Inspect Evals"
        )

    model_name = match.group(1)
    benchmark = match.group(2)

    apply_review_normalizations(report, preferred_model_name=model_name)

    _, overview, scoring = _fetch_sections(benchmark)
    overview = _first_line(overview)
    subject_label = choose_model_subject_label(report)

    problemtype_description = report.setdefault("problemtype", {}).setdefault(
        "description",
        {},
    )
    problemtype_description["value"] = _build_problemtype_description(
        model_name=model_name,
        benchmark=benchmark,
        subject_label=subject_label,
    )
    if "lang" not in problemtype_description:
        problemtype_description["lang"] = "eng"

    description = report.setdefault("description", {})
    description["value"] = _build_new_description(
        model_name=model_name,
        overview=overview,
        scoring=scoring,
        subject_label=subject_label,
    )
    if "lang" not in description:
        description["lang"] = "eng"


def process_report(file_path: Path):
    """Load, normalize, and rewrite a single Inspect report file."""

    with file_path.open("r", encoding="utf-8") as file_obj:
        report = json.load(file_obj)

    normalize_report_data(report)

    with file_path.open("w", encoding="utf-8") as file_obj:
        json.dump(report, file_obj, indent=2)
        file_obj.write("\n")

    print(f"Updated {file_path}")
