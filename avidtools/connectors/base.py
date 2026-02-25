"""Generic normalize helpers for AVID report JSON and JSONL files."""

import json
from pathlib import Path

from .utils import apply_normalizations


def _normalize_report(report: dict) -> None:
    """Apply generic normalizations to a single report dict."""

    apply_normalizations(report)


def process_json_file(
    input_path: Path,
    dry_run: bool,
) -> int:
    """Normalize a JSON file containing one report object or a list of reports."""

    with input_path.open("r", encoding="utf-8") as file_obj:
        payload = json.load(file_obj)

    reports_normalized = 0

    if isinstance(payload, dict):
        _normalize_report(payload)
        reports_normalized += 1
    elif isinstance(payload, list):
        for index, report in enumerate(payload, 1):
            if not isinstance(report, dict):
                raise ValueError(
                    "Invalid item at index "
                    f"{index} in JSON list: expected object"
                )
            _normalize_report(report)
            reports_normalized += 1
    else:
        raise ValueError("Unsupported JSON structure: expected object or list")

    if not dry_run:
        with input_path.open("w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, indent=2)
            file_obj.write("\n")

    return reports_normalized


def process_jsonl_file(
    input_path: Path,
    dry_run: bool,
) -> int:
    """Normalize each report object in a JSONL file."""

    reports_normalized = 0
    normalized_lines = []

    with input_path.open("r", encoding="utf-8") as file_obj:
        for line_num, line in enumerate(file_obj, 1):
            raw_line = line.strip()
            if not raw_line:
                continue

            try:
                report = json.loads(raw_line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_num}: {error.msg}"
                ) from error

            if not isinstance(report, dict):
                raise ValueError(
                    f"Invalid JSON object on line {line_num}: expected object"
                )

            _normalize_report(report)
            reports_normalized += 1
            normalized_lines.append(json.dumps(report, ensure_ascii=False))

    if not dry_run:
        with input_path.open("w", encoding="utf-8") as file_obj:
            if normalized_lines:
                file_obj.write("\n".join(normalized_lines) + "\n")

    return reports_normalized


def normalize_file(input_path: Path, dry_run: bool = False) -> int:
    """Dispatch normalize processing based on input file extension."""

    if input_path.suffix == ".json":
        return process_json_file(input_path, dry_run)
    if input_path.suffix == ".jsonl":
        return process_jsonl_file(input_path, dry_run)
    raise ValueError(f"Unsupported file type: {input_path.suffix}")
