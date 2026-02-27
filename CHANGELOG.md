# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The `normalize_report_data` function in the `inspect` connector now sets a subject-aware `problemtype.description.value`, using "LLM" or "AI system" depending on the artifact type in the report. ([#19](https://github.com/avidml/avidtools/pull/19))
- The `PATTERN` regex in the `inspect` connector now accepts both "LLM" and "AI system" as the subject label, so reports that were already normalized with the "AI system" wording can be re-normalized without error. ([#19](https://github.com/avidml/avidtools/pull/19))
- `INSPECT_MODEL_PREFIXES` in `connectors/utils.py` replaces the old single-prefix constant `INSPECT_MODEL_PREFIX` to handle both "Evaluation of the LLM …" and "Evaluation of the AI system …" problem descriptions. ([#19](https://github.com/avidml/avidtools/pull/19))

## [0.2.1] - 2025-06-24

### Fixed

- Aligned the package version in `pyproject.toml` with the `0.2.1` release tag. ([#12](https://github.com/avidml/avidtools/pull/12))

## [0.2.0] - 2025-06-24

### Added

- Initial API documentation and project README. ([#1](https://github.com/avidml/avidtools/pull/1))
- Tutorial notebook demonstrating usage of the data models and connectors. ([#4](https://github.com/avidml/avidtools/pull/4))
- `inspect` connector: converts [Inspect AI](https://inspect.ai) evaluation logs (`.eval` / `.json`) into AVID `Report` objects, with an optional `normalize` step that fetches benchmark descriptions from [Inspect Evals](https://ukgovernmentbeis.github.io/inspect_evals) and enriches the report. ([#9](https://github.com/avidml/avidtools/pull/9), [#10](https://github.com/avidml/avidtools/pull/10))
- CI/CD pipeline: lint, type-check, and test jobs run on pull requests and releases; automatic PyPI publish on GitHub release. ([#11](https://github.com/avidml/avidtools/pull/11))

### Changed

- Upgraded Pydantic dependency to v2 and updated all data models accordingly; switched to project-relative import paths. ([#5](https://github.com/avidml/avidtools/pull/5))
- Applied Python version environment marker to the `typing` dependency so it is only installed on Python < 3.5, preventing conflicts with the standard-library `typing` module on modern Python versions. ([#7](https://github.com/avidml/avidtools/pull/7))

[Unreleased]: https://github.com/avidml/avidtools/compare/0.2.1...HEAD
[0.2.1]: https://github.com/avidml/avidtools/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/avidml/avidtools/commits/0.2.0
