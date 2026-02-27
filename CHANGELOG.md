# Changelog

All notable changes to avidtools are documented in this file.

## [Unreleased]

### Added
- **Mileva connector** (`scripts/mileva.py`): Script to scrape CVE identifiers from [Mileva.ai](https://mileva.ai) research digests, fetch detailed CVE data from the NVD API, and structure results as AVID reports. Adds `CVSSScores` and `CWETaxonomy` data model components and optional `cvss` / `cwe` fields on `Impact`. ([#14](https://github.com/avidml/avidtools/pull/14))
- **URL connector** (`connectors/url.py`): `URLConnector` class and `fetch_and_convert` helper that scrape a web page and use an OpenAI model to generate an AVID `Report` from the content. ([#15](https://github.com/avidml/avidtools/pull/15))
- **0din connector** (`scripts/odin.py`): Script to scrape AI security disclosures from [0din.ai](https://0din.ai) and create AVID reports, with support for pagination and asynchronous fetching. Adds `OdinTaxonomy` and `JailbreakTaxonomyItem` data model components and an `odin` field on `Impact`. ([#15](https://github.com/avidml/avidtools/pull/15))
- **Normalization in connectors**: `normalize` parameter added to `convert_eval_log` (Inspect) and `process_report` / `normalize_report_data` (Garak), fetching benchmark overview and scoring details from Inspect Evals documentation to enrich report descriptions. ([#16](https://github.com/avidml/avidtools/pull/16))
- Unit tests for normalization utilities and Garak/Inspect connector normalize paths. ([#16](https://github.com/avidml/avidtools/pull/16))
- CI now also runs on `release.published` events. ([#16](https://github.com/avidml/avidtools/pull/16))
- Publish workflow auto-aligns `pyproject.toml` version to the release tag when they differ, then continues to build and publish without creating a separate PR. ([#16](https://github.com/avidml/avidtools/pull/16))

### Changed
- Renamed `enrich` parameter/terminology to `normalize` across the Inspect and Garak connectors and their tests for consistency. ([#17](https://github.com/avidml/avidtools/pull/17))
- Inspect connector `problemtype.description.value` is now generated using the subject-aware label (`LLM` vs `AI system`) derived from artifact types. ([#18](https://github.com/avidml/avidtools/pull/18), [#19](https://github.com/avidml/avidtools/pull/19))

### Fixed
- Inspect connector: subject label lookup now correctly handles `System` artifacts in addition to `Model` artifacts. ([#18](https://github.com/avidml/avidtools/pull/18))

### Security
- **urllib3 2.5.0 → 2.6.0**: Fixes a decompression-bomb vulnerability in the streaming API ([CVE-2025-66471](https://nvd.nist.gov/vuln/detail/CVE-2025-66471), GHSA-2xpw-w6gg-jr37, CVSS 8.9 High) and a DoS via unlimited `Content-Encoding` chaining ([CVE-2025-66418](https://nvd.nist.gov/vuln/detail/CVE-2025-66418), GHSA-gm62-xv2j-4w53, CVSS 8.9 High). ([#13](https://github.com/avidml/avidtools/pull/13))

---

## [0.2.1] – 2025-06-24

### Changed
- Aligned `pyproject.toml` version to `0.2.1` to match the release tag. ([#12](https://github.com/avidml/avidtools/pull/12))

---

## [0.2.0] – 2025-06-24

### Added
- **Inspect AI connector** (`connectors/inspect.py`): Convert [Inspect](https://inspect.ai) evaluation logs (`.eval` / `.json`) into AVID `Report` objects, with support for multi-sample logs, scorer metrics, and optional normalize enrichment. ([#9](https://github.com/avidml/avidtools/pull/9), [#10](https://github.com/avidml/avidtools/pull/10))
- **CI/CD**: GitHub Actions workflows for linting, type-checking, testing, and publishing to PyPI. ([#11](https://github.com/avidml/avidtools/pull/11))
- Basic API documentation and a tutorial notebook. ([#1](https://github.com/avidml/avidtools/pull/1), [#4](https://github.com/avidml/avidtools/pull/4))

### Changed
- Bumped minimum pydantic version; switched to relative imports throughout the package. ([#5](https://github.com/avidml/avidtools/pull/5))
- `typing` dependency now uses a Python version marker (`python_version < "3.5"`) so it is not installed unnecessarily on modern Python. ([#7](https://github.com/avidml/avidtools/pull/7))

---

[Unreleased]: https://github.com/avidml/avidtools/compare/0.2.1...HEAD
[0.2.1]: https://github.com/avidml/avidtools/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/avidml/avidtools/releases/tag/0.2.0
