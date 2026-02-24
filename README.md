# avidtools
Developer tools for AVID.

[API docs](https://avidml.org/avidtools/)

## Components

Currently there are two components:

- **Data models**: defines the base data class for an AVID report as a Pydantic data model, with supporting enums and components.
- **Connectors**: defines connectors to pull data from different sources (e.g. MITRE ATLAS) and structure them as AVID report.

## Installation

Run the following to install the latest stable version on PyPI:
```
pip install avidtools
```

From inside this directory, run the following to install the latest development version:
```
pip install -e .
```

## Release behavior

- On GitHub release publish, CI runs tests/lint/type checks before publishing to PyPI.
- The publish workflow compares the release tag version with `pyproject.toml`.
- If they differ, it automatically aligns the package version to the release tag during the workflow run, then continues build and publish.