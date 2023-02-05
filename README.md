# avidtools
Developer tools for AVID.

## Components

Currently there are two components:

- **[Data models](avidools/datamodels)**: defines the base data class for an AVID report as a Pydantic data model, with supporting enums and components.
- **[Connectors](avidtools/connectors)**: defines connectors to pull data from different sources (e.g. MITRE ATLAS) and structure them as AVID report.

## Installation

Run the following from this directory:
```
pip install -e .
```