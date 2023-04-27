Welcome to avidtools!
=============================================

This package is the official Python toolkit for working with technical resources in the `AI Vulnerability Database <https://avidml.org>`_.
It empowers engineers and developers build pipelines to export outcomes of tests in their ML pipelines as AVID reports,
build an in-house vulnerability database, integrate existing sources of vulnerabilities into AVID-style reports, and much more!

Features
--------
- 📎 defines the schema of AVID reports and vulnerabilities as `pydantic <https://docs.pydantic.dev/>`_ datamodels
- 📋 lists out the enumerations---e.g. taxonomy categories---as pydantic objects
- 🏄 provides connectors to relevant data sources, e.g. MITRE ATLAS case studies and NIST CVEs

.. toctree::
   :maxdepth: 1
   :caption: Reference
   
   reference/report
   reference/vulnerability
   reference/components
   reference/enums
   reference/connectors