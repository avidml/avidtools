Datamodels
==========

There are two datamodels in :code:`avidtools`: :code:`Vulnerability` and :code:`Report`. These mirror the two layers of information supported by our database.


Vulnerability
--------------

A vulnerability (vuln) is a high-level evidence of an AI failure mode, in line with the NIST CVEs.
These are linked to the taxonomy through multiple tags, denoting the AI risk domains 
(Security, Ethics, Performance) this vulnerability pertains to, (sub)categories under that domain, as well as AI lifecycle stages.

.. toctree::
   :maxdepth: 3

   ../reference/vulnerability
   
Report
--------
A report is one example of a particular vulnerability occurring, 
and is potentially more granular and reproducible based on the references provided in that report.

.. toctree::
   :maxdepth: 3

   ../reference/report

