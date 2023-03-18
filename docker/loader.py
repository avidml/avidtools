from pyArango.connection import *
import json
import pathlib
import pydantic.error_wrappers
from avidtools.datamodels import report,enums,components,vulnerability
from pathlib import Path
import logging
import argparse
import json

logging.basicConfig(level=logging.INFO)


conn = Connection(username="root", password="root_passwd")

if conn.hasDatabase('avid')==False: avid_db = conn.createDatabase(name="avid")
else: avid_db = conn.databases['avid']

avid_db.dropAllCollections()
avid_db.reloadCollections()

if avid_db.hasCollection("Vulnerabilities")==False:
    vuln_collection = avid_db.createCollection(name="Vulnerabilities",waitForSync = True)

if avid_db.hasCollection("Reports")==False:
    repo_collection = avid_db.createCollection(name="Reports",waitForSync = True)


for file in Path('./vulnerabilities').glob('*.json'):

    with open(file) as f:
        try:
            logging.info(file)
            data = json.load(f)
            report_obj = vulnerability.Vulnerability(**data)

            # add the object key
            doc = vuln_collection.createDocument(report_obj.dict())
            doc._key = data['metadata']['vuln_id']
            doc.save()

        except pydantic.ValidationError as vae:
            logging.error(f'File -> {file.as_posix()}')
            logging.error(vae)
        except pydantic.error_wrappers.ErrorWrapper as eo:
            logging.error(eo)

for file in pathlib.Path('./reports').glob('*.json'):
    with open(file) as f:
        try:
            logging.info(file)
            data = json.load(f)
            report_obj = report.Report(**data)

            # add the object key
            doc = repo_collection.createDocument(report_obj.dict())
            doc._key = data['metadata']['report_id']
            doc.save()

        except pydantic.ValidationError as vae:
            logging.error(f'File -> {file.as_posix()}')
            logging.error(vae)
        except pydantic.error_wrappers.ErrorWrapper as eo:
            logging.error(eo)
