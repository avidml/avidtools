from pyArango.connection import *
import json
import pathlib

conn = Connection(username="root", password="root_passwd")

if conn.hasDatabase('avid')==False: avid_db = conn.createDatabase(name="avid")
else: avid_db = conn.databases['avid']

avid_db.dropAllCollections()
avid_db.reloadCollections()

if avid_db.hasCollection("Vulnerabilities")==False:
    vuln_collection = avid_db.createCollection(name="Vulnerabilities",waitForSync = True)

if avid_db.hasCollection("Reports")==False:
    repo_collection = avid_db.createCollection(name="Reports",waitForSync = True)


for vuln in pathlib.Path('./vulnerabilities').glob('*.json'):
    with open(vuln,'r') as json_file:
        print(vuln)
        data = json.load(json_file)
        # add the object key
        doc = vuln_collection.createDocument(data)
        doc._key = data['metadata']['vuln_id']
        doc.save()

for rep in pathlib.Path('./reports').glob('*.json'):
    with open(rep,'r') as json_file:
        print(rep)
        data = json.load(json_file)
        # add the object key
        doc = repo_collection.createDocument(data)
        doc._key = data['metadata']['report_id']
        doc.save()
