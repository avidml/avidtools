from pyArango.connection import *
conn = Connection(username="root", password="root_passwd")
db = conn.createDatabase(name="avid")

avid_db = conn["avid"]

vuln_col = db.createCollection(name="Vulnerabilities")
reports_col = db.createCollection(name="Reports")
