from neo4j import GraphDatabase
from backend.app.core.config import settings

user = settings.NEO4J_USER
pwd = settings.NEO4J_PASSWORD
db = settings.NEO4J_DATABASE
uri = 'neo4j+ssc://e5193897.databases.neo4j.io'

driver = GraphDatabase.driver(uri, auth=(user, pwd))
with driver.session(database=db) as s:
    target = 'srv-neo4j-live-01'
    rec = s.run('MATCH (n) WHERE n.id = $nid RETURN n.id as id, n.name as name, n.criticality as crit, n.provenance as prov', {'nid': target}).single()
    print('Record queried directly from Neo4j Aura:')
    print('ID:', rec['id'])
    print('Name:', rec['name'])
    print('Criticality:', rec['crit'])
    print('Provenance:', rec['prov'])
driver.close()
