import uuid
from neo4j import GraphDatabase
from backend.app.core.config import settings

user = 'e5193897'
pwd = settings.NEO4J_PASSWORD
db = 'e5193897'
uri = 'neo4j+ssc://e5193897.databases.neo4j.io'

driver = GraphDatabase.driver(uri, auth=(user, pwd))
test_id = 'test-persist-' + uuid.uuid4().hex[:8]
target_id = 'test-target-' + uuid.uuid4().hex[:8]
rel_id = 'test-rel-' + uuid.uuid4().hex[:8]

print('1. Connecting to Aura at', uri)
with driver.session(database=db) as s:
    q_res = s.run('RETURN 1 AS connection_test').single()
    assert q_res['connection_test'] == 1
    print('1. Real test query passed (RETURN 1 AS connection_test = 1)')

    # 2. Create test nodes
    s.run('CREATE (n:Server {id: $id, name: $name, criticality: 0.95})', id=test_id, name='Test Persistence Server')
    s.run('CREATE (t:Database {id: $id, name: $name, criticality: 1.0})', id=target_id, name='Test Target DB')
    print('2. Created temporary test nodes:', test_id, target_id)

    # 3. Create test relationship
    s.run('MATCH (s:Server {id: $s_id}), (t:Database {id: $t_id}) CREATE (s)-[r:CONNECTED_TO {id: $r_id, confidence: 0.99}]->(t)', s_id=test_id, t_id=target_id, r_id=rel_id)
    print('3. Created temporary test relationship:', rel_id)

    # 4. Read back node in new transaction
    node_rec = s.run('MATCH (n:Server {id: $id}) RETURN n.id as id, n.name as name, n.criticality as crit', id=test_id).single()
    assert node_rec['id'] == test_id
    assert abs(node_rec['crit'] - 0.95) < 0.001
    print('4. Read back node and verified properties matched exactly')

    # 5. Read back relationship
    rel_rec = s.run('MATCH ()-[r:CONNECTED_TO {id: $id}]->() RETURN r.id as id, r.confidence as conf', id=rel_id).single()
    assert rel_rec['id'] == rel_id
    assert abs(rel_rec['conf'] - 0.99) < 0.001
    print('5. Read back relationship and verified properties matched exactly')

    # 6. Delete temporary test records
    s.run('MATCH ()-[r:CONNECTED_TO {id: $id}]->() DELETE r', id=rel_id)
    s.run('MATCH (n {id: $id}) DETACH DELETE n', id=test_id)
    s.run('MATCH (n {id: $id}) DETACH DELETE n', id=target_id)
    print('6. Deleted temporary test records cleanly')

    # 7. Confirm cleanup
    assert s.run('MATCH (n {id: $id}) RETURN count(n) as c', id=test_id).single()['c'] == 0
    assert s.run('MATCH ()-[r {id: $id}]->() RETURN count(r) as c', id=rel_id).single()['c'] == 0
    print('7. Confirmed 100% clean deletion of test records')

driver.close()
print('ALL 7 PERSISTENCE VERIFICATION STEPS PASSED!')
