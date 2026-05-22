from sqlalchemy import text

query2 = text("""
    SELECT * FROM cypher('aegis_network_graph', $$
        MATCH (d:Domain {name: $target})
        MERGE (h:Domain {name: $hostname})
        MERGE (i:IP {address: $ip})
        MERGE (p:Port {number: $port, service: $service})
        MERGE (d)-[:SUBDOMAIN]->(h)
        MERGE (h)-[:RESOLVES_TO]->(i)
        MERGE (i)-[:EXPOSES]->(p)
    $$, :params) as (v agtype);
""")
print(query2)
