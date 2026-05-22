import asyncio
import json
from sqlalchemy import text
from backend.core.database import async_session_factory


async def test():
    async with async_session_factory() as session:
        await session.execute(text("LOAD 'age'"))
        await session.execute(text('SET search_path = ag_catalog, "$user", public'))

        q = text("""
            SELECT * FROM cypher('aegis_network_graph', $$
                MERGE (d:Domain {name: $target})
                RETURN d
            $$, CAST(:params AS agtype)) as (v agtype);
        """)
        params_str = json.dumps({"target": "example.com"})

        try:
            res = await session.execute(q, {"params": params_str})
            print("SUCCESS!", res.fetchall())
        except Exception as e:
            print("ERROR!", e)


asyncio.run(test())
